use super::model::{Api, Asset, Identity, Plan, Release, RemoteAsset, Repository};
use crate::cohort::model::FileEntry;
use anyhow::{Result, bail, ensure};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs::File, io::Read, path::Path, time::Duration};
use ureq::{
    Agent, Body,
    http::{Response, Uri},
};

const JSON_LIMIT: u64 = 16 * 1024 * 1024;
const ASSET_LIMIT: u64 = 512 * 1024 * 1024;
const PAGE_SIZE: usize = 100;
const PAGE_LIMIT: usize = 100;
const TAG_DEPTH: usize = 16;
const DOWNLOAD_REDIRECTS: usize = 5;
const API_VERSION: &str = "2026-03-10";
const URL_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// A credential-bearing client. Intentionally does not implement Debug.
pub struct Client {
    agent: Agent,
    token: String,
    #[cfg(test)]
    test_api: Option<String>,
    #[cfg(test)]
    test_upload: Option<String>,
    #[cfg(test)]
    test_download: Option<String>,
}

impl Client {
    pub(super) fn from_token(token: String) -> Result<Self> {
        Self::new(token)
    }

    /// User identity is optional for repository-scoped environment credentials.
    pub fn identity(&self) -> Result<Identity> {
        let identity: Identity = self.get_json("/user")?;
        ensure!(
            identity.id != 0 && !identity.login.is_empty(),
            "GitHub returned an invalid user identity"
        );
        Ok(identity)
    }

    pub fn from_env() -> Result<Self> {
        let token = ["GH_TOKEN", "GITHUB_TOKEN"]
            .into_iter()
            .filter_map(std::env::var_os)
            .find(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("set GH_TOKEN or GITHUB_TOKEN for GitHub access"))?
            .into_string()
            .map_err(|_| anyhow::anyhow!("GitHub token must be valid text"))?;
        Self::new(token)
    }

    fn new(token: String) -> Result<Self> {
        ensure!(
            !token.is_empty() && token.bytes().all(|b| (33..=126).contains(&b)),
            "GitHub token contains invalid characters"
        );
        let config = Agent::config_builder()
            .https_only(!cfg!(test))
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(300)))
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_resolve(Some(Duration::from_secs(15)))
            .timeout_send_request(Some(Duration::from_secs(30)))
            .timeout_recv_response(Some(Duration::from_secs(30)))
            .timeout_per_read(Some(Duration::from_secs(30)))
            .timeout_per_write(Some(Duration::from_secs(30)))
            .user_agent("cli-release-kit")
            .build();
        Ok(Self {
            agent: Agent::new_with_config(config),
            token,
            #[cfg(test)]
            test_api: None,
            #[cfg(test)]
            test_upload: None,
            #[cfg(test)]
            test_download: None,
        })
    }

    fn endpoint(&self, path: &str, upload: bool) -> String {
        #[cfg(test)]
        if let Some(base) = if upload {
            &self.test_upload
        } else {
            &self.test_api
        } {
            return format!("{base}{path}");
        }
        format!(
            "https://{}{path}",
            if upload {
                "uploads.github.com"
            } else {
                "api.github.com"
            }
        )
    }

    fn get(&self, url: &str, binary: bool, auth: bool) -> Result<Response<Body>> {
        let mut waited = Duration::ZERO;
        for attempt in 0..=2 {
            let mut request = self
                .agent
                .get(url)
                .header(
                    "Accept",
                    if binary {
                        "application/octet-stream"
                    } else {
                        "application/vnd.github+json"
                    },
                )
                .header("X-GitHub-Api-Version", API_VERSION);
            if auth {
                request = request.header("Authorization", format!("Bearer {}", self.token));
            }
            // Never attach transport errors: they can contain credential-bearing URLs.
            let response = request.call().map_err(|_| {
                anyhow::anyhow!(
                    "GitHub request failed (connection, TLS, timeout or protocol error)"
                )
            })?;
            if attempt == 2 || !matches!(response.status().as_u16(), 429 | 502 | 503 | 504) {
                return Ok(response);
            }
            let delay = if let Some(value) = response.headers().get("Retry-After") {
                let Some(seconds) = value
                    .to_str()
                    .ok()
                    .filter(|text| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|text| text.parse::<u64>().ok())
                else {
                    return Ok(response);
                };
                Duration::from_secs(seconds)
            } else {
                Duration::from_millis(100 * (attempt + 1))
            };
            if delay > Duration::from_secs(2).saturating_sub(waited) {
                return Ok(response);
            }
            waited += delay;
            drop(response);
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
        }
        unreachable!()
    }

    fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        json_response(self.get(&self.endpoint(path, false), false, true)?, 200)
    }

    fn post_json<T: DeserializeOwned>(&self, path: &str, value: &serde_json::Value) -> Result<T> {
        let body = serde_json::to_vec(value)
            .map_err(|_| anyhow::anyhow!("could not serialize GitHub request"))?;
        ensure!(
            body.len() as u64 <= JSON_LIMIT,
            "GitHub request JSON exceeds 16 MiB"
        );
        let response = self
            .agent
            .post(self.endpoint(path, false))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/json")
            .send(body.as_slice())
            .map_err(|_| {
                anyhow::anyhow!("GitHub mutation response unavailable; remote outcome is uncertain")
            })?;
        json_response(response, 201)
    }

    fn pages<T: DeserializeOwned>(&self, path: &str, id: impl Fn(&T) -> u64) -> Result<Vec<T>> {
        let mut records = Vec::new();
        let mut seen = BTreeSet::new();
        for page in 1..=PAGE_LIMIT {
            let batch: Vec<T> =
                self.get_json(&format!("{path}?per_page={PAGE_SIZE}&page={page}"))?;
            ensure!(
                batch.len() <= PAGE_SIZE,
                "GitHub pagination returned too many records in one page"
            );
            let complete = batch.len() < PAGE_SIZE;
            for record in batch {
                ensure!(
                    seen.insert(id(&record)),
                    "GitHub pagination returned duplicate identities; retry the read"
                );
                records.push(record);
            }
            if complete {
                return Ok(records);
            }
        }
        bail!(
            "GitHub pagination limit reached (100 pages / 10000 records); completeness is unproven"
        )
    }

    fn download_auth(&self, url: &str, redirect: bool) -> Result<bool> {
        #[cfg(test)]
        {
            if self
                .test_api
                .as_ref()
                .is_some_and(|base| has_test_origin(url, base))
            {
                return Ok(!redirect);
            }
            if redirect
                && self
                    .test_download
                    .as_ref()
                    .is_some_and(|base| has_test_origin(url, base))
            {
                return Ok(false);
            }
        }
        download_auth(url, redirect)
    }

    #[cfg(test)]
    fn loopback(api: String, upload: String, download: Option<String>) -> Self {
        for base in [&api, &upload].into_iter().chain(download.as_ref()) {
            let uri: Uri = base.parse().unwrap();
            assert_eq!(uri.scheme_str(), Some("http"));
            assert_eq!(uri.host(), Some("127.0.0.1"));
            assert!(uri.port_u16().is_some());
            assert_eq!(uri.path(), "/");
            assert!(uri.query().is_none());
        }
        let mut client = Self::new("test-secret-token".into()).unwrap();
        client.test_api = Some(api);
        client.test_upload = Some(upload);
        client.test_download = download;
        client
    }
}

fn encode(value: &str) -> String {
    utf8_percent_encode(value, URL_SEGMENT).to_string()
}

fn repo_path(repo: &str) -> Result<String> {
    let parts: Vec<_> = repo.split('/').collect();
    ensure!(
        parts.len() == 2
            && parts.iter().all(|part| !part.is_empty()
                && *part != "."
                && *part != ".."
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))),
        "GitHub repository must be owner/name"
    );
    Ok(format!("/repos/{}/{}", encode(parts[0]), encode(parts[1])))
}

fn valid_sha(sha: &str) -> bool {
    sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit())
}

fn check_status(response: &Response<Body>, expected: u16) -> Result<()> {
    let status = response.status().as_u16();
    if status == expected {
        return Ok(());
    }
    // Remote error bodies may echo tokens, request headers or signed URLs. Keep
    // diagnostics useful without copying any untrusted server-provided text.
    let reason = match status {
        301..=308 => "unexpected redirect",
        401 => "authentication failed",
        403 if response
            .headers()
            .get("x-github-sso")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("required")
            }) =>
        {
            "organization requires SSO authorization for this credential"
        }
        403 => "forbidden; check repository permissions, organization policies or rate limits",
        404 => "resource not found or inaccessible",
        409 => "conflict",
        422 => "validation failed or request rejected",
        429 => "rate limited; retry later or check the token's rate limit",
        500..=599 => "server failure; mutation outcome may be uncertain",
        _ => "unexpected response",
    };
    bail!("GitHub HTTP {status}: {reason}")
}

fn json_response<T: DeserializeOwned>(mut response: Response<Body>, expected: u16) -> Result<T> {
    check_status(&response, expected)?;
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(JSON_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            anyhow::anyhow!(
                "GitHub JSON response could not be read; mutation outcome may be uncertain"
            )
        })?;
    ensure!(
        bytes.len() as u64 <= JSON_LIMIT,
        "GitHub JSON response exceeds 16 MiB"
    );
    serde_json::from_slice(&bytes).map_err(|_| {
        anyhow::anyhow!("GitHub JSON response is invalid; mutation outcome may be uncertain")
    })
}

/// Returns whether an Authorization header is allowed for this download request.
fn download_auth(url: &str, redirect: bool) -> Result<bool> {
    let uri: Uri = url
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid GitHub asset redirect"))?;
    let authority = uri
        .authority()
        .ok_or_else(|| anyhow::anyhow!("invalid GitHub asset redirect"))?;
    ensure!(
        uri.scheme_str() == Some("https")
            && !authority.as_str().contains('@')
            && authority.port().is_none()
            && !url.contains('#')
            && !url.contains('\\'),
        "unsafe GitHub asset redirect"
    );
    let host = uri.host().unwrap_or_default();
    if !redirect && host == "api.github.com" {
        ensure!(
            uri.query().is_none(),
            "unexpected GitHub API download query"
        );
        return Ok(true);
    }
    ensure!(
        redirect
            && matches!(
                host,
                "release-assets.githubusercontent.com"
                    | "objects.githubusercontent.com"
                    | "objects-origin.githubusercontent.com"
                    | "github-releases.githubusercontent.com"
            ),
        "GitHub asset redirect host is not allowed"
    );
    Ok(false)
}

#[cfg(test)]
fn has_test_origin(url: &str, base: &str) -> bool {
    let Ok(uri) = url.parse::<Uri>() else {
        return false;
    };
    let Ok(base) = base.parse::<Uri>() else {
        return false;
    };
    uri.scheme_str() == Some("http")
        && uri.authority() == base.authority()
        && !url.contains('#')
        && !url.contains('\\')
}

#[derive(Deserialize)]
struct RepositoryResponse {
    id: u64,
    full_name: String,
}
#[derive(Deserialize)]
struct GitObject {
    #[serde(rename = "type")]
    kind: String,
    sha: String,
}
#[derive(Deserialize)]
struct GitRef {
    #[serde(rename = "ref")]
    reference: String,
    object: GitObject,
}
#[derive(Deserialize)]
struct GitTag {
    sha: String,
    object: GitObject,
}
#[derive(Deserialize)]
struct GitCommit {
    sha: String,
}

impl Api for Client {
    fn repository(&mut self, repo: &str) -> Result<Repository> {
        let result: RepositoryResponse = self.get_json(&repo_path(repo)?)?;
        ensure!(
            result.id != 0 && result.full_name.eq_ignore_ascii_case(repo),
            "GitHub repository identity mismatch"
        );
        Ok(Repository {
            id: result.id,
            full_name: result.full_name,
        })
    }

    fn commit_exists(&mut self, repo: &str, commit: &str) -> Result<()> {
        ensure!(
            valid_sha(commit),
            "GitHub commit must be a full 40-character SHA"
        );
        let result: GitCommit =
            self.get_json(&format!("{}/git/commits/{commit}", repo_path(repo)?))?;
        ensure!(result.sha == commit, "GitHub commit identity mismatch");
        Ok(())
    }

    fn tag(&mut self, repo: &str, tag: &str) -> Result<Option<String>> {
        ensure!(!tag.is_empty(), "GitHub tag must not be empty");
        let path = repo_path(repo)?;
        let response = self.get(
            &self.endpoint(&format!("{path}/git/ref/tags/{}", encode(tag)), false),
            false,
            true,
        )?;
        if response.status().as_u16() == 404 {
            return Ok(None);
        }
        let reference: GitRef = json_response(response, 200)?;
        ensure!(
            reference.reference == format!("refs/tags/{tag}"),
            "GitHub tag reference identity mismatch"
        );
        let mut object = reference.object;
        let mut seen = BTreeSet::new();
        for depth in 0..=TAG_DEPTH {
            ensure!(
                valid_sha(&object.sha),
                "GitHub tag returned an invalid object identity"
            );
            if object.kind == "commit" {
                return Ok(Some(object.sha));
            }
            ensure!(
                object.kind == "tag",
                "GitHub tag does not resolve to a commit"
            );
            ensure!(depth < TAG_DEPTH, "GitHub annotated tag depth exceeds 16");
            ensure!(
                seen.insert(object.sha.clone()),
                "GitHub annotated tag cycle detected"
            );
            let next: GitTag = self.get_json(&format!("{path}/git/tags/{}", object.sha))?;
            ensure!(
                next.sha == object.sha,
                "GitHub annotated tag identity mismatch"
            );
            object = next.object;
        }
        unreachable!()
    }

    fn create_tag(&mut self, repo: &str, tag: &str, commit: &str) -> Result<()> {
        ensure!(
            valid_sha(commit) && !tag.is_empty(),
            "invalid GitHub tag creation input"
        );
        let result: GitRef = self.post_json(
            &format!("{}/git/refs", repo_path(repo)?),
            &serde_json::json!({ "ref": format!("refs/tags/{tag}"), "sha": commit }),
        )?;
        ensure!(
            result.reference == format!("refs/tags/{tag}")
                && result.object.kind == "commit"
                && result.object.sha == commit,
            "GitHub created tag identity mismatch"
        );
        Ok(())
    }

    fn releases(&mut self, repo: &str) -> Result<Vec<Release>> {
        self.pages(
            &format!("{}/releases", repo_path(repo)?),
            |release: &Release| release.id,
        )
    }

    fn release(&mut self, repo: &str, id: u64) -> Result<Release> {
        let release: Release = self.get_json(&format!("{}/releases/{id}", repo_path(repo)?))?;
        ensure!(release.id == id, "GitHub release identity mismatch");
        Ok(release)
    }

    fn create_draft(&mut self, plan: &Plan, body: &str) -> Result<Release> {
        let release: Release = self.post_json(
            &format!("{}/releases", repo_path(&plan.repository.full_name)?),
            &serde_json::json!({ "tag_name": plan.tag, "target_commitish": plan.source_commit,
                "name": plan.title, "body": body, "draft": true, "prerelease": plan.prerelease }),
        )?;
        ensure!(
            release.id != 0 && release.draft && release.tag_name == plan.tag,
            "GitHub created draft identity mismatch"
        );
        Ok(release)
    }

    fn assets(&mut self, repo: &str, release: u64) -> Result<Vec<RemoteAsset>> {
        self.pages(
            &format!("{}/releases/{release}/assets", repo_path(repo)?),
            |asset: &RemoteAsset| asset.id,
        )
    }

    fn upload(
        &mut self,
        repo: &str,
        release: u64,
        asset: &Asset,
        path: &Path,
    ) -> Result<RemoteAsset> {
        ensure!(asset.size <= ASSET_LIMIT, "GitHub upload exceeds 512 MiB");
        let file =
            File::open(path).map_err(|_| anyhow::anyhow!("could not open GitHub upload file"))?;
        let metadata = file
            .metadata()
            .map_err(|_| anyhow::anyhow!("could not inspect GitHub upload file"))?;
        ensure!(
            metadata.is_file() && metadata.len() == asset.size,
            "GitHub upload file size changed"
        );
        let url = self.endpoint(
            &format!(
                "{}/releases/{release}/assets?name={}",
                repo_path(repo)?,
                encode(&asset.name)
            ),
            true,
        );
        let response = self
            .agent
            .post(url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", API_VERSION)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Content-Type", "application/octet-stream")
            .header("Content-Length", asset.size.to_string())
            .send(&file)
            .map_err(|_| {
                anyhow::anyhow!("GitHub upload response unavailable; remote outcome is uncertain")
            })?;
        let remote: RemoteAsset = json_response(response, 201)?;
        ensure!(
            remote.id != 0 && remote.name == asset.name && remote.size == asset.size,
            "GitHub uploaded asset identity mismatch"
        );
        Ok(remote)
    }

    fn download_digest(&mut self, repo: &str, asset: u64, expected_size: u64) -> Result<FileEntry> {
        ensure!(
            expected_size <= ASSET_LIMIT,
            "GitHub download exceeds 512 MiB"
        );
        let mut url = self.endpoint(
            &format!("{}/releases/assets/{asset}", repo_path(repo)?),
            false,
        );
        for redirects in 0..=DOWNLOAD_REDIRECTS {
            let auth = self.download_auth(&url, redirects != 0)?;
            let mut response = self.get(&url, true, auth)?;
            if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                ensure!(
                    redirects < DOWNLOAD_REDIRECTS,
                    "GitHub asset redirect limit exceeded"
                );
                url = response
                    .headers()
                    .get("Location")
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| anyhow::anyhow!("GitHub asset redirect has no valid location"))?
                    .to_owned();
                self.download_auth(&url, true)?;
                continue;
            }
            check_status(&response, 200)?;
            if let Some(length) = response.headers().get("Content-Length") {
                let length = length
                    .to_str()
                    .ok()
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or_else(|| anyhow::anyhow!("invalid GitHub download content length"))?;
                ensure!(
                    length == expected_size,
                    "GitHub download content length differs from asset size"
                );
            }
            let mut reader = response.body_mut().as_reader();
            let mut hash = Sha256::new();
            let mut size = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let count = reader
                    .read(&mut buffer)
                    .map_err(|_| anyhow::anyhow!("GitHub asset download could not be read"))?;
                if count == 0 {
                    break;
                }
                size += count as u64;
                ensure!(
                    size <= expected_size,
                    "GitHub download exceeds expected asset size"
                );
                hash.update(&buffer[..count]);
            }
            ensure!(
                size == expected_size,
                "GitHub download is shorter than expected asset size"
            );
            return Ok(FileEntry {
                size,
                sha256: format!("{:x}", hash.finalize()),
            });
        }
        unreachable!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread,
        time::Instant,
    };

    struct Reply {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    }
    impl Reply {
        fn json(value: serde_json::Value) -> Self {
            Self::status(200, value)
        }
        fn status(status: u16, value: serde_json::Value) -> Self {
            Self {
                status,
                headers: vec![],
                body: serde_json::to_vec(&value).unwrap(),
            }
        }
        fn redirect(url: &str) -> Self {
            Self {
                status: 302,
                headers: vec![("Location", url.into())],
                body: vec![],
            }
        }
    }
    struct Request {
        head: String,
        body: Vec<u8>,
    }

    fn read_request(stream: &mut TcpStream) -> Request {
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        let end = loop {
            let mut buffer = [0; 4096];
            let count = stream.read(&mut buffer).unwrap();
            assert!(count != 0, "request ended before headers");
            bytes.extend_from_slice(&buffer[..count]);
            if let Some(pos) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                break pos + 4;
            }
            assert!(bytes.len() < 32 * 1024);
        };
        let head = String::from_utf8(bytes[..end].to_vec()).unwrap();
        let length = head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("Content-Length"))
            .map(|(_, value)| value.trim().parse::<usize>().unwrap())
            .unwrap_or(0);
        while bytes.len() < end + length {
            let mut buffer = [0; 4096];
            let count = stream.read(&mut buffer).unwrap();
            assert!(count != 0, "request ended before body");
            bytes.extend_from_slice(&buffer[..count]);
        }
        Request {
            head,
            body: bytes[end..end + length].to_vec(),
        }
    }

    fn server(replies: Vec<Reply>) -> (String, thread::JoinHandle<Vec<Request>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for reply in replies {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "expected request was not sent");
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => panic!("{error}"),
                    }
                };
                requests.push(read_request(&mut stream));
                if reply.status == 0 {
                    continue;
                }
                let chunked = reply
                    .headers
                    .iter()
                    .any(|(name, _)| *name == "Transfer-Encoding");
                let mut head = format!("HTTP/1.1 {} Test\r\nConnection: close\r\n", reply.status);
                if !chunked {
                    head.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
                }
                for (name, value) in reply.headers {
                    head.push_str(&format!("{name}: {value}\r\n"));
                }
                head.push_str("\r\n");
                stream.write_all(head.as_bytes()).unwrap();
                // The client intentionally stops reading oversized or rejected responses.
                let _ = stream.write_all(&reply.body);
            }
            requests
        });
        (address, handle)
    }

    fn client(replies: Vec<Reply>) -> (Client, thread::JoinHandle<Vec<Request>>) {
        let (base, handle) = server(replies);
        (Client::loopback(base.clone(), base, None), handle)
    }

    #[test]
    fn authenticated_user_and_organization_repository_are_independent() {
        let (mut client, handle) = client(vec![
            Reply::json(serde_json::json!({"id": 19, "login": "alice", "type": "User"})),
            Reply::json(
                serde_json::json!({"id": 73, "full_name": "my-org/tool", "owner": {"type": "Organization"}}),
            ),
        ]);
        let identity = client.identity().unwrap();
        super::super::auth::check_identity("alice", &identity).unwrap();
        let repository = client.repository("my-org/tool").unwrap();
        assert_eq!(repository.full_name, "my-org/tool");
        assert_ne!(
            identity.login,
            repository.full_name.split('/').next().unwrap()
        );
        let requests = handle.join().unwrap();
        assert!(requests[0].head.starts_with("GET /user "));
        assert!(requests[1].head.starts_with("GET /repos/my-org/tool "));
    }

    fn sha(n: usize) -> String {
        format!("{n:040x}")
    }
    fn object(kind: &str, n: usize) -> serde_json::Value {
        serde_json::json!({ "type": kind, "sha": sha(n), "url": "https://attacker.invalid/ignored" })
    }
    fn reference(tag: &str, kind: &str, n: usize) -> Reply {
        Reply::json(
            serde_json::json!({ "ref": format!("refs/tags/{tag}"), "object": object(kind, n) }),
        )
    }
    fn release(id: usize) -> serde_json::Value {
        serde_json::json!({ "id": id, "tag_name": "v1", "draft": true, "prerelease": false,
            "name": "title", "body": "notes", "upload_url": "https://attacker.invalid/upload" })
    }
    fn asset(id: usize) -> serde_json::Value {
        serde_json::json!({ "id": id, "name": "file", "state": "uploaded", "size": 3,
            "digest": null, "browser_download_url": "https://attacker.invalid/asset" })
    }

    #[test]
    fn repository_projects_extra_fields_and_checks_identity() {
        let (mut api, handle) = client(vec![
            Reply::json(serde_json::json!({ "id": 7, "full_name": "Owner/Repo", "private": true })),
            Reply::json(serde_json::json!({ "id": 7, "full_name": "other/repo" })),
        ]);
        assert_eq!(api.repository("owner/repo").unwrap().id, 7);
        assert!(
            api.repository("owner/repo")
                .unwrap_err()
                .to_string()
                .contains("identity")
        );
        let requests = handle.join().unwrap();
        assert!(
            requests[0]
                .head
                .starts_with("GET /repos/owner/repo HTTP/1.1")
        );
        assert!(
            requests[0]
                .head
                .to_lowercase()
                .contains(&format!("x-github-api-version: {API_VERSION}"))
        );
    }

    #[test]
    fn annotated_tag_peels_exact_ref_and_ignores_urls() {
        let (mut api, handle) = client(vec![
            reference("release/v1", "tag", 1),
            Reply::json(serde_json::json!({ "sha": sha(1), "object": object("tag", 2) })),
            Reply::json(serde_json::json!({ "sha": sha(2), "object": object("commit", 3) })),
        ]);
        assert_eq!(api.tag("o/r", "release/v1").unwrap(), Some(sha(3)));
        let requests = handle.join().unwrap();
        assert!(
            requests[0]
                .head
                .starts_with("GET /repos/o/r/git/ref/tags/release%2Fv1 HTTP/1.1")
        );
        assert!(
            requests[1]
                .head
                .starts_with(&format!("GET /repos/o/r/git/tags/{} ", sha(1)))
        );
    }

    #[test]
    fn only_initial_ref_404_means_missing() {
        let (mut api, handle) = client(vec![
            Reply::status(404, serde_json::json!({})),
            reference("v1", "tag", 1),
            Reply::status(404, serde_json::json!({})),
            Reply::status(403, serde_json::json!({})),
        ]);
        assert_eq!(api.tag("o/r", "v1").unwrap(), None);
        assert!(
            api.tag("o/r", "v1")
                .unwrap_err()
                .to_string()
                .contains("404")
        );
        assert!(
            api.tag("o/r", "v1")
                .unwrap_err()
                .to_string()
                .contains("403")
        );
        assert_eq!(handle.join().unwrap().len(), 4);
    }

    #[test]
    fn tag_ref_object_identity_and_type_are_checked() {
        let (mut api, handle) = client(vec![
            reference("other", "commit", 1),
            reference("v1", "tree", 1),
            reference("v1", "tag", 1),
            Reply::json(serde_json::json!({ "sha": sha(2), "object": object("commit", 3) })),
            reference("v1", "tag", 1),
            Reply::json(serde_json::json!({ "sha": sha(1), "object": object("tag", 1) })),
        ]);
        for expected in [
            "reference identity",
            "resolve to a commit",
            "tag identity",
            "cycle",
        ] {
            assert!(
                api.tag("o/r", "v1")
                    .unwrap_err()
                    .to_string()
                    .contains(expected)
            );
        }
        handle.join().unwrap();
    }

    #[test]
    fn tag_depth_is_bounded() {
        let mut replies = vec![reference("v1", "tag", 1)];
        for n in 1..=TAG_DEPTH {
            replies.push(Reply::json(
                serde_json::json!({ "sha": sha(n), "object": object("tag", n + 1) }),
            ));
        }
        let (mut api, handle) = client(replies);
        assert!(
            api.tag("o/r", "v1")
                .unwrap_err()
                .to_string()
                .contains("depth exceeds")
        );
        assert_eq!(handle.join().unwrap().len(), TAG_DEPTH + 1);
    }

    #[test]
    fn commit_exists_requires_full_exact_identity() {
        let (mut api, handle) = client(vec![
            Reply::json(serde_json::json!({ "sha": sha(1), "parents": [] })),
            Reply::json(serde_json::json!({ "sha": sha(2) })),
            Reply::status(404, serde_json::json!({})),
        ]);
        assert!(api.commit_exists("o/r", "abcd").is_err());
        api.commit_exists("o/r", &sha(1)).unwrap();
        assert!(api.commit_exists("o/r", &sha(1)).is_err());
        assert!(
            api.commit_exists("o/r", &sha(1))
                .unwrap_err()
                .to_string()
                .contains("404")
        );
        handle.join().unwrap();
    }

    #[test]
    fn release_pagination_constructs_numbered_urls_and_ignores_link() {
        let mut first = Reply::json((1..=100).map(release).collect());
        first.headers.push((
            "Link",
            "<https://attacker.invalid/?access_token=secret>; rel=\"next\"".into(),
        ));
        let (mut api, handle) = client(vec![first, Reply::json(serde_json::json!([release(101)]))]);
        assert_eq!(api.releases("o/r").unwrap().len(), 101);
        let requests = handle.join().unwrap();
        assert!(
            requests[0]
                .head
                .starts_with("GET /repos/o/r/releases?per_page=100&page=1 ")
        );
        assert!(
            requests[1]
                .head
                .starts_with("GET /repos/o/r/releases?per_page=100&page=2 ")
        );
    }

    #[test]
    fn asset_pagination_rejects_oversized_and_duplicate_pages() {
        let (mut api, handle) = client(vec![
            Reply::json((1..=101).map(asset).collect()),
            Reply::json(serde_json::json!([asset(1), asset(1)])),
        ]);
        assert!(
            api.assets("o/r", 9)
                .unwrap_err()
                .to_string()
                .contains("too many")
        );
        assert!(
            api.assets("o/r", 9)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
        assert!(
            handle.join().unwrap()[0]
                .head
                .starts_with("GET /repos/o/r/releases/9/assets?per_page=100&page=1 ")
        );
    }

    #[test]
    fn pagination_never_exceeds_one_hundred_pages() {
        let replies = (0..PAGE_LIMIT)
            .map(|page| {
                Reply::json(
                    (1..=PAGE_SIZE)
                        .map(|n| release(page * PAGE_SIZE + n))
                        .collect(),
                )
            })
            .collect();
        let (mut api, handle) = client(replies);
        assert!(
            api.releases("o/r")
                .unwrap_err()
                .to_string()
                .contains("pagination limit")
        );
        assert_eq!(handle.join().unwrap().len(), PAGE_LIMIT);
    }

    #[test]
    fn errors_never_echo_server_secrets_or_urls() {
        let sensitive = "test-secret-token https://release-assets.githubusercontent.com/a?sig=secret Authorization: Bearer secret";
        let (mut api, handle) = client(vec![
            Reply::status(422, serde_json::json!({ "message": sensitive })),
            Reply {
                status: 200,
                headers: vec![],
                body: sensitive.as_bytes().to_vec(),
            },
            Reply {
                status: 403,
                headers: vec![(
                    "X-GitHub-SSO",
                    "required; url=https://github.com/orgs/my-org/sso?authorization_request=secret"
                        .into(),
                )],
                body: sensitive.as_bytes().to_vec(),
            },
        ]);
        for index in 0..3 {
            let error = format!("{:#}", api.repository("o/r").unwrap_err());
            for forbidden in ["test-secret-token", "https://", "sig=", "Authorization"] {
                assert!(!error.contains(forbidden), "{error}");
            }
            if index == 2 {
                assert!(error.contains("SSO authorization"), "{error}");
            }
        }
        handle.join().unwrap();
    }

    #[test]
    fn production_download_host_and_credential_guards() {
        assert!(
            download_auth("https://api.github.com/repos/o/r/releases/assets/1", false).unwrap()
        );
        for host in [
            "release-assets.githubusercontent.com",
            "objects.githubusercontent.com",
            "objects-origin.githubusercontent.com",
            "github-releases.githubusercontent.com",
        ] {
            assert!(!download_auth(&format!("https://{host}/a?sig=private"), true).unwrap());
        }
        for url in [
            "http://release-assets.githubusercontent.com/a",
            "https://attacker.invalid/a",
            "https://release-assets.githubusercontent.com.evil.invalid/a",
            "https://user:secret@release-assets.githubusercontent.com/a",
            "https://release-assets.githubusercontent.com:443/a",
            "https://release-assets.githubusercontent.com:9999/a",
            "//release-assets.githubusercontent.com/a",
            "https://api.github.com/repos/o/r/releases/assets/1",
            "https://release-assets.githubusercontent.com/a#secret",
        ] {
            assert!(download_auth(url, true).is_err(), "accepted {url}");
        }
        assert!(download_auth("https://api.github.com/a?token=secret", false).is_err());
    }

    #[test]
    fn binary_redirect_does_not_forward_authorization() {
        let (download, downloaded) = server(vec![Reply {
            status: 200,
            headers: vec![],
            body: b"abc".to_vec(),
        }]);
        let (api, received) = server(vec![Reply::redirect(&format!("{download}/a?sig=private"))]);
        let mut client = Client::loopback(api.clone(), api, Some(download));
        assert_eq!(
            client.download_digest("o/r", 7, 3).unwrap(),
            FileEntry {
                size: 3,
                sha256: format!("{:x}", Sha256::digest(b"abc"))
            }
        );
        let initial = received.join().unwrap();
        assert!(
            initial[0]
                .head
                .to_lowercase()
                .contains("authorization: bearer test-secret-token")
        );
        assert!(
            initial[0]
                .head
                .to_lowercase()
                .contains("accept: application/octet-stream")
        );
        let redirected = downloaded.join().unwrap();
        assert!(!redirected[0].head.to_lowercase().contains("authorization:"));
        assert!(redirected[0].head.starts_with("GET /a?sig=private "));
    }

    #[test]
    fn binary_download_rejects_unsafe_redirect_and_wrong_sizes() {
        let (mut api, handle) = client(vec![
            Reply::redirect("https://attacker.invalid/a?sig=private"),
            Reply {
                status: 200,
                headers: vec![],
                body: b"abc".to_vec(),
            },
            Reply {
                status: 200,
                headers: vec![],
                body: b"a".to_vec(),
            },
        ]);
        let error = api.download_digest("o/r", 1, 3).unwrap_err().to_string();
        assert!(error.contains("not allowed"));
        assert!(!error.contains("attacker") && !error.contains("sig="));
        assert!(api.download_digest("o/r", 1, 2).is_err());
        assert!(api.download_digest("o/r", 1, 3).is_err());
        assert!(api.download_digest("o/r", 1, ASSET_LIMIT + 1).is_err());
        handle.join().unwrap();
    }

    #[test]
    fn upload_streams_file_with_explicit_length_and_encoded_name() {
        let mut reply = asset(7);
        reply["name"] = "a &?#.zip".into();
        let (mut api, handle) = client(vec![Reply::status(201, reply)]);
        let temporary = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temporary.path(), b"abc").unwrap();
        let asset = Asset {
            name: "a &?#.zip".into(),
            size: 3,
            sha256: "unused".into(),
        };
        assert_eq!(
            api.upload("o/r", 9, &asset, temporary.path()).unwrap().id,
            7
        );
        let requests = handle.join().unwrap();
        assert!(
            requests[0]
                .head
                .starts_with("POST /repos/o/r/releases/9/assets?name=a%20%26%3F%23.zip ")
        );
        assert!(
            requests[0]
                .head
                .to_lowercase()
                .contains("content-length: 3")
        );
        assert!(
            !requests[0]
                .head
                .to_lowercase()
                .contains("transfer-encoding:")
        );
        assert_eq!(requests[0].body, b"abc");
    }

    #[test]
    fn create_draft_always_sets_draft_and_sends_no_publish_option() {
        let (mut api, handle) = client(vec![Reply::status(201, release(7))]);
        let plan = Plan {
            schema: 1,
            id: "id".into(),
            implementation: "test".into(),
            engine_source_id: "test".into(),
            collection_id: "collection".into(),
            policy_id: "policy".into(),
            source_commit: sha(1),
            repository: Repository {
                id: 1,
                full_name: "o/r".into(),
            },
            tag: "v1".into(),
            create_tag_if_missing: false,
            title: "title".into(),
            notes: "notes".into(),
            prerelease: false,
            assets: vec![],
        };
        assert!(api.create_draft(&plan, "marked notes").unwrap().draft);
        let requests = handle.join().unwrap();
        assert!(requests[0].head.starts_with("POST /repos/o/r/releases "));
        let payload: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(payload["draft"], true);
        assert_eq!(payload["body"], "marked notes");
        assert!(payload.get("make_latest").is_none());
    }

    #[test]
    fn mutation_disconnect_is_uncertain_and_not_retried() {
        let (mut api, handle) = client(vec![Reply {
            status: 0,
            headers: vec![],
            body: vec![],
        }]);
        let error = api
            .create_tag("o/r", "v1", &sha(1))
            .unwrap_err()
            .to_string();
        assert!(error.contains("uncertain"));
        assert_eq!(handle.join().unwrap().len(), 1);
    }

    #[test]
    fn json_response_is_bounded() {
        let (mut api, handle) = client(vec![Reply {
            status: 200,
            headers: vec![],
            body: vec![b' '; JSON_LIMIT as usize + 1],
        }]);
        assert!(
            api.repository("o/r")
                .unwrap_err()
                .to_string()
                .contains("exceeds 16 MiB")
        );
        handle.join().unwrap();
    }

    #[test]
    fn read_status_retries_are_bounded_and_respect_retry_after() {
        let transient = |status| Reply {
            status,
            headers: vec![("Retry-After", "0".into())],
            body: vec![],
        };
        let (mut api, handle) = client(vec![
            transient(503),
            transient(429),
            Reply::json(serde_json::json!({ "id": 1, "full_name": "o/r" })),
            transient(502),
            transient(504),
            transient(503),
            Reply {
                status: 429,
                headers: vec![("Retry-After", "3".into())],
                body: vec![],
            },
            Reply {
                status: 429,
                headers: vec![("Retry-After", "tomorrow".into())],
                body: vec![],
            },
        ]);
        assert_eq!(api.repository("o/r").unwrap().id, 1);
        assert!(
            api.repository("o/r")
                .unwrap_err()
                .to_string()
                .contains("503")
        );
        assert!(
            api.repository("o/r")
                .unwrap_err()
                .to_string()
                .contains("429")
        );
        assert!(
            api.repository("o/r")
                .unwrap_err()
                .to_string()
                .contains("429")
        );
        let requests = handle.join().unwrap();
        assert_eq!(requests.len(), 8);
        assert!(
            requests
                .iter()
                .all(|request| request.head.starts_with("GET "))
        );
    }

    #[test]
    fn mutations_never_retry_status_or_follow_redirects() {
        let (mut api, handle) = client(vec![
            Reply {
                status: 503,
                headers: vec![("Retry-After", "0".into())],
                body: vec![],
            },
            Reply::redirect("https://attacker.invalid/mutation"),
        ]);
        assert!(
            api.create_tag("o/r", "v1", &sha(1))
                .unwrap_err()
                .to_string()
                .contains("503")
        );
        assert!(
            api.create_tag("o/r", "v1", &sha(1))
                .unwrap_err()
                .to_string()
                .contains("redirect")
        );
        let requests = handle.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|request| request.head.starts_with("POST "))
        );
    }

    #[test]
    fn streamed_download_without_length_enforces_exact_size() {
        let chunked = |body: &[u8]| Reply {
            status: 200,
            headers: vec![("Transfer-Encoding", "chunked".into())],
            body: body.to_vec(),
        };
        let (mut api, handle) = client(vec![
            chunked(b"3\r\nabc\r\n0\r\n\r\n"),
            chunked(b"4\r\nabcd\r\n0\r\n\r\n"),
            chunked(b"1\r\na\r\n0\r\n\r\n"),
        ]);
        assert_eq!(api.download_digest("o/r", 1, 3).unwrap().size, 3);
        assert!(
            api.download_digest("o/r", 1, 3)
                .unwrap_err()
                .to_string()
                .contains("exceeds expected")
        );
        assert!(
            api.download_digest("o/r", 1, 3)
                .unwrap_err()
                .to_string()
                .contains("shorter")
        );
        handle.join().unwrap();
    }
}
