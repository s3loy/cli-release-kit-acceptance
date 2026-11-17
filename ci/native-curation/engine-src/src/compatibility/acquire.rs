//! Acquisition of reviewed tool archives. No downloaded program is executed.
use super::{ArchiveLinkPolicy, ToolInput};
use anyhow::{Context, Result, bail, ensure};
use flate2::bufread::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    time::Duration,
};
use ureq::{Agent, http::Uri};
const DOWNLOAD_LIMIT: u64 = 1024 * 1024 * 1024;
const EXPANDED_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
const ENTRY_LIMIT: usize = 100_000;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Member {
    sha256: String,
    size: u64,
    executable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    symlink_target: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    tool: ToolInput,
    root: String,
    members: BTreeMap<String, Member>,
    inventory_sha256: String,
}
fn owned_directory(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path.parent().is_some()
            && path
                .components()
                .all(|p| !matches!(p, Component::ParentDir | Component::CurDir)),
        "tool directory must be absolute and normalized"
    );
    for ancestor in path.ancestors() {
        if let Ok(meta) = fs::symlink_metadata(ancestor) {
            ensure!(
                !meta.file_type().is_symlink(),
                "tool directory contains a symlink"
            );
        }
    }
    fs::create_dir_all(path)?;
    ensure!(
        fs::symlink_metadata(path)?.is_dir(),
        "tool output must be a directory"
    );
    Ok(())
}
/// Initial endpoints are reviewed source inputs. Redirects retain HTTPS and
/// carry no credentials; archive bytes are accepted only under the saved hash.
pub(crate) fn validate_download_url(url: &str) -> Result<()> {
    let uri: Uri = url
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid pinned archive download URL"))?;
    ensure!(
        uri.scheme_str() == Some("https")
            && uri.host().is_some_and(|host| !host.is_empty())
            && uri
                .authority()
                .is_some_and(|authority| !authority.as_str().contains('@'))
            && !url.contains(['#', '\\'])
            && !url.chars().any(char::is_whitespace)
            && !url.chars().any(char::is_control),
        "pinned archive download requires an absolute credential-free HTTPS endpoint"
    );
    Ok(())
}
fn redirect_location(current: &str, location: &str) -> Result<String> {
    ensure!(
        !location.is_empty()
            && !location.contains(['#', '\\'])
            && !location.chars().any(char::is_control),
        "invalid archive redirect location"
    );
    let absolute = location.find(':').is_some_and(|colon| {
        location
            .find(['/', '?'])
            .is_none_or(|separator| colon < separator)
    });
    let resolved = if absolute {
        location.to_owned()
    } else if location.starts_with("//") {
        format!("https:{location}")
    } else {
        let base: Uri = current
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid archive redirect base"))?;
        let authority = base
            .authority()
            .context("archive redirect base lacks an authority")?;
        let path = if location.starts_with('/') {
            location.to_owned()
        } else if location.starts_with('?') {
            format!("{}{location}", base.path())
        } else {
            let directory = base
                .path()
                .rsplit_once('/')
                .map(|(prefix, _)| prefix)
                .unwrap_or("");
            format!("{directory}/{location}")
        };
        format!("https://{authority}{path}")
    };
    validate_download_url(&resolved)?;
    Ok(resolved)
}

fn download(
    agent: &Agent,
    source: &str,
    path: &Path,
    expected: &str,
    budget: &mut u64,
    allow_empty: bool,
) -> Result<()> {
    let mut current = source.to_owned();
    for hop in 0..=5 {
        validate_download_url(&current)?;
        let mut response = agent
            .get(&current)
            .header("Accept", "application/octet-stream")
            .call()
            .map_err(|_| anyhow::anyhow!("tool download request failed"))?;
        if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
            ensure!(hop < 5, "tool download redirect bound exceeded");
            let location = response
                .headers()
                .get("Location")
                .and_then(|value| value.to_str().ok())
                .context("archive redirect lacks a valid location")?;
            current = redirect_location(&current, location)?;
            continue;
        }
        ensure!(
            response.status().as_u16() == 200,
            "tool download HTTP status {}",
            response.status().as_u16()
        );
        if let Some(length) = response.headers().get("Content-Length") {
            let size = length.to_str()?.parse::<u64>()?;
            ensure!(
                (size > 0 || allow_empty) && size <= *budget,
                "tool download exceeds remaining budget"
            );
        }
        let mut out = OpenOptions::new().write(true).create_new(true).open(path)?;
        let mut reader = response.body_mut().as_reader();
        let mut hash = Sha256::new();
        let mut total = 0;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let n = reader
                .read(&mut buffer)
                .map_err(|_| anyhow::anyhow!("tool download body failed"))?;
            if n == 0 {
                break;
            }
            total += n as u64;
            ensure!(total <= *budget, "tool download exceeds remaining budget");
            hash.update(&buffer[..n]);
            out.write_all(&buffer[..n])?;
        }
        ensure!(
            (total > 0 || allow_empty) && format!("{:x}", hash.finalize()) == expected,
            "downloaded tool archive SHA256 differs from the saved pin"
        );
        out.sync_all()?;
        *budget -= total;
        return Ok(());
    }
    bail!("tool download redirect bound exceeded")
}
fn archive_name(raw: &str) -> Result<String> {
    let value = raw.trim_end_matches('/');
    crate::config::relative(value)?;
    ensure!(
        value.len() <= 4096,
        "tool archive member name exceeds bound"
    );
    Ok(value.into())
}
fn output_file(
    root: &Path,
    name: &str,
    mode: u32,
    declared: u64,
    mut reader: impl Read,
    members: &mut BTreeMap<String, Member>,
    remaining: &mut u64,
) -> Result<()> {
    ensure!(
        members.len() < ENTRY_LIMIT && !members.contains_key(name),
        "duplicate or excessive tool archive members"
    );
    ensure!(
        mode & 0o7000 == 0 && declared <= *remaining,
        "tool member has special permissions or exceeds expanded bound"
    );
    let path = crate::config::safe_join(root, name)?;
    fs::create_dir_all(path.parent().context("tool member lacks a parent")?)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    let mut hash = Sha256::new();
    let mut total = 0;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        ensure!(
            total <= declared && total <= *remaining,
            "tool archive member exceeds declared or expanded size"
        );
        hash.update(&buffer[..n]);
        file.write_all(&buffer[..n])?;
    }
    ensure!(
        total == declared,
        "tool archive member size differs from header"
    );
    *remaining -= total;
    let executable = cfg!(unix) && mode & 0o111 != 0;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
        )?;
    }
    members.insert(
        name.into(),
        Member {
            sha256: format!("{:x}", hash.finalize()),
            size: total,
            executable,
            symlink_target: None,
        },
    );
    Ok(())
}
#[derive(Clone, Debug)]
enum ArchiveEntry {
    Directory,
    File,
    Link { target: String, hard: bool },
}

// Include implicit parents, so archive ordering cannot hide file/directory or
// case collisions. The same accounting bounds directories created by aliases.
struct ArchiveTree {
    entries: BTreeMap<String, ArchiveEntry>,
    folded: BTreeMap<String, String>,
    limit: usize,
}
impl ArchiveTree {
    fn new(limit: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            folded: BTreeMap::new(),
            limit,
        }
    }
    fn insert(&mut self, name: &str, entry: ArchiveEntry) -> Result<()> {
        crate::config::relative(name)?;
        ensure!(name.len() <= 4096, "tool materialized path exceeds bound");
        let mut prefix = String::new();
        let mut parts = name.split('/').peekable();
        while let Some(part) = parts.next() {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            let kind = if parts.peek().is_some() {
                ArchiveEntry::Directory
            } else {
                entry.clone()
            };
            let folded = prefix.to_ascii_lowercase();
            if let Some(previous) = self.folded.get(&folded) {
                ensure!(previous == &prefix, "case-colliding tool archive paths");
            }
            if let Some(previous) = self.entries.get(&prefix) {
                ensure!(
                    matches!(
                        (previous, &kind),
                        (ArchiveEntry::Directory, ArchiveEntry::Directory)
                    ),
                    "colliding tool archive file, directory or link paths"
                );
            } else {
                ensure!(
                    self.entries.len() < self.limit,
                    "tool archive tree entry count exceeds bound"
                );
                self.folded.insert(folded, prefix.clone());
                self.entries.insert(prefix.clone(), kind);
            }
        }
        Ok(())
    }

    fn resolve(&self, name: &str) -> Result<String> {
        let top = name.split('/').next().unwrap();
        let mut resolved = Vec::new();
        let mut pending: VecDeque<_> = name.split('/').map(str::to_owned).collect();
        let mut seen = BTreeSet::new();
        let mut requires_file = false;
        while let Some(part) = pending.pop_front() {
            match part.as_str() {
                "" | "." => continue,
                ".." => {
                    ensure!(resolved.pop().is_some(), "tool link escapes output root");
                    continue;
                }
                _ => resolved.push(part),
            }
            ensure!(
                resolved[0] == top,
                "tool link escapes its top-level SDK directory"
            );
            let prefix = resolved.join("/");
            ensure!(
                prefix.len() <= 4096,
                "tool link expansion path exceeds bound"
            );
            match self
                .entries
                .get(&prefix)
                .context("dangling tool archive link target")?
            {
                ArchiveEntry::Link { target, hard } => {
                    ensure!(
                        seen.insert(prefix) && seen.len() <= 64,
                        "cyclic or excessive tool link chain"
                    );
                    ensure!(
                        !*hard || pending.is_empty(),
                        "hard tool link used as a directory"
                    );
                    requires_file |= *hard;
                    if *hard {
                        resolved.clear();
                    } else {
                        resolved.pop();
                    }
                    for part in target.split('/').rev() {
                        pending.push_front(part.to_owned());
                    }
                    let expanded = resolved
                        .iter()
                        .chain(pending.iter())
                        .map(|p| p.len() + 1)
                        .sum::<usize>();
                    ensure!(expanded <= 4097, "tool link expansion path exceeds bound");
                }
                ArchiveEntry::File => ensure!(
                    pending.is_empty(),
                    "tool link suffix traverses a regular file"
                ),
                ArchiveEntry::Directory => (),
            }
        }
        let result = resolved.join("/");
        let kind = self
            .entries
            .get(&result)
            .context("dangling tool archive link target")?;
        ensure!(
            !requires_file || matches!(kind, ArchiveEntry::File),
            "hard tool link target must resolve to an archived regular file"
        );
        Ok(result)
    }
}

enum LinkAction {
    Directory(String),
    File { destination: String, source: String },
}

// Plan the complete logical expansion before creating any aliases. Preserving
// vendor links retains the same graph, path, cycle and expansion bounds.
fn plan_links(
    tree: &ArchiveTree,
    members: &BTreeMap<String, Member>,
    mut remaining: u64,
) -> Result<Vec<LinkAction>> {
    let mut actions = Vec::new();
    let mut output = ArchiveTree::new(tree.limit);
    let mut children: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (name, kind) in &tree.entries {
        if !matches!(kind, ArchiveEntry::Link { .. }) {
            output.insert(name, kind.clone())?;
        }
        if let Some((parent, _)) = name.rsplit_once('/') {
            children.entry(parent).or_default().push(name);
        }
    }
    enum Task {
        Visit { source: String, destination: String },
        Leave(String),
    }
    for (name, kind) in &tree.entries {
        if !matches!(kind, ArchiveEntry::Link { .. }) {
            continue;
        }
        let mut pending = vec![Task::Visit {
            source: name.clone(),
            destination: name.clone(),
        }];
        let mut active = BTreeSet::new();
        while let Some(task) = pending.pop() {
            let (source, destination) = match task {
                Task::Leave(source) => {
                    active.remove(&source);
                    continue;
                }
                Task::Visit {
                    source,
                    destination,
                } => (tree.resolve(&source)?, destination),
            };
            match &tree.entries[&source] {
                ArchiveEntry::File => {
                    output.insert(&destination, ArchiveEntry::File)?;
                    let member = members
                        .get(&source)
                        .context("missing archived tool file")?
                        .clone();
                    ensure!(
                        member.size <= remaining,
                        "tool link expansion exceeds expanded bound"
                    );
                    remaining -= member.size;
                    actions.push(LinkAction::File {
                        destination,
                        source,
                    });
                }
                ArchiveEntry::Directory => {
                    ensure!(
                        active.insert(source.clone()),
                        "cyclic tool directory link expansion"
                    );
                    output.insert(&destination, ArchiveEntry::Directory)?;
                    actions.push(LinkAction::Directory(destination.clone()));
                    pending.push(Task::Leave(source.clone()));
                    for child in children.get(source.as_str()).into_iter().flatten().rev() {
                        let basename = child.rsplit('/').next().unwrap();
                        ensure!(
                            pending.len() < tree.limit,
                            "tool link expansion work exceeds bound"
                        );
                        pending.push(Task::Visit {
                            source: (*child).to_owned(),
                            destination: format!("{destination}/{basename}"),
                        });
                    }
                }
                ArchiveEntry::Link { .. } => unreachable!("resolved archive link"),
            }
        }
    }
    Ok(actions)
}

fn copy_link_file(
    root: &Path,
    destination: &str,
    source: &str,
    members: &mut BTreeMap<String, Member>,
    remaining: &mut u64,
) -> Result<()> {
    let member = members
        .get(source)
        .context("missing archived tool file")?
        .clone();
    output_file(
        root,
        destination,
        if member.executable { 0o755 } else { 0o644 },
        member.size,
        File::open(crate::config::safe_join(root, source)?)?,
        members,
        remaining,
    )
}

fn symlink_member(target: String) -> Member {
    Member {
        sha256: crate::source::digest(target.as_bytes()),
        size: target.len() as u64,
        executable: false,
        symlink_target: Some(target),
    }
}

fn materialize_links(
    root: &Path,
    tree: &ArchiveTree,
    members: &mut BTreeMap<String, Member>,
    remaining: &mut u64,
    policy: ArchiveLinkPolicy,
) -> Result<()> {
    let actions = plan_links(tree, members, *remaining)?;
    if policy.is_materialize() {
        for action in actions {
            match action {
                LinkAction::Directory(name) => {
                    fs::create_dir_all(crate::config::safe_join(root, &name)?)?
                }
                LinkAction::File {
                    destination,
                    source,
                } => copy_link_file(root, &destination, &source, members, remaining)?,
            }
        }
        return Ok(());
    }
    ensure!(
        cfg!(unix),
        "verified tool symlink preservation requires a Unix host"
    );
    let mut declared_bytes = 0u64;
    for (name, kind) in &tree.entries {
        match kind {
            ArchiveEntry::Link {
                target,
                hard: false,
            } => declared_bytes += target.len() as u64,
            ArchiveEntry::Link { hard: true, .. } => {
                declared_bytes += members[&tree.resolve(name)?].size
            }
            _ => (),
        }
    }
    ensure!(
        declared_bytes <= *remaining,
        "preserved tool links exceed expanded bound"
    );
    for (name, kind) in &tree.entries {
        match kind {
            ArchiveEntry::Directory => fs::create_dir_all(crate::config::safe_join(root, name)?)?,
            ArchiveEntry::Link { hard: true, .. } => {
                copy_link_file(root, name, &tree.resolve(name)?, members, remaining)?
            }
            _ => (),
        }
    }
    for (name, kind) in &tree.entries {
        if let ArchiveEntry::Link {
            target,
            hard: false,
        } = kind
        {
            let member = symlink_member(target.clone());
            ensure!(
                member.size <= *remaining && members.len() < ENTRY_LIMIT,
                "preserved tool links exceed expanded bound"
            );
            let path = crate::config::safe_join(root, name)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(target, &path)?;
            #[cfg(not(unix))]
            let _ = path;
            *remaining -= member.size;
            ensure!(
                members.insert(name.clone(), member).is_none(),
                "duplicate preserved tool link"
            );
        }
    }
    Ok(())
}

fn link_target(name: &str, target: &str, hard: bool) -> Result<String> {
    ensure!(
        !target.is_empty()
            && target.len() <= 4096
            && !target.starts_with('/')
            && !target.contains(['\\', ':'])
            && !target.chars().any(char::is_control),
        "tool archive link target must be an internal relative path"
    );
    let mut parts = if hard {
        vec![]
    } else {
        name.split('/').map(str::to_owned).collect::<Vec<_>>()
    };
    if !hard {
        parts.pop();
    }
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                ensure!(
                    parts.pop().is_some(),
                    "tool archive link escapes output root"
                );
            }
            p => parts.push(p.into()),
        }
    }
    let result = parts.join("/");
    archive_name(&result)?;
    ensure!(
        name.split('/').next() == result.split('/').next(),
        "tool archive link escapes its top-level SDK directory"
    );
    Ok(result)
}
fn unpack(path: &Path, root: &Path, limit: u64) -> Result<(String, BTreeMap<String, Member>)> {
    unpack_with_policy(path, root, limit, ArchiveLinkPolicy::Materialize)
}
fn unpack_with_policy(
    path: &Path,
    root: &Path,
    limit: u64,
    policy: ArchiveLinkPolicy,
) -> Result<(String, BTreeMap<String, Member>)> {
    unpack_bounded(path, root, limit, ENTRY_LIMIT, policy)
}
fn unpack_bounded(
    path: &Path,
    root: &Path,
    limit: u64,
    entry_limit: usize,
    policy: ArchiveLinkPolicy,
) -> Result<(String, BTreeMap<String, Member>)> {
    let mut members = BTreeMap::new();
    let mut names = BTreeSet::new();
    let mut tree = ArchiveTree::new(entry_limit);
    let mut links = 0usize;
    let mut remaining = limit;
    let filename = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("invalid tool archive name")?;
    if filename.ends_with(".tar.gz") {
        let mut archive = tar::Archive::new(GzDecoder::new(BufReader::new(File::open(path)?)));
        for entry in archive.entries()? {
            let mut entry = entry?;
            let name = archive_name(std::str::from_utf8(&entry.path_bytes())?)?;
            ensure!(
                names.len() < entry_limit && names.insert(name.clone()),
                "duplicate or excessive tool archive entries"
            );
            let kind = entry.header().entry_type();
            let mode = entry.header().mode()?;
            if kind.is_dir() {
                ensure!(mode & 0o7000 == 0, "special tool directory permissions");
                tree.insert(&name, ArchiveEntry::Directory)?;
                fs::create_dir_all(crate::config::safe_join(root, &name)?)?;
            } else if kind.is_file() {
                tree.insert(&name, ArchiveEntry::File)?;
                let size = entry.size();
                output_file(
                    root,
                    &name,
                    mode,
                    size,
                    &mut entry,
                    &mut members,
                    &mut remaining,
                )?;
            } else if kind.is_symlink() || kind.is_hard_link() {
                ensure!(links < 4096, "too many tool archive links");
                links += 1;
                let target = entry
                    .link_name()?
                    .context("tool link lacks a target")?
                    .to_str()
                    .context("non-UTF8 tool link target")?
                    .to_owned();
                link_target(&name, &target, kind.is_hard_link())?;
                tree.insert(
                    &name,
                    ArchiveEntry::Link {
                        target,
                        hard: kind.is_hard_link(),
                    },
                )?;
            } else {
                bail!("tool archive contains a special file");
            }
        }
        let mut decoder = archive.into_inner();
        let mut tail = Vec::new();
        decoder
            .by_ref()
            .take(1024 * 1024 + 1)
            .read_to_end(&mut tail)?;
        ensure!(
            tail.len() <= 1024 * 1024 && tail.iter().all(|b| *b == 0),
            "unexpected tool tar trailing data"
        );
        ensure!(
            decoder.into_inner().fill_buf()?.is_empty(),
            "extra compressed stream or trailing bytes in tool archive"
        );
    } else if filename.ends_with(".zip") {
        let mut archive = zip::ZipArchive::new(File::open(path)?)?;
        ensure!(
            archive.offset() == 0 && archive.len() <= entry_limit,
            "prepended or excessive tool ZIP entries"
        );
        let mut raw = File::open(path)?;
        let mut central_position = archive.central_directory_start();
        let mut local_positions = BTreeSet::new();
        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            ensure!(
                entry.central_header_start() == central_position,
                "unaccounted or duplicate ZIP central-directory records"
            );
            raw.seek(SeekFrom::Start(central_position))?;
            let mut central = [0u8; 46];
            raw.read_exact(&mut central)?;
            ensure!(&central[..4] == b"PK\x01\x02", "invalid ZIP central header");
            let field = |at| u16::from_le_bytes([central[at], central[at + 1]]) as u64;
            central_position = central_position
                .checked_add(46 + field(28) + field(30) + field(32))
                .context("ZIP central offset overflow")?;
            ensure!(
                local_positions.insert(entry.header_start()),
                "duplicate ZIP local file header"
            );
            raw.seek(SeekFrom::Start(entry.header_start()))?;
            let mut local = [0u8; 30];
            raw.read_exact(&mut local)?;
            ensure!(&local[..4] == b"PK\x03\x04", "invalid ZIP local header");
            let name_size = u16::from_le_bytes([local[26], local[27]]) as usize;
            let mut local_name = vec![0; name_size];
            raw.read_exact(&mut local_name)?;
            ensure!(
                local_name == entry.name_raw(),
                "ZIP local and central member names differ"
            );
            let name = archive_name(std::str::from_utf8(entry.name_raw())?)?;
            ensure!(names.insert(name.clone()), "duplicate tool ZIP entry");
            let mode = entry.unix_mode().unwrap_or(0o100644);
            let kind = mode & 0o170000;
            if entry.is_dir() {
                ensure!(mode & 0o7000 == 0, "special tool directory permissions");
                tree.insert(&name, ArchiveEntry::Directory)?;
                fs::create_dir_all(crate::config::safe_join(root, &name)?)?;
            } else if kind == 0o120000 {
                ensure!(
                    links < 4096 && entry.size() <= 4096,
                    "oversized tool ZIP symlink"
                );
                links += 1;
                let mut target = String::new();
                entry.take(4097).read_to_string(&mut target)?;
                link_target(&name, &target, false)?;
                tree.insert(
                    &name,
                    ArchiveEntry::Link {
                        target,
                        hard: false,
                    },
                )?;
            } else {
                ensure!(
                    kind == 0 || kind == 0o100000,
                    "tool ZIP contains a special file"
                );
                tree.insert(&name, ArchiveEntry::File)?;
                let size = entry.size();
                output_file(
                    root,
                    &name,
                    mode,
                    size,
                    &mut entry,
                    &mut members,
                    &mut remaining,
                )?;
            }
        }
        raw.seek(SeekFrom::Start(central_position))?;
        let mut end = [0u8; 4];
        raw.read_exact(&mut end)?;
        ensure!(
            end == *b"PK\x05\x06" || end == *b"PK\x06\x06",
            "unaccounted ZIP directory records"
        );
    } else {
        bail!("unsupported tool archive format; expected tar.gz or ZIP");
    }
    materialize_links(root, &tree, &mut members, &mut remaining, policy)?;
    ensure!(!members.is_empty(), "empty tool archive");
    let tops = members
        .keys()
        .map(|p| p.split('/').next().unwrap())
        .collect::<BTreeSet<_>>();
    let top = if tops.len() == 1 && members.keys().all(|p| p.contains('/')) {
        tops.first().unwrap().to_string()
    } else {
        String::new()
    };
    Ok((top, members))
}
fn inventory_digest(members: &BTreeMap<String, Member>) -> Result<String> {
    Ok(crate::source::digest(&serde_json::to_vec(members)?))
}
fn raw_members(input: &Path, filename: &str, limit: u64) -> Result<BTreeMap<String, Member>> {
    let metadata = fs::symlink_metadata(input)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= limit,
        "raw input must be a bounded regular file"
    );
    Ok(BTreeMap::from([(
        filename.to_owned(),
        Member {
            sha256: crate::source::file_digest(input)?,
            size: metadata.len(),
            executable: false,
            symlink_target: None,
        },
    )]))
}
fn materialize_raw(
    input: &Path,
    tree: &Path,
    filename: &str,
    limit: u64,
) -> Result<(String, BTreeMap<String, Member>)> {
    let expected = raw_members(input, filename, limit)?;
    let mut remaining = limit;
    let mut members = BTreeMap::new();
    output_file(
        tree,
        filename,
        0o644,
        expected[filename].size,
        File::open(input)?,
        &mut members,
        &mut remaining,
    )?;
    ensure!(members == expected, "raw input changed while being copied");
    Ok((String::new(), members))
}
fn verify_against_raw(
    input: &Path,
    tree: &Path,
    filename: &str,
    value: &Receipt,
    limit: u64,
) -> Result<()> {
    let expected = raw_members(input, filename, limit)?;
    ensure!(
        value.root.is_empty()
            && value.members == expected
            && value.inventory_sha256 == inventory_digest(&expected)?
            && inventory(tree, ArchiveLinkPolicy::Materialize)? == expected,
        "cached raw input or receipt differs from the pinned input bytes"
    );
    Ok(())
}
fn verify_against_archive(
    archive: &Path,
    owned: &Path,
    tree: &Path,
    value: &Receipt,
    limit: u64,
    policy: ArchiveLinkPolicy,
) -> Result<()> {
    let mut attempt = 0u32;
    let verification = loop {
        let path = owned.join(format!("verify-{}-{attempt}", std::process::id()));
        match fs::create_dir(&path) {
            Ok(()) => break path,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt += 1;
                ensure!(attempt < 1000, "too many owned SDK verification paths");
            }
            Err(e) => return Err(e.into()),
        }
    };
    let result = (|| {
        let (root, expected) = unpack_with_policy(archive, &verification, limit, policy)?;
        ensure!(
            root == value.root
                && expected == value.members
                && value.inventory_sha256 == inventory_digest(&expected)?
                && inventory(tree, policy)? == expected,
            "cached SDK tree or receipt differs from the pinned archive bytes"
        );
        Ok(())
    })();
    fs::remove_dir_all(&verification)
        .context("remove this invocation's SDK verification directory")?;
    result
}
fn inventory(root: &Path, policy: ArchiveLinkPolicy) -> Result<BTreeMap<String, Member>> {
    let mut pending = vec![root.to_path_buf()];
    let mut values = BTreeMap::new();
    let mut total = 0;
    let mut count = 0usize;
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            count += 1;
            ensure!(
                count <= ENTRY_LIMIT,
                "extracted tool inventory entry count exceeds bound"
            );
            let meta = fs::symlink_metadata(entry.path())?;
            let path = entry.path();
            let name = path
                .strip_prefix(root)?
                .to_str()
                .context("non-UTF8 extracted tool path")?
                .replace('\\', "/");
            crate::config::relative(&name)?;
            if meta.file_type().is_symlink() {
                ensure!(
                    policy == ArchiveLinkPolicy::PreserveVerified,
                    "extracted tool inventory contains a symlink"
                );
                let target = fs::read_link(&path)?
                    .to_str()
                    .context("non-UTF8 extracted tool link target")?
                    .to_owned();
                link_target(&name, &target, false)?;
                let member = symlink_member(target);
                total += member.size;
                ensure!(
                    total <= EXPANDED_LIMIT,
                    "extracted tool inventory exceeds expanded bound"
                );
                values.insert(name, member);
            } else if meta.is_dir() {
                pending.push(path);
            } else {
                ensure!(
                    meta.is_file() && values.len() < ENTRY_LIMIT,
                    "extracted tool inventory contains a special file or exceeds bound"
                );
                total += meta.len();
                ensure!(
                    total <= EXPANDED_LIMIT,
                    "extracted tool inventory exceeds expanded bound"
                );
                #[cfg(unix)]
                let executable = {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = meta.permissions().mode();
                    ensure!(mode & 0o7000 == 0, "special extracted tool permissions");
                    mode & 0o111 != 0
                };
                #[cfg(not(unix))]
                let executable = false;
                values.insert(
                    name,
                    Member {
                        sha256: crate::source::file_digest(&path)?,
                        size: meta.len(),
                        executable,
                        symlink_target: None,
                    },
                );
            }
        }
    }
    Ok(values)
}
/// Validates the expected archive bytes, then extracts to a new empty directory.
/// Internal file and directory links are materialized within shared bounds; no symlinks are created.
pub fn extract_tool_archive(
    path: &Path,
    directory: &Path,
    expected_sha256: &str,
) -> Result<PathBuf> {
    super::environment::digest(&format!("sha256:{expected_sha256}"))?;
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= DOWNLOAD_LIMIT,
        "tool archive must be a bounded regular file"
    );
    ensure!(
        crate::source::file_digest(path)? == expected_sha256,
        "tool archive SHA256 differs from expected input"
    );
    owned_directory(directory)?;
    ensure!(
        fs::read_dir(directory)?.next().is_none(),
        "tool extraction requires an empty owned directory"
    );
    let (root, _) = unpack(path, directory, EXPANDED_LIMIT)?;
    Ok(directory.join(root))
}
/// Reuse requires the same archive hash, saved pin and full current extracted
/// inventory. Partial or altered state fails closed and requires a fresh path.
pub fn acquire_tools(tools: &[ToolInput], directory: &Path) -> Result<BTreeMap<String, PathBuf>> {
    ensure!(tools.len() <= 32, "too many tool inputs");
    owned_directory(directory)?;
    let archives = directory.join("archives");
    owned_directory(&archives)?;
    let agent = Agent::new_with_config(
        Agent::config_builder()
            .https_only(true)
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(600)))
            .timeout_connect(Some(Duration::from_secs(15)))
            .timeout_per_read(Some(Duration::from_secs(30)))
            .user_agent("relship-tool-acquisition")
            .build(),
    );
    let mut outputs = BTreeMap::new();
    let mut budget = DOWNLOAD_LIMIT;
    let mut expanded_budget = EXPANDED_LIMIT;
    for tool in tools {
        super::validate_tool_input(tool)?;
        let (name, source, sha256, filename, raw_file, link_policy) = match tool {
            ToolInput::Archive {
                name,
                url,
                sha256,
                filename,
                link_policy,
                ..
            } => (name, url, sha256, filename, false, *link_policy),
            ToolInput::Raw {
                name,
                url,
                sha256,
                filename,
                ..
            } => (
                name,
                url,
                sha256,
                filename,
                true,
                ArchiveLinkPolicy::Materialize,
            ),
            ToolInput::ImageContained { .. } => continue,
        };
        crate::config::relative(name)?;
        crate::config::relative(filename)?;
        ensure!(
            !name.contains('/') && !filename.contains('/') && !outputs.contains_key(name),
            "duplicate or non-basename tool input"
        );
        super::environment::digest(&format!("sha256:{sha256}"))?;
        validate_download_url(source)?;
        let archive = archives.join(filename);
        if archive.exists() {
            let meta = fs::symlink_metadata(&archive)?;
            ensure!(
                meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= budget,
                "cached tool archive is not a bounded regular file"
            );
            ensure!(
                crate::source::file_digest(&archive)? == *sha256,
                "cached tool archive differs from pin"
            );
            budget -= meta.len();
        } else {
            download(&agent, source, &archive, sha256, &mut budget, raw_file)?;
        }
        let owned = directory.join(name);
        let receipt = owned.join("receipt.json");
        let tree = owned.join("tree");
        let root = if owned.exists() {
            owned_directory(&owned)?;
            owned_directory(&tree)?;
            let meta = fs::symlink_metadata(&receipt)?;
            ensure!(
                meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= 16 * 1024 * 1024,
                "tool receipt must be a bounded regular file"
            );
            ensure!(
                receipt.is_file() && tree.is_dir(),
                "incomplete acquired tool state; use a fresh owned directory"
            );
            let raw = fs::read(&receipt)?;
            ensure!(raw.len() <= 16 * 1024 * 1024, "tool receipt exceeds bound");
            let value: Receipt = serde_json::from_slice(&raw)?;
            ensure!(value.tool == *tool, "acquired tool expected pin changed");
            if raw_file {
                verify_against_raw(&archive, &tree, filename, &value, expanded_budget)?;
            } else {
                verify_against_archive(
                    &archive,
                    &owned,
                    &tree,
                    &value,
                    expanded_budget,
                    link_policy,
                )?;
            }
            if !value.root.is_empty() {
                crate::config::relative(&value.root)?;
            }
            tree.join(value.root)
        } else {
            owned_directory(&owned)?;
            owned_directory(&tree)?;
            let (root, members) = if raw_file {
                materialize_raw(&archive, &tree, filename, expanded_budget)?
            } else {
                unpack_with_policy(&archive, &tree, expanded_budget, link_policy)?
            };
            let value = Receipt {
                tool: tool.clone(),
                root: root.clone(),
                inventory_sha256: inventory_digest(&members)?,
                members,
            };
            let mut out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(receipt)?;
            out.write_all(&serde_json::to_vec_pretty(&value)?)?;
            out.sync_all()?;
            tree.join(root)
        };
        let extracted = inventory(&tree, link_policy)?;
        let bytes: u64 = extracted.values().map(|m| m.size).sum();
        ensure!(
            bytes <= expanded_budget,
            "total extracted tool inventory exceeds bound"
        );
        expanded_budget -= bytes;
        outputs.insert(name.clone(), root);
    }
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounded_fixture(path: &Path, branching: bool) {
        let encoder = flate2::write::GzEncoder::new(
            File::create(path).unwrap(),
            flate2::Compression::default(),
        );
        let mut archive = tar::Builder::new(encoder);
        let mut file = tar::Header::new_gnu();
        file.set_mode(0o755);
        file.set_size(4);
        file.set_cksum();
        archive
            .append_data(&mut file, "sdk/tree/tool", &b"tool"[..])
            .unwrap();
        let mut directory = tar::Header::new_gnu();
        directory.set_entry_type(tar::EntryType::Directory);
        directory.set_mode(0o755);
        directory.set_size(0);
        directory.set_cksum();
        archive
            .append_data(&mut directory, "sdk/tree/empty", &[][..])
            .unwrap();
        let links = if branching {
            (0..12)
                .flat_map(|level| {
                    ["a", "b"].map(move |side| {
                        (
                            format!("sdk/level{level}/{side}"),
                            if level == 0 {
                                "../tree".to_owned()
                            } else {
                                format!("../level{}", level - 1)
                            },
                        )
                    })
                })
                .collect::<Vec<_>>()
        } else {
            vec![("sdk/alias".into(), "tree".into())]
        };
        for (name, target) in links {
            let mut link = tar::Header::new_gnu();
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_mode(0o777);
            link.set_size(0);
            link.set_link_name(target).unwrap();
            link.set_cksum();
            archive.append_data(&mut link, name, &[][..]).unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap();
    }

    #[test]
    fn directory_alias_bytes_and_implicit_directories_share_expansion_bounds() {
        let temporary = tempfile::tempdir().unwrap();
        let archive = temporary.path().join("sdk.tar.gz");
        bounded_fixture(&archive, false);
        for (name, bytes, entries, expected) in [
            ("bytes", 7, 100, Some("expanded bound")),
            ("entries", 8, 5, Some("entry count exceeds bound")),
            ("exact", 8, 7, None),
        ] {
            for policy in [
                ArchiveLinkPolicy::Materialize,
                ArchiveLinkPolicy::PreserveVerified,
            ] {
                if !cfg!(unix) && !policy.is_materialize() {
                    continue;
                }
                let output = temporary.path().join(format!("{name}-{policy:?}"));
                fs::create_dir(&output).unwrap();
                let result = unpack_bounded(&archive, &output, bytes, entries, policy);
                if let Some(expected) = expected {
                    assert!(result.unwrap_err().to_string().contains(expected), "{name}");
                } else {
                    assert_eq!(result.unwrap().1.len(), 2);
                    assert!(output.join("sdk/alias/empty").is_dir());
                }
            }
        }
    }

    #[test]
    fn branching_directory_aliases_stop_at_the_materialized_entry_budget() {
        let temporary = tempfile::tempdir().unwrap();
        let archive = temporary.path().join("sdk.tar.gz");
        bounded_fixture(&archive, true);
        for policy in [
            ArchiveLinkPolicy::Materialize,
            ArchiveLinkPolicy::PreserveVerified,
        ] {
            let output = temporary.path().join(format!("out-{policy:?}"));
            fs::create_dir(&output).unwrap();
            let error = unpack_bounded(&archive, &output, 1024 * 1024, 50, policy).unwrap_err();
            assert!(
                error.to_string().contains("entry count exceeds bound"),
                "{error}"
            );
        }
    }

    #[test]
    fn regular_member_receipts_retain_the_legacy_bytes() {
        let raw = r#"{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":4,"executable":true}"#;
        let member: Member = serde_json::from_str(raw).unwrap();
        assert_eq!(member.symlink_target, None);
        assert_eq!(serde_json::to_string(&member).unwrap(), raw);
    }

    #[test]
    fn redirects_resolve_on_https_and_reject_credentials_or_downgrades() {
        assert_eq!(
            redirect_location(
                "https://curl.se/download/tool.tar.gz",
                "../archive/tool.tar.gz"
            )
            .unwrap(),
            "https://curl.se/download/../archive/tool.tar.gz"
        );
        assert_eq!(
            redirect_location("https://vendor.example/tool", "/release/tool.tar.gz").unwrap(),
            "https://vendor.example/release/tool.tar.gz"
        );
        assert_eq!(
            redirect_location("https://vendor.example/tool", "//cdn.example/tool.tar.gz").unwrap(),
            "https://cdn.example/tool.tar.gz"
        );
        assert_eq!(
            redirect_location("https://vendor.example/tool?old", "?signature=new").unwrap(),
            "https://vendor.example/tool?signature=new"
        );
        for location in [
            "http://cdn.example/tool",
            "https://user:secret@cdn.example/tool",
            "/tool#fragment",
            "https://cdn.example/tool\\name",
        ] {
            assert!(redirect_location("https://vendor.example/tool", location).is_err());
        }
    }
}
