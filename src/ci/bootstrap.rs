//! Native, fail-closed installers embedded into generated CI workflows.

pub fn bash() -> &'static str {
    include_str!("templates/install.sh")
}

pub fn powershell() -> &'static str {
    include_str!("templates/install.ps1")
}

#[cfg(all(test, unix))]
mod tests {
    use super::bash;
    use crate::{archive, source::digest};
    use std::collections::BTreeMap;
    use std::fs;
    use std::net::{TcpListener, TcpStream};
    use std::path::Path;
    use std::process::{Child, Command, Output, Stdio};
    use std::time::Duration;
    use tempfile::TempDir;

    const SOURCE_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    struct HttpsFixture {
        root: TempDir,
        server: Child,
        port: u16,
    }

    impl HttpsFixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let generated = Command::new("openssl")
                .args([
                    "req",
                    "-new",
                    "-x509",
                    "-nodes",
                    "-newkey",
                    "rsa:2048",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=DNS:localhost",
                    "-keyout",
                    "key.pem",
                    "-out",
                    "cert.pem",
                ])
                .current_dir(root.path())
                .output()
                .expect("openssl is required for the native HTTPS bootstrap test");
            assert!(
                generated.status.success(),
                "{}",
                String::from_utf8_lossy(&generated.stderr)
            );
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            let server = Command::new("openssl")
                .args(["s_server", "-quiet", "-WWW", "-accept"])
                .arg(format!("127.0.0.1:{port}"))
                .args(["-cert", "cert.pem", "-key", "key.pem"])
                .current_dir(root.path())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let fixture = Self { root, server, port };
            for _ in 0..100 {
                if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    return fixture;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            panic!("local TLS fixture did not start");
        }

        fn install(
            &self,
            artifact: &str,
            format: &str,
            member: &str,
            target: &str,
            expected: Option<&str>,
        ) -> Output {
            self.command(artifact, format, member, target, expected)
                .output()
                .unwrap()
        }

        fn command(
            &self,
            artifact: &str,
            format: &str,
            member: &str,
            target: &str,
            expected: Option<&str>,
        ) -> Command {
            let bytes = fs::read(self.root.path().join(artifact)).unwrap();
            let mut command = Command::new("bash");
            command
                .args(["-c", bash()])
                .env(
                    "RELSHIP_URL",
                    format!("https://localhost:{}/{artifact}", self.port),
                )
                .env(
                    "RELSHIP_SHA256",
                    expected
                        .map(str::to_owned)
                        .unwrap_or_else(|| digest(&bytes)),
                )
                .env("RELSHIP_FORMAT", format)
                .env("RELSHIP_MEMBER", member)
                .env("RELSHIP_VERSION", "0.1.0")
                .env("RELSHIP_SOURCE_ID", SOURCE_ID)
                .env("RELSHIP_INSTALL_DIR", self.root.path().join(target))
                .env("CURL_CA_BUNDLE", self.root.path().join("cert.pem"))
                .env_remove("RELSHIP_DOWNLOAD_TOKEN")
                .env_remove("GITHUB_ENV");
            command
        }
    }

    impl Drop for HttpsFixture {
        fn drop(&mut self) {
            let _ = self.server.kill();
            let _ = self.server.wait();
        }
    }

    fn engine() -> Vec<u8> {
        format!(
            "#!/bin/sh\n[ -z \"${{RELSHIP_DOWNLOAD_TOKEN:-}}\" ] || exit 21\n[ \"$*\" = \"build-info --json --expect-version 0.1.0 --expect-source-id {SOURCE_ID} --expect-contract 1\" ]\n"
        ).into_bytes()
    }

    fn files() -> BTreeMap<String, archive::Content> {
        BTreeMap::from([
            (
                "relship".into(),
                archive::Content {
                    bytes: engine(),
                    executable: true,
                },
            ),
            (
                "README.txt".into(),
                archive::Content {
                    bytes: b"passive documentation".to_vec(),
                    executable: false,
                },
            ),
            (
                format!("docs/{}", "a".repeat(120)),
                archive::Content {
                    bytes: b"GNU long-name compatibility".to_vec(),
                    executable: false,
                },
            ),
        ])
    }

    fn assert_installed(output: Output, target: &Path) {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(fs::read(target.join("relship")).unwrap(), engine());
        let names: Vec<_> = fs::read_dir(target)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["relship"]);
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            target.join("relship").to_str().unwrap()
        );
    }

    #[test]
    fn native_bash_installs_digest_verified_raw_and_engine_archives_over_https() {
        let fixture = HttpsFixture::new();
        fs::write(fixture.root.path().join("raw"), engine()).unwrap();
        archive::write(&fixture.root.path().join("engine.tar.gz"), &files()).unwrap();
        archive::write(&fixture.root.path().join("engine.zip"), &files()).unwrap();
        for (artifact, format, member) in [
            ("raw", "binary", ""),
            ("engine.tar.gz", "tar.gz", "relship"),
            ("engine.zip", "zip", "relship"),
        ] {
            let target = format!("installed-{artifact}");
            assert_installed(
                fixture.install(artifact, format, member, &target, None),
                &fixture.root.path().join(target),
            );
        }
    }

    #[test]
    fn native_bash_rejects_wrong_digest_identity_links_and_case_collisions() {
        let fixture = HttpsFixture::new();
        fs::write(fixture.root.path().join("raw"), engine()).unwrap();
        let wrong_hash = "0".repeat(64);
        let output = fixture.install("raw", "binary", "", "digest-failure", Some(&wrong_hash));
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("SHA-256 mismatch"));
        assert!(!fixture.root.path().join("digest-failure").exists());
        fs::write(
            fixture.root.path().join("wrong-engine"),
            b"#!/bin/sh\nexit 4\n",
        )
        .unwrap();
        let output = fixture.install("wrong-engine", "binary", "", "identity-failure", None);
        assert!(!output.status.success());
        assert!(!fixture.root.path().join("identity-failure").exists());
        let mut collision = files();
        collision.insert(
            "RELSHIP".into(),
            archive::Content {
                bytes: engine(),
                executable: true,
            },
        );
        for extension in ["zip", "tar.gz"] {
            let artifact = format!("collision.{extension}");
            archive::write(&fixture.root.path().join(&artifact), &collision).unwrap();
            let output = fixture.install(
                &artifact,
                extension,
                "relship",
                &format!("failed-{extension}"),
                None,
            );
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("case-colliding"));
            assert!(
                !fixture
                    .root
                    .path()
                    .join(format!("failed-{extension}"))
                    .exists()
            );
        }
        for (index, entry_type) in [tar::EntryType::Symlink, tar::EntryType::Link]
            .into_iter()
            .enumerate()
        {
            let artifact = format!("link-{index}.tar.gz");
            let file = fs::File::create(fixture.root.path().join(&artifact)).unwrap();
            let gzip = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            let mut tar = tar::Builder::new(gzip);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(entry_type);
            header.set_mode(0o755);
            header.set_size(0);
            header.set_link_name("elsewhere").unwrap();
            header.set_cksum();
            tar.append_data(&mut header, "relship", std::io::empty())
                .unwrap();
            tar.into_inner().unwrap().finish().unwrap();
            let output = fixture.install(
                &artifact,
                "tar.gz",
                "relship",
                &format!("link-failure-{index}"),
                None,
            );
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr).contains("non-regular tar member"));
        }
    }

    #[test]
    fn native_bash_accepts_native_tar_and_zip_producers() {
        let fixture = HttpsFixture::new();
        fs::write(fixture.root.path().join("relship"), engine()).unwrap();
        for (tool, arguments, artifact, format) in [
            (
                "tar",
                vec!["-czf", "native.tar.gz", "relship"],
                "native.tar.gz",
                "tar.gz",
            ),
            (
                "zip",
                vec!["-q", "native.zip", "relship"],
                "native.zip",
                "zip",
            ),
        ] {
            let output = Command::new(tool)
                .args(arguments)
                .current_dir(fixture.root.path())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{tool}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let target = format!("installed-{tool}");
            assert_installed(
                fixture.install(artifact, format, "relship", &target, None),
                &fixture.root.path().join(target),
            );
        }
    }

    #[test]
    fn native_bash_keeps_authentication_private_and_exports_only_verified_paths() {
        let fixture = HttpsFixture::new();
        fs::write(fixture.root.path().join("raw"), engine()).unwrap();
        let environment = fixture.root.path().join("github-env");
        let output = fixture
            .command("raw", "binary", "", "authenticated", None)
            .env("RELSHIP_DOWNLOAD_TOKEN", "private-fixture-token")
            .env("GITHUB_ENV", &environment)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
        assert_eq!(
            fs::read_to_string(environment).unwrap(),
            format!(
                "RELSHIP_BIN={}\n",
                fixture.root.path().join("authenticated/relship").display()
            )
        );
        let output = fixture
            .command("raw", "binary", "", "invalid-token", None)
            .env("RELSHIP_DOWNLOAD_TOKEN", "secret-token\nheader=injection")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-token"));
        assert!(!fixture.root.path().join("invalid-token").exists());
        let output = fixture
            .command("raw", "binary", "", "plain-http", None)
            .env(
                "RELSHIP_URL",
                format!("http://localhost:{}/raw", fixture.port),
            )
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!fixture.root.path().join("plain-http").exists());
    }
}
