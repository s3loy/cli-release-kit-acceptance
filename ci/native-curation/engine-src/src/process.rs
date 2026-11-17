use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use wait_timeout::ChildExt;

const OUTPUT_LIMIT: u64 = 16 * 1024 * 1024;
static CAPTURE_ID: AtomicU64 = AtomicU64::new(0);

pub fn environment() -> BTreeMap<String, String> {
    filtered_environment(
        std::env::vars_os()
            .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?))),
        cfg!(windows),
    )
}

fn filtered_environment(
    values: impl Iterator<Item = (String, String)>,
    windows: bool,
) -> BTreeMap<String, String> {
    const EXACT: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "USERPROFILE",
        "LOCALAPPDATA",
        "SYSTEMROOT",
        "COMSPEC",
        "PATHEXT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "TERM",
        "CI",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "RUSTUP_TOOLCHAIN",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "SDKROOT",
        "DEVELOPER_DIR",
        "MACOSX_DEPLOYMENT_TARGET",
        "CC",
        "CXX",
        "AR",
        "LD",
        "CFLAGS",
        "CXXFLAGS",
        "CPPFLAGS",
        "LDFLAGS",
        "LIBRARY_PATH",
        "CPATH",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "SOURCE_DATE_EPOCH",
        "TZ",
    ];
    const PREFIXES: &[&str] = &[
        "CARGO_TARGET_",
        "CARGO_PROFILE_",
        "PKG_CONFIG_",
        "OPENSSL_",
        "CC_",
        "CXX_",
        "AR_",
    ];
    values
        .map(|(key, value)| {
            (
                if windows {
                    key.to_ascii_uppercase()
                } else {
                    key
                },
                value,
            )
        })
        .filter(|(key, _)| {
            (EXACT.contains(&key.as_str()) || PREFIXES.iter().any(|p| key.starts_with(p)))
                && !crate::config::secret_name(key)
        })
        .collect()
}

#[derive(Serialize, Deserialize)]
struct Record {
    label: String,
    command: Vec<String>,
    exit_code: Option<i32>,
    timed_out: bool,
    elapsed_ms: u64,
    spawn_error: Option<String>,
}

pub struct Commands {
    root: PathBuf,
    logs: PathBuf,
    timeout: u64,
    records: Vec<Record>,
}

impl Commands {
    pub fn new(root: &Path, logs: &Path, timeout: u64) -> Result<Self> {
        fs::create_dir_all(logs)?;
        Ok(Self {
            root: root.into(),
            logs: logs.into(),
            timeout,
            records: if logs.join("commands.json").exists() {
                serde_json::from_slice(&read_bounded(&logs.join("commands.json"), OUTPUT_LIMIT)?)?
            } else {
                Vec::new()
            },
        })
    }

    pub fn run(
        &mut self,
        argv: &[String],
        label: &str,
        extra: &BTreeMap<String, String>,
    ) -> Result<String> {
        self.run_inner(argv, label, extra, false, true)
    }

    pub(crate) fn run_without_core(
        &mut self,
        argv: &[String],
        label: &str,
        extra: &BTreeMap<String, String>,
    ) -> Result<String> {
        self.run_inner(argv, label, extra, true, true)
    }

    /// Execute with only the supplied environment. Legacy callers retain their allowlist.
    pub fn run_exact(
        &mut self,
        argv: &[String],
        label: &str,
        environment: &BTreeMap<String, String>,
    ) -> Result<String> {
        self.run_inner(argv, label, environment, false, false)
    }

    fn run_inner(
        &mut self,
        argv: &[String],
        label: &str,
        extra: &BTreeMap<String, String>,
        disable_core: bool,
        inherit_environment: bool,
    ) -> Result<String> {
        ensure!(!argv.is_empty(), "empty command");
        ensure!(
            label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "invalid command label"
        );
        ensure!(
            !self.records.iter().any(|r| r.label == label),
            "duplicate command label: {label}"
        );
        let out_path = self.logs.join(format!("{label}.stdout"));
        let err_path = self.logs.join(format!("{label}.stderr"));
        let mut command = Command::new(&argv[0]);
        command
            .args(&argv[1..])
            .current_dir(&self.root)
            .env_clear()
            .envs(if inherit_environment {
                environment()
            } else {
                BTreeMap::new()
            })
            .envs(extra)
            .stdin(Stdio::null())
            .stdout(File::create(&out_path)?)
            .stderr(File::create(&err_path)?);
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
            if disable_core {
                unsafe {
                    command.pre_exec(|| {
                        let limit = libc::rlimit {
                            rlim_cur: 0,
                            rlim_max: 0,
                        };
                        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
            }
        }
        #[cfg(not(unix))]
        let _ = disable_core;
        eprintln!("kit: {label}");
        let started = Instant::now();
        let spawned = command.spawn();
        let mut record = Record {
            label: label.into(),
            command: argv.to_vec(),
            exit_code: None,
            timed_out: false,
            elapsed_ms: 0,
            spawn_error: None,
        };
        let result = match spawned {
            Ok(mut child) => {
                let waited = child.wait_timeout(Duration::from_secs(self.timeout));
                let status = match waited {
                    Ok(Some(status)) => Ok(status),
                    Ok(None) => {
                        record.timed_out = true;
                        terminate(&mut child);
                        child.wait()
                    }
                    Err(error) => {
                        terminate(&mut child);
                        let _ = child.wait();
                        Err(error)
                    }
                };
                match status {
                    Ok(status) => {
                        record.exit_code = status.code();
                        if status.success() && !record.timed_out {
                            Ok(())
                        } else {
                            Err(anyhow::anyhow!(
                                "command failed (exit={:?}, timeout={}): {}",
                                status.code(),
                                record.timed_out,
                                err_path.display()
                            ))
                        }
                    }
                    Err(error) => Err(error.into()),
                }
            }
            Err(error) => {
                record.spawn_error = Some(error.to_string());
                Err(anyhow::anyhow!("cannot start {}: {error}", argv[0]))
            }
        };
        record.elapsed_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        self.records.push(record);
        fs::write(
            self.logs.join("commands.json"),
            serde_json::to_vec_pretty(&self.records)?,
        )?;
        if let Err(error) = result {
            let stderr = read_bounded(&err_path, 64 * 1024).unwrap_or_default();
            bail!("{error}: {}", String::from_utf8_lossy(&stderr));
        }
        let bytes = read_bounded(&out_path, OUTPUT_LIMIT)?;
        String::from_utf8(bytes).context("command output is not UTF-8")
    }
}

fn terminate(child: &mut std::process::Child) {
    #[cfg(unix)]
    unsafe {
        // process_group(0) gives the child a group owned by this invocation.
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "command output exceeds {limit} bytes"
    );
    Ok(bytes)
}

pub fn capture(root: &Path, argv: &[String], timeout: u64) -> Result<String> {
    capture_spec(root, argv, &BTreeMap::new(), timeout)
}

/// Capture a bounded command with explicit, caller-validated environment overrides.
pub fn capture_spec(
    root: &Path,
    argv: &[String],
    env: &BTreeMap<String, String>,
    timeout: u64,
) -> Result<String> {
    let base = std::env::temp_dir();
    let path = loop {
        let id = CAPTURE_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = base.join(format!("release-kit-capture-{}-{id}", std::process::id()));
        let builder = &mut fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&candidate) {
            Ok(()) => break candidate,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    };
    let result = Commands::new(root, &path, timeout).and_then(|mut c| c.run(argv, "capture", env));
    let _ = fs::remove_dir_all(&path);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_environment_keeps_cache_location_without_credentials() {
        let values = BTreeMap::from([
            ("Path".into(), r"C:\tools".into()),
            (
                "LocalAppData".into(),
                r"C:\Users\runner\AppData\Local".into(),
            ),
            ("SystemRoot".into(), r"C:\Windows".into()),
            ("GitHub_Token".into(), "credential".into()),
            ("CARGO_TARGET_SECRET".into(), "credential".into()),
        ]);
        let windows = filtered_environment(values.clone().into_iter(), true);
        assert_eq!(windows.len(), 3);
        assert_eq!(windows["LOCALAPPDATA"], values["LocalAppData"]);
        assert_eq!(windows["SYSTEMROOT"], values["SystemRoot"]);
        assert_eq!(windows["PATH"], values["Path"]);
        let unix = filtered_environment(values.into_iter(), false);
        assert!(unix.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn controlled_runtime_disables_core_dumps_in_its_child() {
        let temp = tempfile::tempdir().unwrap();
        let mut runner = Commands::new(temp.path(), &temp.path().join("logs"), 5).unwrap();
        let output = runner
            .run_without_core(
                &["sh".into(), "-c".into(), "ulimit -c".into()],
                "core-limit",
                &BTreeMap::new(),
            )
            .unwrap();
        assert_eq!(output.trim(), "0");
    }

    #[test]
    fn failed_command_and_timeout_leave_receipts() {
        let temp = tempfile::tempdir().unwrap();
        let mut runner = Commands::new(temp.path(), &temp.path().join("logs"), 1).unwrap();
        let cargo = vec!["cargo".into(), "--definitely-not-a-cargo-option".into()];
        assert!(runner.run(&cargo, "failure", &BTreeMap::new()).is_err());
        let log = fs::read_to_string(temp.path().join("logs/commands.json")).unwrap();
        assert!(log.contains("exit_code"));
        #[cfg(unix)]
        {
            let argv = vec!["sh".into(), "-c".into(), "sleep 20 & wait".into()];
            assert!(runner.run(&argv, "timeout", &BTreeMap::new()).is_err());
            let log = fs::read_to_string(temp.path().join("logs/commands.json")).unwrap();
            assert!(log.contains("\"timed_out\": true"));
        }
    }
}
