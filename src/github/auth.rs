use super::{api::Client, model::Identity};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use serde_json::Value;
use std::{
    ffi::OsStr,
    io::Read,
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;

const HOST: &str = "github.com";
const TOKEN_LIMIT: usize = 8 * 1024;
const STATUS_LIMIT: usize = 1024 * 1024;
const HELPER_TIMEOUT: Duration = Duration::from_secs(20);
const AMBIENT_CREDENTIALS: &[&str] = &[
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GH_ENTERPRISE_TOKEN",
    "GITHUB_ENTERPRISE_TOKEN",
    "GH_DEBUG",
];

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Account {
    pub host: String,
    pub login: String,
    pub active: bool,
    pub state: String,
}

/// An explicit account always uses its stored credential and verifies its owner.
/// Environment credentials remain usable for Actions and GitHub Apps without /user.
pub fn client(account: Option<&str>) -> Result<Client> {
    match account {
        None => Client::from_env(),
        Some(login) => selected_client(
            login,
            &Gh::installed(),
            Client::from_token,
            Client::identity,
        ),
    }
}

pub fn accounts() -> Result<Vec<Account>> {
    accounts_with(&Gh::installed())
}

pub fn check_identity(expected: &str, actual: &Identity) -> Result<()> {
    validate_login(expected)?;
    ensure!(
        actual.id != 0 && actual.login.eq_ignore_ascii_case(expected),
        "the stored GitHub credential does not identify the requested account; sign in again with 'gh auth login --hostname github.com'"
    );
    Ok(())
}

fn validate_login(login: &str) -> Result<()> {
    // Enterprise managed users can contain underscores and exceed 39 characters.
    ensure!(
        !login.is_empty()
            && login.len() <= 100
            && login.as_bytes()[0].is_ascii_alphanumeric()
            && login
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "GitHub account must start with an ASCII letter or digit and contain at most 100 ASCII letters, digits, hyphens or underscores"
    );
    Ok(())
}

fn selected_client<C>(
    login: &str,
    gh: &Gh<'_>,
    from_token: impl FnOnce(String) -> Result<C>,
    identity: impl FnOnce(&C) -> Result<Identity>,
) -> Result<C> {
    validate_login(login)?;
    let token = token_with(gh, login)
        .with_context(|| format!("could not load stored GitHub account '{login}'"))?;
    let client = from_token(token)?;
    check_identity(login, &identity(&client)?)?;
    Ok(client)
}

// The executable and deadline are internal injection points for hermetic tests.
// Production always invokes the installed gh and uses fixed GitHub endpoints.
struct Gh<'a> {
    executable: &'a OsStr,
    timeout: Duration,
}

impl Gh<'static> {
    fn installed() -> Self {
        Self {
            executable: OsStr::new("gh"),
            timeout: HELPER_TIMEOUT,
        }
    }
}

impl Gh<'_> {
    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(self.executable);
        command.args(args);
        command
    }

    fn capture(&self, args: &[&str], limit: usize) -> Result<Vec<u8>> {
        capture(self.command(args), limit, self.timeout)
    }
}

fn token_with(gh: &Gh<'_>, login: &str) -> Result<String> {
    validate_login(login)?;
    let output = gh.capture(
        &[
            "auth",
            "token",
            "--hostname",
            HOST,
            "--user",
            login,
            "--no-refresh",
        ],
        TOKEN_LIMIT + 2,
    )?;
    let output = String::from_utf8(output)
        .map_err(|_| anyhow::anyhow!("GitHub CLI returned an invalid stored credential"))?;
    let token = output.trim_end_matches(['\r', '\n']);
    ensure!(
        !token.is_empty(),
        "GitHub CLI returned an empty stored credential"
    );
    ensure!(
        token.len() <= TOKEN_LIMIT,
        "GitHub CLI stored credential exceeds 8 KiB"
    );
    ensure!(
        token.bytes().all(|byte| (33..=126).contains(&byte)),
        "GitHub CLI returned an invalid stored credential"
    );
    Ok(token.to_owned())
}

fn accounts_with(gh: &Gh<'_>) -> Result<Vec<Account>> {
    let output = gh.capture(
        &[
            "auth",
            "status",
            "--hostname",
            HOST,
            "--json",
            "hosts",
            "--no-refresh",
        ],
        STATUS_LIMIT,
    )?;
    project_accounts(&output)
}

fn project_accounts(output: &[u8]) -> Result<Vec<Account>> {
    // Do not deserialize or return the full gh record: it can contain credentials.
    let value: Value = serde_json::from_slice(output)
        .map_err(|_| anyhow::anyhow!("GitHub CLI returned invalid account status JSON"))?;
    let hosts = value
        .get("hosts")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("GitHub CLI returned invalid account status JSON"))?;
    let Some(records) = hosts.get(HOST) else {
        return Ok(Vec::new());
    };
    let records = records
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("GitHub CLI returned invalid account status JSON"))?;
    records
        .iter()
        .map(|record| {
            let login = record
                .get("login")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("GitHub CLI returned an invalid account login"))?;
            validate_login(login)?;
            let state = match record.get("state").and_then(Value::as_str) {
                Some("success") => "success",
                Some("failure") => "failure",
                _ => "unknown",
            };
            Ok(Account {
                host: HOST.into(),
                login: login.into(),
                active: record
                    .get("active")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                state: state.into(),
            })
        })
        .collect()
}

fn capture(mut command: Command, limit: usize, timeout: Duration) -> Result<Vec<u8>> {
    // Never route credential output through the normal command logger or files.
    for name in AMBIENT_CREDENTIALS {
        command.env_remove(name);
    }
    command
        .env_remove("GH_FORCE_TTY")
        .env("GH_PROMPT_DISABLED", "1")
        .env("GH_PAGER", "")
        .env("PAGER", "")
        .env("GH_NO_UPDATE_NOTIFIER", "1")
        .env("GH_NO_EXTENSION_UPDATE_NOTIFIER", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!(
                "GitHub CLI (gh) was not found; install gh and sign in with 'gh auth login --hostname github.com'"
            )
        } else {
            anyhow::anyhow!("could not start GitHub CLI (gh); check its installation and permissions")
        }
    })?;
    let stdout = child.stdout.take().expect("piped gh stdout");
    let (sender, receiver) = mpsc::channel();
    if std::thread::Builder::new()
        .spawn(move || {
            let mut output = Vec::with_capacity(limit.min(4096));
            let result = stdout.take(limit as u64 + 1).read_to_end(&mut output);
            let _ = sender.send(result.map(|_| output));
        })
        .is_err()
    {
        stop_helper(&mut child);
        bail!("could not start GitHub CLI credential capture");
    }
    let deadline = Instant::now() + timeout;
    let mut status = None;
    let mut output = None;
    loop {
        if status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(_) => {
                    stop_helper(&mut child);
                    bail!("could not wait for GitHub CLI credential helper");
                }
            };
        }
        if let (Some(status), Some(output)) = (&status, &mut output) {
            ensure!(
                status.success(),
                "GitHub CLI credential helper failed; confirm the requested account is stored with 'gh auth status --hostname github.com', sign in with 'gh auth login --hostname github.com' if needed, and use a gh version supporting --no-refresh"
            );
            return Ok(std::mem::take(output));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            stop_helper(&mut child);
            bail!("GitHub CLI credential helper timed out");
        }
        if output.is_some() {
            status = match child.wait_timeout(remaining) {
                Ok(status) => status,
                Err(_) => {
                    stop_helper(&mut child);
                    bail!("could not wait for GitHub CLI credential helper");
                }
            };
            continue;
        }
        match receiver.recv_timeout(remaining.min(Duration::from_millis(20))) {
            Ok(Ok(bytes)) if bytes.len() <= limit => output = Some(bytes),
            Ok(Ok(_)) => {
                stop_helper(&mut child);
                bail!("GitHub CLI credential helper output exceeds its size limit");
            }
            Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                stop_helper(&mut child);
                bail!("could not read GitHub CLI credential helper output");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    }
}

fn stop_helper(child: &mut Child) {
    stop_helper_with(child, |child| {
        #[cfg(unix)]
        unsafe {
            // The running, unreaped leader still reserves this process-group ID.
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        let _ = child.kill();
    });
}

fn stop_helper_with(child: &mut Child, signal: impl FnOnce(&mut Child)) {
    // After reaping the leader its ID may be reused. Never signal that old ID,
    // even if a descendant still holds stdout open. Capture's deadline bounds
    // the wait in that case; the bounded reader can remain detached.
    if !matches!(child.try_wait(), Ok(None)) {
        return;
    }
    signal(child);
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_case_insensitive_and_requires_a_real_user_id() {
        let identity = Identity {
            id: 42,
            login: "Alice".into(),
        };
        check_identity("alice", &identity).unwrap();
        assert!(check_identity("bob", &identity).is_err());
        assert!(
            check_identity(
                "alice",
                &Identity {
                    id: 0,
                    login: "Alice".into()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn validates_managed_users_and_rejects_flags_or_path_input() {
        for login in ["a", "alice-1", "alice_enterprise", &"a".repeat(100)] {
            validate_login(login).unwrap();
        }
        for login in [
            "",
            "-alice",
            "_alice",
            "alice/bob",
            "alice bob",
            "álice",
            "alice\n",
            &"a".repeat(101),
        ] {
            assert!(validate_login(login).is_err());
        }
    }

    #[test]
    fn account_projection_discards_credentials_and_normalizes_state() {
        let accounts = project_accounts(br#"{"hosts":{"github.com":[
            {"host":"github.com","login":"alice","active":true,"state":"success","token":"secret-token","tokenSource":"secret-source","oauth_token":"secret-oauth"},
            {"login":"bob_enterprise","active":false,"state":"failure","error":"secret-error"},
            {"login":"carol","state":"secret-state"}
        ],"enterprise.example":[{"login":"excluded"}]}}"#).unwrap();
        assert_eq!(accounts.len(), 3);
        assert_eq!(
            accounts[0],
            Account {
                host: HOST.into(),
                login: "alice".into(),
                active: true,
                state: "success".into()
            }
        );
        assert_eq!(accounts[1].state, "failure");
        assert_eq!(accounts[2].state, "unknown");
        assert!(!accounts[2].active);
        let serialized = serde_json::to_string(&accounts).unwrap();
        assert!(!serialized.contains("secret"));
        assert!(!serialized.contains("excluded"));
        assert_eq!(project_accounts(br#"{"hosts":{}}"#).unwrap(), Vec::new());
    }

    #[test]
    fn malformed_status_errors_do_not_include_response_content() {
        for response in [
            b"secret-token".as_slice(),
            br#"{"hosts":[] ,"token":"secret-token"}"#,
            br#"{"hosts":{"github.com":{}} ,"token":"secret-token"}"#,
            br#"{"hosts":{"github.com":[{"login":"secret/token"}]}}"#,
        ] {
            let error = project_accounts(response).unwrap_err().to_string();
            assert!(!error.contains("secret"));
        }
    }

    #[cfg(unix)]
    mod helper {
        use super::*;
        use std::{fs, os::unix::fs::PermissionsExt, path::Path};

        fn fake(directory: &Path, script: &str) -> std::path::PathBuf {
            let path = directory.join("gh");
            fs::write(&path, format!("#!/bin/sh\nset -eu\n{script}\n")).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            path
        }

        fn gh(executable: &Path) -> Gh<'_> {
            Gh {
                executable: executable.as_os_str(),
                timeout: Duration::from_secs(2),
            }
        }

        #[test]
        fn token_command_selects_account_without_switching_and_strips_newline() {
            let directory = tempfile::tempdir().unwrap();
            let executable = fake(
                directory.path(),
                r#"
                [ "$*" = 'auth token --hostname github.com --user Alice --no-refresh' ]
                [ "$GH_PROMPT_DISABLED" = 1 ]
                printf 'test-token\r\n'
            "#,
            );
            assert_eq!(token_with(&gh(&executable), "Alice").unwrap(), "test-token");
        }

        #[test]
        fn listing_command_returns_only_safe_account_fields() {
            let directory = tempfile::tempdir().unwrap();
            let executable = fake(
                directory.path(),
                r#"
                [ "$*" = 'auth status --hostname github.com --json hosts --no-refresh' ]
                printf '%s' '{"hosts":{"github.com":[{"host":"github.com","login":"alice","active":true,"state":"success","token":"secret-token"},{"login":"bob","active":false,"state":"failure"}]}}'
            "#,
            );
            let accounts = accounts_with(&gh(&executable)).unwrap();
            assert_eq!(accounts.len(), 2);
            assert!(!serde_json::to_string(&accounts).unwrap().contains("secret"));
        }

        #[test]
        fn helper_removes_ambient_tokens_and_debug_without_mutating_global_environment() {
            let directory = tempfile::tempdir().unwrap();
            let executable = fake(
                directory.path(),
                r#"
                [ "${GH_TOKEN+x}" != x ]
                [ "${GITHUB_TOKEN+x}" != x ]
                [ "${GH_ENTERPRISE_TOKEN+x}" != x ]
                [ "${GITHUB_ENTERPRISE_TOKEN+x}" != x ]
                [ "${GH_DEBUG+x}" != x ]
                printf 'test-token\n'
            "#,
            );
            let mut command = gh(&executable).command(&[]);
            for name in AMBIENT_CREDENTIALS {
                command.env(name, "ambient-secret");
            }
            let output = capture(command, 100, Duration::from_secs(2)).unwrap();
            assert_eq!(output, b"test-token\n");
        }

        #[test]
        fn selected_account_verifies_identity_before_returning_client() {
            let directory = tempfile::tempdir().unwrap();
            let executable = fake(directory.path(), "printf 'test-token\\n'");
            let selected = selected_client("alice", &gh(&executable), Ok, |token: &String| {
                assert_eq!(token, "test-token");
                Ok(Identity {
                    id: 42,
                    login: "Alice".into(),
                })
            })
            .unwrap();
            assert_eq!(selected, "test-token");
            let error = selected_client("alice", &gh(&executable), Ok, |_: &String| {
                Ok(Identity {
                    id: 42,
                    login: "another-user".into(),
                })
            })
            .unwrap_err()
            .to_string();
            assert!(error.contains("does not identify the requested account"));
            assert!(!error.contains("test-token"));
        }

        #[test]
        fn missing_account_or_helper_failure_never_uses_another_credential() {
            let directory = tempfile::tempdir().unwrap();
            let executable = fake(
                directory.path(),
                "printf secret-token; printf secret-error >&2; exit 1",
            );
            let error = selected_client(
                "missing",
                &gh(&executable),
                |_: String| -> Result<String> {
                    panic!("a failed helper must not construct a fallback client")
                },
                |_: &String| -> Result<Identity> { panic!("must not call GitHub") },
            )
            .unwrap_err();
            let error = format!("{error:#}");
            assert!(error.contains("gh auth login"));
            assert!(!error.contains("secret"));
        }

        #[test]
        fn missing_executable_is_actionable_and_redacted() {
            let directory = tempfile::tempdir().unwrap();
            let error = token_with(&gh(&directory.path().join("secret-path")), "alice")
                .unwrap_err()
                .to_string();
            assert!(error.contains("install gh"));
            assert!(!error.contains("secret"));
        }

        #[test]
        fn empty_invalid_and_oversized_tokens_are_rejected_without_echoing_them() {
            for script in [
                "printf '\\n'",
                "printf 'secret token\\n'",
                "printf '%09000d' 0",
                "printf '\\377'",
            ] {
                let directory = tempfile::tempdir().unwrap();
                let executable = fake(directory.path(), script);
                let error = token_with(&gh(&executable), "alice")
                    .unwrap_err()
                    .to_string();
                assert!(!error.contains("secret"));
            }
        }

        #[test]
        fn maximum_token_length_allows_the_helpers_line_ending() {
            let directory = tempfile::tempdir().unwrap();
            let executable = fake(directory.path(), "printf '%08192d\\r\\n' 0");
            assert_eq!(
                token_with(&gh(&executable), "alice").unwrap().len(),
                TOKEN_LIMIT
            );
            let executable = fake(directory.path(), "printf '%08193d\\n' 0");
            assert!(token_with(&gh(&executable), "alice").is_err());
        }

        #[test]
        fn status_output_is_bounded() {
            let directory = tempfile::tempdir().unwrap();
            let executable = fake(directory.path(), "printf '%01048577d' 0");
            let error = accounts_with(&gh(&executable)).unwrap_err().to_string();
            assert!(error.contains("size limit"));
        }

        #[test]
        fn timeout_bounds_wait_without_exposing_output() {
            let directory = tempfile::tempdir().unwrap();
            let executable = fake(directory.path(), "printf secret-token; sleep 10 & wait");
            let helper = Gh {
                executable: executable.as_os_str(),
                timeout: Duration::from_millis(80),
            };
            let started = Instant::now();
            let error = token_with(&helper, "alice").unwrap_err().to_string();
            assert!(error.contains("timed out"));
            assert!(!error.contains("secret"));
            assert!(started.elapsed() < Duration::from_secs(2));
        }

        #[test]
        fn exited_helper_cannot_leave_capture_waiting_on_a_descendant() {
            let directory = tempfile::tempdir().unwrap();
            let executable = fake(directory.path(), "sleep 1 & exit 0");
            let helper = Gh {
                executable: executable.as_os_str(),
                timeout: Duration::from_millis(80),
            };
            let started = Instant::now();
            assert!(
                token_with(&helper, "alice")
                    .unwrap_err()
                    .to_string()
                    .contains("timed out")
            );
            assert!(started.elapsed() < Duration::from_secs(2));
        }

        #[test]
        fn reaped_helper_is_never_signaled_again() {
            let mut child = Command::new("/bin/sh")
                .args(["-c", "exit 0"])
                .spawn()
                .unwrap();
            child.wait().unwrap();
            let mut signaled = false;
            stop_helper_with(&mut child, |_| signaled = true);
            assert!(
                !signaled,
                "a reaped helper no longer reserves its process ID"
            );
        }
    }
}
