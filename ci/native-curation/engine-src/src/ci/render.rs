//! Deterministic, statically assigned consumer workflows.
use super::{
    bootstrap, config,
    model::{Config, Runner},
};
use crate::{cohort::io, source};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
};

const CHECKOUT: &str = "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd";
const UPLOAD: &str = "actions/upload-artifact@bbbca2ddaa5d8feaa63e36b76fdaad77386f024f";
const DOWNLOAD: &str = "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131";
const SETUP_GO: &str = "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16";
const MANIFEST: &str = "relship/generated.json";
const MANAGED: [&str; 4] = [
    "workflows/relship-check.yml",
    "workflows/relship-release.yml",
    "relship/install.sh",
    "relship/install.ps1",
];
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Generated {
    schema: u32,
    config_id: String,
    files: BTreeMap<String, String>,
}
pub(super) fn q(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization")
}
fn hosted(runner: &Runner) -> bool {
    // GitHub-hosted runner labels are intentionally an allowlist. Unknown and
    // custom labels cannot place pull-request code on a persistent runner.
    runner.runs_on.len() == 1
        && matches!(
            runner.runs_on[0].as_str(),
            "ubuntu-22.04"
                | "ubuntu-24.04"
                | "ubuntu-22.04-arm"
                | "ubuntu-24.04-arm"
                | "windows-2022"
                | "windows-2025"
                | "windows-11-arm"
                | "macos-14"
                | "macos-15"
                | "macos-15-intel"
                | "macos-26"
                | "macos-26-intel"
        )
}
pub(super) enum Argument<'a> {
    Literal(&'a str),
    Environment(&'a str),
}
use Argument::{Environment, Literal};

struct JobPermissions {
    contents: &'static str,
    actions: &'static str,
}

pub(super) struct Script<'a> {
    pub(super) runner: &'a Runner,
}
impl Script<'_> {
    pub(super) fn windows(&self) -> bool {
        self.runner.host.starts_with("windows-")
    }
    pub(super) fn shell(&self) -> &str {
        if self.windows() { "pwsh" } else { "bash" }
    }
    pub(super) fn command(&self, args: &[Argument<'_>]) -> String {
        let args = args
            .iter()
            .map(|argument| match argument {
                Argument::Environment(name) if self.windows() => format!("\"$env:{name}\""),
                Argument::Environment(name) => format!("\"${name}\""),
                Argument::Literal(value)
                    if !value.is_empty()
                        && value.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || b"_./:=+-".contains(&byte)
                        }) =>
                {
                    (*value).to_string()
                }
                Argument::Literal(value) if self.windows() => {
                    format!("'{}'", value.replace('\'', "''"))
                }
                Argument::Literal(value) => format!("'{}'", value.replace('\'', "'\\''")),
            })
            .collect::<Vec<_>>()
            .join(" ");
        if self.windows() {
            format!(
                "& $env:RELSHIP_BIN {args}\nif ($LASTEXITCODE -ne 0) {{ throw 'relship command failed' }}"
            )
        } else {
            format!("\"$RELSHIP_BIN\" {args}")
        }
    }
    pub(super) fn mkdir(&self, path: &str) -> String {
        if self.windows() {
            format!("New-Item -ItemType Directory -Force -Path '{path}' | Out-Null")
        } else {
            format!("mkdir -p '{path}'")
        }
    }
    pub(super) fn step(&self, text: &mut String, name: &str, script: &str) {
        text.push_str(&format!(
            "      - name: {}\n        shell: {}\n        run: |\n",
            q(name),
            self.shell()
        ));
        if !self.windows() {
            text.push_str("          set -euo pipefail\n");
        }
        for line in script.lines() {
            text.push_str("          ");
            text.push_str(line);
            text.push('\n');
        }
    }
}
pub(super) fn env(text: &mut String, key: &str, value: &str, indent: usize) {
    text.push_str(&format!("{}{}: {}\n", " ".repeat(indent), key, q(value)));
}
#[allow(clippy::too_many_arguments)]
fn job(
    text: &mut String,
    id: &str,
    name: &str,
    runner: &Runner,
    needs: &[String],
    condition: Option<&str>,
    environment: Option<&str>,
    permissions: Option<JobPermissions>,
) {
    text.push_str(&format!("  {id}:\n"));
    if let Some(permissions) = permissions {
        text.push_str(&format!(
            "    permissions:\n      contents: {}\n      actions: {}\n",
            permissions.contents, permissions.actions
        ));
    }
    text.push_str(&format!("    name: {}\n", q(name)));
    if !needs.is_empty() {
        text.push_str(&format!(
            "    needs: {}\n",
            serde_json::to_string(needs).unwrap()
        ));
    }
    if let Some(condition) = condition {
        text.push_str(&format!("    if: {condition}\n"));
    }
    text.push_str(&format!(
        "    runs-on: {}\n    timeout-minutes: 90\n",
        serde_json::to_string(&runner.runs_on).unwrap()
    ));
    if let Some(environment) = environment {
        text.push_str(&format!("    environment: {}\n", q(environment)));
    }
    text.push_str("    env:\n");
    if let Some(version) = &runner.rust_version {
        env(text, "RELSHIP_RUST_VERSION", version, 6);
        env(
            text,
            "RELSHIP_RUST_HOST",
            &config::rust_host(runner).expect("validated rust host"),
            6,
        );
        env(
            text,
            "RUSTUP_TOOLCHAIN",
            &format!("{version}-{}", config::rust_host(runner).unwrap()),
            6,
        );
    }
    env(text, "RELSHIP_EXPECTED_SOURCE", "${{ github.sha }}", 6);
    text.push_str("    steps:\n");
}
pub(super) fn checkout_install(
    text: &mut String,
    cfg: &Config,
    runner: &Runner,
    tools: bool,
    check_generated: bool,
    pull_request: bool,
) {
    let script = Script { runner };
    text.push_str(&format!("      - uses: {CHECKOUT}\n        with:\n          ref: ${{{{ github.sha }}}}\n          fetch-depth: 0\n          persist-credentials: false\n"));
    let copy = if script.windows() {
        "if ((git rev-parse HEAD) -ne $env:RELSHIP_EXPECTED_SOURCE) { throw 'checkout SHA differs' }\n$env:RELSHIP_CONFIG = Join-Path $env:RUNNER_TEMP 'relship-reviewed-ci.toml'\nCopy-Item -LiteralPath release-ci.toml -Destination $env:RELSHIP_CONFIG\n\"RELSHIP_CONFIG=$env:RELSHIP_CONFIG\" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8\nNew-Item -ItemType Directory -Force -Path target/relship | Out-Null"
    } else {
        "test \"$(git rev-parse HEAD)\" = \"$RELSHIP_EXPECTED_SOURCE\"\nRELSHIP_CONFIG=\"$RUNNER_TEMP/relship-reviewed-ci.toml\"\ncp release-ci.toml \"$RELSHIP_CONFIG\"\nprintf 'RELSHIP_CONFIG=%s\\n' \"$RELSHIP_CONFIG\" >> \"$GITHUB_ENV\"\nmkdir -p target/relship"
    };
    script.step(
        text,
        "Freeze reviewed configuration from exact source SHA",
        copy,
    );
    let install = &cfg.installs[&runner.host];
    text.push_str(&format!(
        "      - name: Install SHA-256 pinned relship engine\n        shell: {}\n        env:\n",
        script.shell()
    ));
    for (key, value) in [
        ("RELSHIP_URL", install.url.as_str()),
        ("RELSHIP_SHA256", install.sha256.as_str()),
        ("RELSHIP_FORMAT", install.format.as_str()),
        ("RELSHIP_MEMBER", install.member.as_deref().unwrap_or("")),
        ("RELSHIP_VERSION", cfg.engine.version.as_str()),
        ("RELSHIP_SOURCE_ID", cfg.engine.source_id.as_str()),
        (
            "RELSHIP_INSTALL_DIR",
            "${{ runner.temp }}/relship-engine-${{ github.job }}-${{ github.run_attempt }}",
        ),
    ] {
        env(text, key, value, 10);
    }
    if let Some(secret) = install.auth_secret.as_ref().filter(|_| !pull_request) {
        env(
            text,
            "RELSHIP_DOWNLOAD_TOKEN",
            &format!("${{{{ secrets.{secret} }}}}"),
            10,
        );
    }
    text.push_str("        run: |\n");
    text.push_str(if script.windows() {
        "          & ./.github/relship/install.ps1\n"
    } else {
        "          bash .github/relship/install.sh\n"
    });
    if check_generated {
        script.step(
            text,
            "Check reviewed workflow generation",
            &script.command(&[
                Literal("ci"),
                Literal("check"),
                Literal("--config"),
                Environment("RELSHIP_CONFIG"),
            ]),
        );
    }
    if tools {
        if runner.rust_version.is_some() {
            let command = if script.windows() {
                "rustup toolchain install \"$env:RELSHIP_RUST_VERSION-$env:RELSHIP_RUST_HOST\" --profile minimal\nif ($LASTEXITCODE -ne 0) { throw 'exact Rust toolchain install failed' }"
            } else {
                "rustup toolchain install \"$RELSHIP_RUST_VERSION-$RELSHIP_RUST_HOST\" --profile minimal"
            };
            script.step(text, "Install exact native Rust toolchain", command);
        }
        if let Some(version) = &runner.go_version {
            text.push_str(&format!("      - uses: {SETUP_GO}\n        with:\n          go-version: {}\n          cache: false\n          check-latest: false\n",q(version)));
        }
    }
}
pub(super) fn upload(text: &mut String, name: &str, path: &str, condition: Option<&str>) {
    text.push_str(&format!("      - uses: {UPLOAD}\n"));
    if let Some(condition) = condition {
        text.push_str(&format!("        if: {condition}\n"));
    }
    text.push_str(&format!("        with:\n          name: {}\n          path: {}\n          if-no-files-found: error\n          retention-days: 7\n",q(name),q(path)));
}
pub(super) fn download(text: &mut String, name: &str, path: &str) {
    text.push_str(&format!(
        "      - uses: {DOWNLOAD}\n        with:\n          name: {}\n          path: {}\n",
        q(name),
        q(path)
    ));
}
fn artifact(kind: &str, profile: Option<&str>) -> String {
    let profile = profile.map(|value| format!("-{value}")).unwrap_or_default();
    format!("relship-{kind}{profile}-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}")
}
fn coordinator(text: &mut String, cfg: &Config, release: bool) {
    let runner = &cfg.coordinator;
    job(
        text,
        "plan",
        "Review exact SHA, profiles and canonical plan",
        runner,
        &["guard".into()],
        release.then_some("inputs.mode == 'fresh'"),
        (release && !hosted(runner)).then_some(cfg.trusted.environment.as_str()),
        None,
    );
    checkout_install(text, cfg, runner, true, true, !release);
    let script = Script { runner };
    let protocol = cfg.execution_protocol.to_string();
    let commands = [
        script.mkdir("target/relship/input"),
        script.command(&[
            Literal("plan"),
            Literal("--protocol"),
            Literal(&protocol),
            Literal("--output"),
            Literal("target/relship/input/plan.json"),
        ]),
        script.command(&[
            Literal("ci"),
            Literal("schedule"),
            Literal("--config"),
            Environment("RELSHIP_CONFIG"),
            Literal("--plan"),
            Literal("target/relship/input/plan.json"),
            Literal("--expected-source"),
            Environment("RELSHIP_EXPECTED_SOURCE"),
            Literal("--output"),
            Literal("target/relship/input/schedule.json"),
        ]),
    ]
    .join("\n");
    script.step(
        text,
        "Create source-bound plan and complete schedule",
        &commands,
    );
    let summary = if script.windows() {
        "\"Approved source SHA: $env:RELSHIP_EXPECTED_SOURCE\" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8\nGet-Content target/relship/input/plan.json, target/relship/input/schedule.json | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8"
    } else {
        "printf 'Approved source SHA: `%s`\\n\\n```json\\n' \"$RELSHIP_EXPECTED_SOURCE\" >> \"$GITHUB_STEP_SUMMARY\"\ncat target/relship/input/plan.json target/relship/input/schedule.json >> \"$GITHUB_STEP_SUMMARY\"\nprintf '\\n```\\n' >> \"$GITHUB_STEP_SUMMARY\""
    };
    script.step(
        text,
        "Show SHA, exact unit plan and static profiles before approval",
        summary,
    );
    upload(
        text,
        &artifact("input", None),
        "target/relship/input/",
        None,
    );
}
fn worker(
    text: &mut String,
    cfg: &Config,
    profile: &str,
    runner: &Runner,
    rebuild: bool,
    release: bool,
) {
    let id = format!(
        "{}_{}",
        if rebuild { "rebuild" } else { "worker" },
        profile.replace('-', "_")
    );
    let needs = if rebuild {
        vec![
            format!("worker_{}", profile.replace('-', "_")),
            "plan".into(),
        ]
    } else {
        vec!["plan".into(), "guard".into()]
    };
    job(
        text,
        &id,
        &format!(
            "{} {profile} at ${{{{ github.sha }}}}",
            if rebuild {
                "Approve fresh rebuild"
            } else {
                "Candidate"
            }
        ),
        runner,
        &needs,
        None,
        (rebuild || !hosted(runner)).then_some(cfg.trusted.environment.as_str()),
        None,
    );
    checkout_install(text, cfg, runner, true, false, !release);
    text.push_str("      - name: Bind static profile\n        shell: ");
    // The profile is written as data by the job, never evaluated as shell code.
    let script = Script { runner };
    text.push_str(script.shell());
    text.push_str("\n        env:\n");
    env(text, "RELSHIP_STATIC_PROFILE", profile, 10);
    text.push_str("        run: |\n");
    text.push_str(if script.windows() { "          \"RELSHIP_PROFILE=$env:RELSHIP_STATIC_PROFILE\" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8\n" } else { "          printf 'RELSHIP_PROFILE=%s\\n' \"$RELSHIP_STATIC_PROFILE\" >> \"$GITHUB_ENV\"\n" });
    download(text, &artifact("input", None), "target/relship/input/");
    let mut args = vec![
        Literal("ci"),
        Literal("run-job"),
        Literal("--config"),
        Environment("RELSHIP_CONFIG"),
        Literal("--plan"),
        Literal("target/relship/input/plan.json"),
        Literal("--schedule"),
        Literal("target/relship/input/schedule.json"),
        Literal("--expected-source"),
        Environment("RELSHIP_EXPECTED_SOURCE"),
        Literal("--profile"),
        Environment("RELSHIP_PROFILE"),
    ];
    if rebuild {
        download(
            text,
            &artifact("candidate", Some(profile)),
            "target/relship/candidate-bundle/",
        );
        script.step(
            text,
            "Import complete candidate before opening signing material",
            &script.command(&[
                Literal("import"),
                Literal("--plan"),
                Literal("target/relship/input/plan.json"),
                Literal("--bundle"),
                Literal("target/relship/candidate-bundle"),
                Literal("--output"),
                Literal("target/relship/candidate"),
            ]),
        );
        text.push_str(&format!("      - name: Rebuild approved source and sign exact profile units\n        shell: {}\n        env:\n",script.shell()));
        env(
            text,
            "RELSHIP_SIGNING_KEY",
            &format!("${{{{ secrets.{} }}}}", cfg.trusted.signing_secret),
            10,
        );
        text.push_str("        run: |\n");
        args.extend([
            Literal("--role"),
            Literal("rebuild"),
            Literal("--candidate"),
            Literal("target/relship/candidate"),
            Literal("--key"),
            Environment("RELSHIP_KEY_FILE"),
            Literal("--output"),
            Literal("target/relship/job"),
        ]);
        let command = script.command(&args);
        let body = if script.windows() {
            format!(
                "$ErrorActionPreference = 'Stop'\n$env:RELSHIP_KEY_FILE = Join-Path $env:RUNNER_TEMP ('relship-signing-' + [guid]::NewGuid().ToString() + '.json')\ntry {{\n  [IO.File]::WriteAllText($env:RELSHIP_KEY_FILE, $env:RELSHIP_SIGNING_KEY, [Text.UTF8Encoding]::new($false))\n  Remove-Item Env:RELSHIP_SIGNING_KEY\n{command}\n}} finally {{\n  Remove-Item Env:RELSHIP_SIGNING_KEY -ErrorAction SilentlyContinue\n  Remove-Item -LiteralPath $env:RELSHIP_KEY_FILE -Force -ErrorAction SilentlyContinue\n}}"
            )
        } else {
            format!(
                "set -euo pipefail\numask 077\nRELSHIP_KEY_FILE=$(mktemp \"$RUNNER_TEMP/relship-signing.XXXXXXXX\")\ntrap 'rm -f -- \"$RELSHIP_KEY_FILE\"; unset RELSHIP_SIGNING_KEY' EXIT\nprintf '%s' \"$RELSHIP_SIGNING_KEY\" > \"$RELSHIP_KEY_FILE\"\nunset RELSHIP_SIGNING_KEY\n{command}"
            )
        };
        for line in body.lines() {
            text.push_str("          ");
            text.push_str(line);
            text.push('\n');
        }
    } else {
        args.extend([
            Literal("--role"),
            Literal("worker"),
            Literal("--output"),
            Literal("target/relship/job"),
        ]);
        script.step(
            text,
            "Build candidate without signing or delivery credentials",
            &script.command(&args),
        );
    }
    upload(
        text,
        &artifact(if rebuild { "trusted" } else { "candidate" }, Some(profile)),
        "target/relship/job/result/",
        None,
    );
}
fn check_workflow(cfg: &Config) -> String {
    let mut text = String::from(
        "# Generated by relship; review and commit together with release-ci.toml.\nname: Relship candidate checks\non:\n  pull_request:\npermissions:\n  contents: read\nconcurrency:\n  group: relship-check-${{ github.repository }}-${{ github.ref }}\n  cancel-in-progress: true\njobs:\n",
    );
    text.push_str("  guard:\n    name: Require isolated GitHub-hosted pull-request runners\n    runs-on: ubuntu-24.04\n    steps:\n      - name: Validate static runner isolation before checkout\n        shell: bash\n        run: |\n");
    let private_install = std::iter::once(&cfg.coordinator)
        .chain(cfg.workers.values().map(|worker| &worker.runner))
        .any(|runner| cfg.installs[&runner.host].auth_secret.is_some());
    if !hosted(&cfg.coordinator) || cfg.workers.values().any(|worker| !hosted(&worker.runner)) {
        text.push_str("          echo 'Candidate checks cannot run pull-request code on self-hosted or unknown runner labels. Review the configured profiles.' >&2\n          exit 1\n");
    } else if private_install {
        text.push_str("          echo 'Pull-request checks require an engine install source without authentication. Download secrets are never exposed to pull-request code.' >&2\n          exit 1\n");
    } else {
        text.push_str("          echo 'Every static profile uses an explicitly allowed isolated GitHub-hosted runner and an unauthenticated engine source.'\n");
        coordinator(&mut text, cfg, false);
        for (profile, worker_cfg) in &cfg.workers {
            worker(&mut text, cfg, profile, &worker_cfg.runner, false, false);
        }
    }
    text
}
fn release_workflow(cfg: &Config) -> String {
    let mut text = String::from(
        "# Generated by relship; environment approval authorizes only the displayed exact workflow SHA.\nname: Relship reviewed draft release\nrun-name: Relship ${{ inputs.tag }} at ${{ github.sha }} (${{ inputs.mode }})\non:\n  workflow_dispatch:\n    inputs:\n      tag:\n        description: Exact release tag\n        type: string\n        required: true\n      mode:\n        description: Fresh draft or explicit saved-state restore\n        type: choice\n        options: [fresh, restore]\n        default: fresh\n      restore_run_id:\n        description: Exact original run ID; no latest-artifact lookup\n        type: string\n      restore_run_attempt:\n        description: Exact original run attempt\n        type: string\n      old_writer_stopped:\n        description: I confirmed that the original publisher process has stopped\n        type: boolean\n        default: false\npermissions:\n  contents: read\nconcurrency:\n  group: relship-delivery-${{ github.repository }}-${{ inputs.tag }}\n  cancel-in-progress: false\njobs:\n  guard:\n    runs-on: ubuntu-24.04\n    steps:\n      - name: Require trusted branch and exact workflow revision\n        shell: bash\n        env:\n",
    );
    env(
        &mut text,
        "RELSHIP_BRANCH",
        &format!("refs/heads/{}", cfg.trusted.branch),
        10,
    );
    for (key, value) in [
        ("RELSHIP_REF", "${{ github.ref }}"),
        ("RELSHIP_SHA", "${{ github.sha }}"),
        ("RELSHIP_WORKFLOW_SHA", "${{ github.workflow_sha }}"),
        ("RELSHIP_MODE", "${{ inputs.mode }}"),
        ("RELSHIP_OLD_RUN", "${{ inputs.restore_run_id }}"),
        ("RELSHIP_OLD_ATTEMPT", "${{ inputs.restore_run_attempt }}"),
        ("RELSHIP_STOPPED", "${{ inputs.old_writer_stopped }}"),
    ] {
        env(&mut text, key, value, 10);
    }
    let profiles = cfg
        .workers
        .iter()
        .map(|(name, worker)| (name, &worker.targets, &worker.runner.runs_on))
        .collect::<Vec<_>>();
    env(
        &mut text,
        "RELSHIP_STATIC_PROFILES",
        &serde_json::to_string(&profiles).unwrap(),
        10,
    );
    text.push_str("        run: |\n          set -euo pipefail\n          test \"$RELSHIP_REF\" = \"$RELSHIP_BRANCH\" || { echo 'Dispatch must use the trusted branch' >&2; exit 1; }\n          test \"$RELSHIP_SHA\" = \"$RELSHIP_WORKFLOW_SHA\" || { echo 'Workflow revision must equal the exact approved source SHA' >&2; exit 1; }\n          if [[ $RELSHIP_MODE == restore ]]; then\n            [[ $RELSHIP_OLD_RUN =~ ^[1-9][0-9]{0,19}$ && $RELSHIP_OLD_ATTEMPT =~ ^[1-9][0-9]{0,19}$ && $RELSHIP_STOPPED == true ]] || { echo 'Restore requires exact origin and original-writer-stopped confirmation' >&2; exit 1; }\n          fi\n          printf 'Exact workflow/source SHA: `%s`\\nMode: `%s`\\nRestore origin: `%s` attempt `%s`\\n' \"$RELSHIP_SHA\" \"$RELSHIP_MODE\" \"$RELSHIP_OLD_RUN\" \"$RELSHIP_OLD_ATTEMPT\" >> \"$GITHUB_STEP_SUMMARY\"\n          printf '\\nStatic profile IDs, targets and runner labels:\\n```json\\n%s\\n```\\n' \"$RELSHIP_STATIC_PROFILES\" >> \"$GITHUB_STEP_SUMMARY\"\n");
    coordinator(&mut text, cfg, true);
    for (profile, worker_cfg) in &cfg.workers {
        worker(&mut text, cfg, profile, &worker_cfg.runner, false, true);
        worker(&mut text, cfg, profile, &worker_cfg.runner, true, true);
    }
    let needs = cfg
        .workers
        .keys()
        .map(|profile| format!("rebuild_{}", profile.replace('-', "_")))
        .chain(["plan".into()])
        .collect::<Vec<_>>();
    job(
        &mut text,
        "merge",
        "Verify policy and merge complete trusted results",
        &cfg.coordinator,
        &needs,
        None,
        (!hosted(&cfg.coordinator)).then_some(cfg.trusted.environment.as_str()),
        None,
    );
    checkout_install(&mut text, cfg, &cfg.coordinator, false, false, false);
    download(&mut text, &artifact("input", None), "target/relship/input/");
    for profile in cfg.workers.keys() {
        download(
            &mut text,
            &artifact("trusted", Some(profile)),
            &format!("target/relship/results/{profile}/"),
        );
    }
    let script = Script {
        runner: &cfg.coordinator,
    };
    let result_paths = cfg
        .workers
        .keys()
        .map(|profile| format!("target/relship/results/{profile}"))
        .collect::<Vec<_>>();
    let mut merge = vec![
        Literal("merge"),
        Literal("--plan"),
        Literal("target/relship/input/plan.json"),
        Literal("--policy"),
        Environment("RELSHIP_POLICY"),
        Literal("--output"),
        Literal("target/relship/collection"),
    ];
    for path in &result_paths {
        merge.extend([Literal("--result"), Literal(path)]);
    }
    text.push_str(&format!("      - name: Verify complete collection under configured trust policy\n        shell: {}\n        env:\n",script.shell()));
    env(&mut text, "RELSHIP_POLICY", &cfg.delivery.policy, 10);
    text.push_str("        run: |\n");
    let command = script.command(&merge);
    for line in command.lines() {
        text.push_str("          ");
        text.push_str(line);
        text.push('\n');
    }
    upload(
        &mut text,
        &artifact("collection", None),
        "target/relship/collection/",
        None,
    );
    delivery(&mut text, cfg, false);
    delivery(&mut text, cfg, true);
    text
}
fn delivery(text: &mut String, cfg: &Config, restore: bool) {
    let runner = &cfg.coordinator;
    job(
        text,
        if restore {
            "restore_delivery"
        } else {
            "delivery"
        },
        &format!(
            "Approve {} draft at ${{{{ github.sha }}}}",
            if restore { "restored" } else { "new" }
        ),
        runner,
        &if restore {
            vec!["guard".into()]
        } else {
            vec!["merge".into()]
        },
        Some(if restore {
            "inputs.mode == 'restore'"
        } else {
            "inputs.mode == 'fresh'"
        }),
        Some(&cfg.delivery.environment),
        // Restore fetches historical artifacts with the workflow token, even
        // when the publisher uses a separate delivery token.
        (cfg.delivery.token_secret.is_none() || restore).then_some(JobPermissions {
            contents: if cfg.delivery.token_secret.is_none() {
                "write"
            } else {
                "read"
            },
            actions: "read",
        }),
    );
    // Delivery has no compilers and never executes product hooks.
    checkout_install(text, cfg, runner, false, true, false);
    let script = Script { runner };
    if restore {
        text.push_str(&format!("      - uses: {DOWNLOAD}\n        with:\n          name: relship-state-${{{{ inputs.restore_run_id }}}}-${{{{ inputs.restore_run_attempt }}}}\n          run-id: ${{{{ inputs.restore_run_id }}}}\n          github-token: ${{{{ github.token }}}}\n          path: target/relship/saved/\n"));
        text.push_str(&format!("      - name: Restore only the explicitly selected original state\n        shell: {}\n        env:\n",script.shell()));
        env(text, "RELSHIP_OLD_RUN", "${{ inputs.restore_run_id }}", 10);
        env(
            text,
            "RELSHIP_OLD_ATTEMPT",
            "${{ inputs.restore_run_attempt }}",
            10,
        );
        env(text, "RELSHIP_TAG", "${{ inputs.tag }}", 10);
        text.push_str("        run: |\n");
        let command = script.command(&[
            Literal("ci"),
            Literal("restore-state"),
            Literal("--config"),
            Environment("RELSHIP_CONFIG"),
            Literal("--archive"),
            Literal("target/relship/saved/state.tar"),
            Literal("--run-id"),
            Environment("RELSHIP_OLD_RUN"),
            Literal("--run-attempt"),
            Environment("RELSHIP_OLD_ATTEMPT"),
            Literal("--old-writer-stopped"),
            Literal("--expected-source"),
            Environment("RELSHIP_EXPECTED_SOURCE"),
            Literal("--expected-tag"),
            Environment("RELSHIP_TAG"),
            Literal("--output"),
            Literal("target/relship/restored"),
        ]);
        for line in command.lines() {
            text.push_str("          ");
            text.push_str(line);
            text.push('\n');
        }
    } else {
        download(
            text,
            &artifact("collection", None),
            "target/relship/collection/",
        );
    }
    let (collection, attempt) = if restore {
        (
            "target/relship/restored/collection",
            "target/relship/restored/attempt",
        )
    } else {
        ("target/relship/collection", "target/relship/delivery")
    };
    text.push_str(&format!(
        "      - name: {}\n        shell: {}\n        env:\n",
        if restore {
            "Reconcile original draft and verify remote assets"
        } else {
            "Plan, stage and verify draft without final publication"
        },
        script.shell()
    ));
    env(text, "RELSHIP_POLICY", &cfg.delivery.policy, 10);
    env(text, "RELSHIP_REPOSITORY", &cfg.delivery.repository, 10);
    env(text, "RELSHIP_TAG", "${{ inputs.tag }}", 10);
    env(
        text,
        "GITHUB_TOKEN",
        &cfg.delivery
            .token_secret
            .as_ref()
            .map(|name| format!("${{{{ secrets.{name} }}}}"))
            .unwrap_or("${{ github.token }}".into()),
        10,
    );
    text.push_str("        run: |\n");
    let mut commands = Vec::new();
    if restore {
        commands.push(script.command(&[
            Literal("github"),
            Literal("resume"),
            Literal("--collection"),
            Literal(collection),
            Literal("--policy"),
            Environment("RELSHIP_POLICY"),
            Literal("--output"),
            Literal(attempt),
        ]));
    } else {
        let mut args = vec![
            Literal("github"),
            Literal("plan"),
            Literal("--collection"),
            Literal(collection),
            Literal("--policy"),
            Environment("RELSHIP_POLICY"),
            Literal("--repo"),
            Environment("RELSHIP_REPOSITORY"),
            Literal("--tag"),
            Environment("RELSHIP_TAG"),
        ];
        if cfg.delivery.create_tag_if_missing {
            args.push(Literal("--create-tag-if-missing"));
        }
        args.extend([
            Literal("--output"),
            Literal("target/relship/draft-plan.json"),
        ]);
        commands.push(script.command(&args));
        commands.push(script.command(&[
            Literal("github"),
            Literal("stage"),
            Literal("--plan"),
            Literal("target/relship/draft-plan.json"),
            Literal("--collection"),
            Literal(collection),
            Literal("--policy"),
            Environment("RELSHIP_POLICY"),
            Literal("--output"),
            Literal(attempt),
        ]));
    }
    commands.push(script.command(&[
        Literal("github"),
        Literal("verify"),
        Literal("--collection"),
        Literal(collection),
        Literal("--policy"),
        Environment("RELSHIP_POLICY"),
        Literal("--output"),
        Literal(attempt),
    ]));
    let mut body = commands.join("\n");
    if !script.windows() {
        body = format!("set -euo pipefail\n{body}");
    }
    for line in body.lines() {
        text.push_str("          ");
        text.push_str(line);
        text.push('\n');
    }
    text.push_str(&format!("      - name: Save original collection and stopped publisher state\n        if: always()\n        shell: {}\n        env:\n",script.shell()));
    env(text, "RELSHIP_RUN_ID", "${{ github.run_id }}", 10);
    env(text, "RELSHIP_RUN_ATTEMPT", "${{ github.run_attempt }}", 10);
    text.push_str("        run: |\n");
    let pack = script.command(&[
        Literal("ci"),
        Literal("pack-state"),
        Literal("--config"),
        Environment("RELSHIP_CONFIG"),
        Literal("--collection"),
        Literal(collection),
        Literal("--attempt"),
        Literal(attempt),
        Literal("--run-id"),
        Environment("RELSHIP_RUN_ID"),
        Literal("--run-attempt"),
        Environment("RELSHIP_RUN_ATTEMPT"),
        Literal("--output"),
        Literal("target/relship/state.tar"),
    ]);
    let body = if script.windows() {
        format!(
            "if (!(Test-Path '{attempt}/receipt.json')) {{ throw 'No saved publisher state; automatic takeover is unavailable' }}\n{pack}"
        )
    } else {
        format!(
            "set -euo pipefail\ntest -f '{attempt}/receipt.json' || {{ echo 'No saved publisher state; automatic takeover is unavailable' >&2; exit 1; }}\n{pack}"
        )
    };
    for line in body.lines() {
        text.push_str("          ");
        text.push_str(line);
        text.push('\n');
    }
    upload(
        text,
        &artifact("state", None),
        "target/relship/state.tar",
        Some("always()"),
    );
}

pub fn files(cfg: &Config) -> Result<BTreeMap<String, Vec<u8>>> {
    config::validate(cfg)?;
    // Hyphens and underscores must not collapse into the same static job ID.
    let mut ids = std::collections::BTreeSet::new();
    ensure!(
        cfg.workers
            .keys()
            .all(|id| ids.insert(id.replace('-', "_").to_ascii_lowercase())),
        "worker profile names collide after GitHub job ID normalization"
    );
    let (checks, release) = if cfg.execution_protocol == 6 {
        super::qualified::workflows(cfg)?
    } else {
        (check_workflow(cfg), release_workflow(cfg))
    };
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::from([
        (MANAGED[0].into(), checks.into_bytes()),
        (MANAGED[1].into(), release.into_bytes()),
        (MANAGED[2].into(), bootstrap::bash().as_bytes().to_vec()),
        (
            MANAGED[3].into(),
            bootstrap::powershell().as_bytes().to_vec(),
        ),
    ]);
    let generated = Generated {
        schema: 1,
        config_id: config::id(cfg)?,
        files: files
            .iter()
            .map(|(name, bytes)| (name.clone(), source::digest(bytes)))
            .collect(),
    };
    let mut bytes = serde_json::to_vec_pretty(&generated)?;
    bytes.push(b'\n');
    files.insert(MANIFEST.into(), bytes);
    Ok(files)
}
fn output_path(root: &Path, output: &Path) -> Result<PathBuf> {
    let path = if output.is_absolute() {
        output.to_path_buf()
    } else {
        root.canonicalize()?.join(output)
    };
    let mut current = PathBuf::new();
    for component in path.components() {
        ensure!(
            !matches!(component, Component::ParentDir),
            "generated output must not contain parent traversal"
        );
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "generated output ancestry must contain regular directories"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(path)
}
fn previous(output: &Path) -> Result<Option<Generated>> {
    let path = crate::config::safe_join(output, MANIFEST)?;
    if !path.exists() {
        return Ok(None);
    }
    let generated: Generated = io::read_json(&path)?;
    ensure!(
        generated.schema == 1
            && generated.files.keys().map(String::as_str).eq(MANAGED
                .iter()
                .copied()
                .collect::<std::collections::BTreeSet<_>>(
            )),
        "generated manifest does not own the exact supported file set"
    );
    ensure!(
        cohort_digest(&generated.config_id)
            && generated.files.values().all(|digest| cohort_digest(digest)),
        "invalid generated manifest identities"
    );
    Ok(Some(generated))
}
fn cohort_digest(value: &str) -> bool {
    crate::cohort::plan::is_digest(value)
}
pub fn generate(root: &Path, cfg: &Config, output: &Path, force: bool) -> Result<()> {
    let files = files(cfg)?;
    let output = output_path(root, output)?;
    let old = previous(&output)?;
    // Complete preflight before the first write; --force only changes files
    // already owned by a valid generated manifest.
    for (name, bytes) in &files {
        let path = crate::config::safe_join(&output, name)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                ensure!(
                    metadata.is_file() && !metadata.file_type().is_symlink(),
                    "generated path is not a regular file: {name}"
                );
                ensure!(
                    old.is_some(),
                    "refusing to overwrite an unowned file: {name}"
                );
                if name != MANIFEST && !force {
                    ensure!(
                        metadata.len() <= io::JSON_LIMIT
                            && old.as_ref().unwrap().files.get(name)
                                == Some(&source::file_digest(&path)?),
                        "generated file has local edits; review before using --force: {name}"
                    );
                }
                let _ = bytes;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    let manifest = files
        .get(MANIFEST)
        .context("generated manifest missing")?
        .clone();
    for (name, bytes) in files
        .into_iter()
        .filter(|(name, _)| name != MANIFEST)
        .chain([(MANIFEST.into(), manifest)])
    {
        let path = crate::config::safe_join(&output, &name)?;
        fs::create_dir_all(path.parent().context("generated file has no parent")?)?;
        let temporary = path.with_extension(format!("relship-{}", io::random_id()?));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &path)?;
    }
    Ok(())
}
pub fn check(root: &Path, cfg: &Config, output: &Path) -> Result<()> {
    let output = output_path(root, output)?;
    for (name, bytes) in files(cfg)? {
        let path = crate::config::safe_join(&output, &name)?;
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("missing generated file: {name}"))?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() == bytes.len() as u64,
            "generated file drift: {name}"
        );
        ensure!(fs::read(&path)? == bytes, "generated file drift: {name}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn bash_command_preserves_literal_and_environment_arguments() {
        use std::{os::unix::fs::PermissionsExt, process::Command};

        let temporary = tempfile::tempdir().unwrap();
        let executable = temporary.path().join("capture argv's.sh");
        fs::write(&executable, "#!/bin/sh\nprintf '%s\\000' \"$@\"\n").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let marker = temporary.path().join("unexpected-command");
        let literal = format!("literal '\"$env:HOME; $(touch {})\nlast", marker.display());
        let value = format!("environment '\"$HOME; $(touch {})\nlast", marker.display());
        let runner = config::tests::example().coordinator;
        let script = Script { runner: &runner };
        let command = script.command(&[
            Literal("--config"),
            Environment("RELSHIP_TEST_VALUE"),
            Literal(&literal),
            Literal(""),
        ]);
        let output = Command::new("bash")
            .args(["-euo", "pipefail", "-c", &command])
            .env("RELSHIP_BIN", &executable)
            .env("RELSHIP_TEST_VALUE", &value)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut expected = Vec::new();
        for argument in ["--config", value.as_str(), literal.as_str(), ""] {
            expected.extend_from_slice(argument.as_bytes());
            expected.push(0);
        }
        assert_eq!(output.stdout, expected);
        assert!(!marker.exists());
    }

    #[test]
    fn powershell_rendering_distinguishes_environment_from_literal_dollars() {
        let mut cfg = config::tests::example();
        cfg.coordinator.host = "windows-x86_64".into();
        let script = Script {
            runner: &cfg.coordinator,
        };
        assert_eq!(
            script.command(&[
                Literal("github"),
                Literal("--tag"),
                Environment("RELSHIP_TAG"),
                Literal("literal '\"$HOME; $(Write-Error injected)"),
                Literal(""),
            ]),
            "& $env:RELSHIP_BIN github --tag \"$env:RELSHIP_TAG\" 'literal ''\"$HOME; $(Write-Error injected)' ''\nif ($LASTEXITCODE -ne 0) { throw 'relship command failed' }"
        );

        cfg.coordinator.runs_on = vec!["windows-2025".into()];
        cfg.workers.get_mut("native").unwrap().runner = cfg.coordinator.clone();
        cfg.workers.get_mut("native").unwrap().targets = vec!["windows-x86_64-msvc".into()];
        let install = cfg.installs.values().next().unwrap().clone();
        cfg.installs.insert("windows-x86_64".into(), install);
        for protocol in [3, 4, 5] {
            cfg.execution_protocol = protocol;
            let generated = files(&cfg).unwrap();
            let release = String::from_utf8(generated[MANAGED[1]].clone()).unwrap();
            let commands = release
                .lines()
                .filter(|line| line.contains("& $env:RELSHIP_BIN"))
                .collect::<Vec<_>>();
            assert!(commands.len() >= 12);
            for command in &commands {
                assert!(!command.contains("\"$RELSHIP_"), "{command}");
                assert!(!command.contains("$env:env:"), "{command}");
            }
            assert!(commands.iter().any(|command| {
                command.contains("--role rebuild")
                    && command.contains("--key \"$env:RELSHIP_KEY_FILE\"")
            }));
            assert!(commands.iter().any(|command| {
                command.contains("restore-state")
                    && command.contains("--expected-tag \"$env:RELSHIP_TAG\"")
            }));
        }
    }

    #[test]
    fn delivery_permissions_follow_the_token_used_by_each_job() {
        for custom_token in [false, true] {
            let mut cfg = config::tests::example();
            cfg.delivery.token_secret = custom_token.then(|| "DRAFT_TOKEN".into());
            let generated = files(&cfg).unwrap();
            let release = String::from_utf8(generated[MANAGED[1]].clone()).unwrap();
            let (build_jobs, delivery_jobs) = release.split_once("\n  delivery:\n").unwrap();
            let (delivery, restore) = delivery_jobs.split_once("\n  restore_delivery:\n").unwrap();
            assert!(!build_jobs.contains("contents: write"));
            assert!(!build_jobs.contains("actions: read"));
            if custom_token {
                assert!(!delivery.contains("    permissions:"));
                assert!(
                    restore
                        .contains("    permissions:\n      contents: read\n      actions: read\n")
                );
            } else {
                for job in [delivery, restore] {
                    assert!(job.contains(
                        "    permissions:\n      contents: write\n      actions: read\n"
                    ));
                }
            }
            let token = if custom_token {
                "GITHUB_TOKEN: \"${{ secrets.DRAFT_TOKEN }}\""
            } else {
                "GITHUB_TOKEN: \"${{ github.token }}\""
            };
            for job in [delivery, restore] {
                assert!(job.contains(token));
            }
            assert!(restore.contains("github-token: ${{ github.token }}"));
            assert!(!delivery.contains("github-token:"));
        }
    }

    #[test]
    fn deterministic_static_roles_and_limited_secret_scopes() {
        let cfg = config::tests::example();
        let first = files(&cfg).unwrap();
        assert_eq!(first, files(&cfg).unwrap());
        let checks = String::from_utf8(first[MANAGED[0]].clone()).unwrap();
        let release = String::from_utf8(first[MANAGED[1]].clone()).unwrap();
        assert!(!checks.contains("matrix:"));
        assert!(!checks.contains("secrets."));
        assert!(checks.contains("engine install source without authentication"));
        assert!(!checks.contains(CHECKOUT));
        assert!(!checks.contains(&cfg.trusted.signing_secret));
        assert!(!checks.contains(cfg.delivery.token_secret.as_deref().unwrap()));
        assert!(release.contains("github.workflow_sha"));
        assert!(release.contains("cancel-in-progress: false"));
        assert!(release.contains("--role rebuild"));
        assert!(release.contains("--old-writer-stopped"));
        assert!(release.contains("Remove-Item") == cfg.coordinator.host.starts_with("windows-"));
        assert!(release.contains("unset RELSHIP_SIGNING_KEY"));
    }
    #[test]
    fn legacy_workflow_and_config_bytes_stay_fixed() {
        let mut cfg = config::tests::example();
        cfg.engine.source_id = "e".repeat(64);
        for (protocol, config_id, release_id) in [
            (
                3,
                "d2bf329be9cb30fc69318ae0ee4af489eaa3b4857db7847304911975dd81f71f",
                "0da3b90eeac7344c008860bf94b04a46c7cf1577279f7bdcb6627c9afe78a183",
            ),
            (
                4,
                "671b61cdc9beecdcdc8e3fbadc64806a73b4ed03d71842440fe0d646809c44fd",
                "3e6f07112b5a8ad007bfc2617685d1003fb2a6bcc3f0ea05ef7fe23a629c595d",
            ),
        ] {
            cfg.execution_protocol = protocol;
            let generated = files(&cfg).unwrap();
            assert_eq!(config::id(&cfg).unwrap(), config_id);
            assert_eq!(
                source::digest(&generated[MANAGED[0]]),
                "a3a29f366112581b029ad5004990f76063c757a967c7f6f50bb690e74392a87d"
            );
            assert_eq!(source::digest(&generated[MANAGED[1]]), release_id);
            let runner = serde_json::to_value(&cfg.coordinator).unwrap();
            assert!(runner.get("emulators").is_none() && runner.get("rootfs").is_none());
        }
    }
    #[test]
    fn reviewed_execution_protocol_is_a_literal_in_both_workflows() {
        let mut cfg = config::tests::example();
        cfg.installs
            .values_mut()
            .for_each(|install| install.auth_secret = None);
        for protocol in [3, 4, 5] {
            cfg.execution_protocol = protocol;
            let generated = files(&cfg).unwrap();
            for name in [MANAGED[0], MANAGED[1]] {
                let text = String::from_utf8(generated[name].clone()).unwrap();
                assert!(text.contains(&format!("plan --protocol {protocol} --output")));
                assert!(!text.contains("plan --protocol $"));
            }
        }
    }
    #[test]
    fn untrusted_pr_never_uses_custom_runner() {
        let mut cfg = config::tests::example();
        cfg.workers.get_mut("native").unwrap().runner.runs_on =
            vec!["self-hosted".into(), "sdk".into()];
        let files = files(&cfg).unwrap();
        let check = String::from_utf8(files[MANAGED[0]].clone()).unwrap();
        assert!(check.contains("  guard:"));
        assert!(check.contains("exit 1"));
        assert!(!check.contains(CHECKOUT));
        assert!(!check.contains("runs-on: [\"self-hosted\""));
    }
    #[test]
    fn drift_and_unowned_files_require_review() {
        let root = tempfile::tempdir().unwrap();
        let cfg = config::tests::example();
        generate(root.path(), &cfg, Path::new(".github"), false).unwrap();
        check(root.path(), &cfg, Path::new(".github")).unwrap();
        fs::write(
            root.path().join(".github/relship/install.sh"),
            "local edits",
        )
        .unwrap();
        assert!(check(root.path(), &cfg, Path::new(".github")).is_err());
        assert!(generate(root.path(), &cfg, Path::new(".github"), false).is_err());
        generate(root.path(), &cfg, Path::new(".github"), true).unwrap();
        check(root.path(), &cfg, Path::new(".github")).unwrap();
        let fresh = tempfile::tempdir().unwrap();
        fs::create_dir_all(fresh.path().join(".github/workflows")).unwrap();
        fs::write(
            fresh.path().join(".github/workflows/relship-check.yml"),
            "user",
        )
        .unwrap();
        assert!(generate(fresh.path(), &cfg, Path::new(".github"), true).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn output_symlinks_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(other.path(), root.path().join(".github")).unwrap();
        assert!(
            generate(
                root.path(),
                &config::tests::example(),
                Path::new(".github"),
                true
            )
            .is_err()
        );
    }
    #[test]
    fn public_pr_profiles_depend_on_fixed_guard_without_secret_context() {
        let mut cfg = config::tests::example();
        cfg.installs
            .values_mut()
            .for_each(|install| install.auth_secret = None);
        let generated = files(&cfg).unwrap();
        let checks = String::from_utf8(generated[MANAGED[0]].clone()).unwrap();
        assert!(checks.contains("  guard:"));
        assert!(checks.contains("  plan:"));
        assert!(checks.contains("  worker_native:"));
        assert!(checks.contains("needs: [\"guard\"]"));
        assert!(checks.contains("needs: [\"plan\",\"guard\"]"));
        assert!(!checks.contains("secrets."));
        assert!(!checks.contains("always()"));
    }
    #[test]
    fn profiles_must_not_alias_jobs_or_windows_artifact_paths() {
        let mut cfg = config::tests::example();
        let mut other = cfg.workers["native"].clone();
        other.targets = vec!["linux-x86_64-musl".into()];
        cfg.workers.insert("NATIVE".into(), other);
        let error = files(&cfg).unwrap_err();
        assert!(error.to_string().contains("collide"));
    }
}
