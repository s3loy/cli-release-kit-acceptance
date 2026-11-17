//! Reviewed native-six CI, reusing the managed-file renderer and installers.
use super::{
    bootstrap, config,
    model::{Config, Runner},
    render::{
        self,
        Argument::{Environment, Literal},
        Script,
    },
    seal::Role,
};
use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

/// Frozen from the upstream v2.49.0 checksums.txt; runtime provisioning never
/// downloads a checksum as a substitute for this reviewed expected identity.
pub fn nfpm_tool(host: &str) -> Result<crate::compatibility::ToolInput> {
    let (architecture, sha256) = match host {
        "linux-x86_64" => (
            "x86_64",
            "2afaa5ffb5e3493402e31e7c67a5a1fb42133e3f66fc315ca0051934125561c7",
        ),
        "linux-aarch64" => (
            "arm64",
            "d4eee71839e92c68cbd3b101640bad32d2856fc551acae0635be9118e48c9d9c",
        ),
        _ => anyhow::bail!(
            "qualified native package provisioning requires native Linux x86_64 or ARM64"
        ),
    };
    let version = crate::delivery::model::NFPM_VERSION;
    ensure!(
        version == "2.49.0",
        "nFPM archive pins require an explicit version update"
    );
    let filename = format!("nfpm_{version}_Linux_{architecture}.tar.gz");
    Ok(crate::compatibility::ToolInput::Archive {
        link_policy: Default::default(),
        name: "nfpm".into(),
        version: version.into(),
        url: format!("https://github.com/goreleaser/nfpm/releases/download/v{version}/{filename}"),
        sha256: sha256.into(),
        filename,
    })
}
struct NativePackaging {
    tool: crate::delivery::native::NativeTool,
    directory: std::path::PathBuf,
}
impl Drop for NativePackaging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}
fn provision_nfpm(runner: &Runner) -> Result<NativePackaging> {
    ensure!(
        runner.nfpm.is_some(),
        "qualified native packaging requires a reviewed nFPM executable SHA-256 pin"
    );
    let tool = nfpm_tool(&runner.host)?;
    let directory = std::env::temp_dir()
        .canonicalize()?
        .join(format!("relship-nfpm-{}", crate::cohort::io::random_id()?));
    let result = (|| {
        let acquired = crate::compatibility::acquire_tools(&[tool], &directory)?;
        let root = acquired
            .get("nfpm")
            .ok_or_else(|| anyhow::anyhow!("nFPM provisioning returned no verified root"))?;
        let path = crate::config::safe_join(root, "nfpm")?;
        // Existing preflight verifies configured executable bytes before the
        // first --version invocation, then checks exact tool version and hash.
        let tool = super::run::validate_native_tool(runner, &path)?;
        Ok(NativePackaging {
            tool,
            directory: directory.clone(),
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&directory);
    }
    result
}

pub fn hosted_label(host: &str) -> Result<&'static str> {
    Ok(match host {
        "linux-x86_64" => "ubuntu-24.04",
        "linux-aarch64" => "ubuntu-24.04-arm",
        "macos-x86_64" => "macos-15-intel",
        "macos-aarch64" => "macos-15",
        "windows-x86_64" => "windows-2022",
        "windows-aarch64" => "windows-11-vs2026-arm",
        _ => anyhow::bail!("unsupported qualified runner host"),
    })
}

pub(super) fn target_host(target: &str) -> Result<String> {
    if config::validate_host(target).is_ok() {
        return Ok(target.into());
    }
    let target = crate::catalog::resolve(target)?;
    let host = format!("{}-{}", target.os, target.arch);
    config::validate_host(&host)?;
    Ok(host)
}

pub fn validate_profiles(cfg: &Config) -> Result<()> {
    ensure!(
        cfg.execution_protocol == 6,
        "qualified CI requires execution-protocol 6"
    );
    for runner in std::iter::once(&cfg.coordinator).chain(cfg.workers.values().map(|w| &w.runner)) {
        ensure!(
            runner.runs_on == vec![hosted_label(&runner.host)?.to_string()],
            "qualified jobs require the reviewed fresh hosted runner for their native host"
        );
        ensure!(
            runner.emulators.is_empty() && runner.rootfs.is_empty(),
            "native-six qualified profiles cannot select emulated runtime dependencies"
        );
        ensure!(
            cfg.installs
                .get(&runner.host)
                .ok_or_else(|| anyhow::anyhow!("qualified host has no engine install pin"))?
                .auth_secret
                .is_none(),
            "qualified engine bootstrap must use an unauthenticated pinned source"
        );
    }
    ensure!(
        cfg.coordinator.host == "linux-x86_64",
        "independent sealing coordinator requires the reviewed Linux x86_64 hosted runner"
    );
    let mut hosts = BTreeSet::new();
    for worker in cfg.workers.values() {
        ensure!(
            hosts.insert(&worker.runner.host),
            "each qualified profile must select its unique native host"
        );
        for target in &worker.targets {
            ensure!(
                target_host(target)? == worker.runner.host,
                "qualified profile target belongs to another native host"
            );
        }
    }
    Ok(())
}

/// This schedule identity is derived from reviewed configuration and exact plan.
/// It does not grant authority to a schedule copied from an uploaded bundle.
pub fn schedule_id(cfg: &Config, plan_id: &str, source_commit: &str) -> Result<String> {
    config::validate(cfg)?;
    ensure!(
        crate::cohort::plan::is_digest(plan_id),
        "invalid qualified plan identity"
    );
    let mut bytes = b"cli-release-kit/qualified-ci-schedule/v1\0".to_vec();
    bytes.extend(serde_json::to_vec(&(
        config::id(cfg)?,
        plan_id,
        source_commit,
        &cfg.workers,
    ))?);
    Ok(crate::source::digest(&bytes))
}

pub fn validate_plan(
    cfg: &Config,
    plan: &crate::qualified::model::Plan,
    expected_source: &str,
) -> Result<()> {
    config::assert_current_engine(cfg)?;
    validate_profiles(cfg)?;
    crate::qualified::plan::validate_offline(plan)?;
    ensure!(
        plan.source.commit == expected_source && plan.engine_source_id == cfg.engine.source_id,
        "qualified plan differs from expected source or pinned engine identity"
    );
    let text = plan.ci_config.as_ref().ok_or_else(|| {
        anyhow::anyhow!("qualified CI plan must include source-bound release-ci.toml")
    })?;
    ensure!(
        plan.source.files.get("release-ci.toml") == Some(&crate::source::digest(text.as_bytes())),
        "qualified plan CI configuration bytes differ from source manifest"
    );
    let saved: Config = toml::from_str(text)
        .map_err(|_| anyhow::anyhow!("invalid source-bound CI configuration"))?;
    config::validate(&saved)?;
    ensure!(
        &saved == cfg,
        "reviewed CI configuration differs from source-bound plan"
    );
    let mut covered = BTreeSet::new();
    for profile in cfg.workers.keys() {
        for build in selected_builds(cfg, plan, profile)? {
            ensure!(
                covered.insert(build),
                "qualified build is assigned to multiple CI profiles"
            );
        }
    }
    ensure!(
        covered.len() == plan.builds.len(),
        "qualified CI profiles do not cover every planned build"
    );
    Ok(())
}

pub fn selected_builds(
    cfg: &Config,
    plan: &crate::qualified::model::Plan,
    profile: &str,
) -> Result<Vec<usize>> {
    let worker = cfg
        .workers
        .get(profile)
        .ok_or_else(|| anyhow::anyhow!("unknown qualified CI profile"))?;
    let selected = plan
        .builds
        .iter()
        .enumerate()
        .filter(|(_, b)| {
            worker.targets.contains(&b.target)
                || worker
                    .targets
                    .contains(&crate::qualified::plan::host_key(b))
        })
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    ensure!(
        !selected.is_empty(),
        "qualified CI profile has no planned builds"
    );
    Ok(selected)
}

pub fn expected(
    cfg: &Config,
    plan: &crate::qualified::model::Plan,
    repository: &str,
    expected_source: &str,
    run_id: u64,
    run_attempt: u64,
) -> Result<super::seal::Expected> {
    validate_plan(cfg, plan, expected_source)?;
    let mut profiles = BTreeMap::new();
    for profile in cfg.workers.keys() {
        let builds = selected_builds(cfg, plan, profile)?;
        let packages = plan
            .packages
            .iter()
            .filter(|p| builds.contains(&p.build))
            .map(|p| (p.id.clone(), p.filename.clone()))
            .collect();
        profiles.insert(profile.clone(), packages);
    }
    let expected = super::seal::Expected {
        repository: repository.into(),
        branch: cfg.trusted.branch.clone(),
        run_id,
        run_attempt,
        source_commit: expected_source.into(),
        engine_source_id: plan.engine_source_id.clone(),
        config_id: config::id(cfg)?,
        plan_id: plan.id.clone(),
        schedule_id: schedule_id(cfg, &plan.id, expected_source)?,
        profiles,
    };
    super::seal::validate_expected(&expected)?;
    Ok(expected)
}

/// Run source execution only in the credential-free native worker process.
/// The sealing process calls only the static verifier and transport reader.
#[allow(clippy::too_many_arguments)]
pub fn execute_job(
    root: &Path,
    cfg: &Config,
    plan: &crate::qualified::model::Plan,
    profile: &str,
    role: Role,
    expected_source: &str,
    output: &Path,
    resume: bool,
) -> Result<crate::qualified::model::Receipt> {
    validate_plan(cfg, plan, expected_source)?;
    let worker = cfg
        .workers
        .get(profile)
        .ok_or_else(|| anyhow::anyhow!("unknown qualified CI profile"))?;
    ensure!(
        worker.runner.host == format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        "qualified worker is not running on its configured native host"
    );
    let selected = selected_builds(cfg, plan, profile)?;
    let nfpm = if plan
        .packages
        .iter()
        .any(|p| selected.contains(&p.build) && p.format.is_native())
    {
        Some(provision_nfpm(&worker.runner)?)
    } else {
        None
    };
    let receipt = crate::qualified::run::execute(
        root,
        plan,
        output,
        &selected,
        resume,
        nfpm.as_ref().map(|p| p.tool.path.as_path()),
    )?;
    // Export is a small data-only closure. Build trees and installed SDKs stay
    // on the worker and never cross into the key-bearing sealing job.
    let transport = output.join("result");
    crate::qualified::run::export(output, &transport)?;
    let manifest = manifest(cfg, plan, &receipt, profile, role)?;
    crate::cohort::io::write_json_atomic(&output.join("ci-manifest.json"), &manifest)?;
    Ok(receipt)
}

pub fn manifest(
    cfg: &Config,
    plan: &crate::qualified::model::Plan,
    receipt: &crate::qualified::model::Receipt,
    profile: &str,
    role: Role,
) -> Result<super::seal::Manifest> {
    validate_plan(cfg, plan, &plan.source.commit)?;
    let selected = selected_builds(cfg, plan, profile)?;
    ensure!(
        receipt.schema == crate::qualified::model::SCHEMA
            && receipt.plan_id == plan.id
            && receipt.source_commit == plan.source.commit
            && receipt.selected == selected
            && receipt.complete,
        "qualified result is incomplete or its selected build scope differs from the reviewed profile"
    );
    let required = plan
        .packages
        .iter()
        .enumerate()
        .filter(|(_, p)| selected.contains(&p.build))
        .collect::<Vec<_>>();
    ensure!(
        receipt
            .packages
            .keys()
            .copied()
            .eq(required.iter().map(|(i, _)| *i)),
        "qualified result packages differ from the complete profile package set"
    );
    ensure!(
        receipt
            .payloads
            .keys()
            .copied()
            .eq(selected.iter().copied()),
        "qualified result payload scope differs from the complete reviewed profile"
    );
    let validation_ids = plan
        .validations
        .iter()
        .filter(|v| required.iter().any(|(index, _)| *index == v.package))
        .map(|v| &v.id)
        .collect::<BTreeSet<_>>();
    ensure!(
        receipt.validations.keys().eq(validation_ids.into_iter()),
        "qualified result validation scope differs from the complete reviewed profile"
    );
    let mut packages = BTreeMap::new();
    for (index, package) in required {
        let record = &receipt.packages[&index];
        ensure!(
            record.package_id == package.id && record.filename == package.filename,
            "qualified result package identity differs from plan"
        );
        let validations = plan
            .validations
            .iter()
            .filter(|v| v.package == index)
            .map(|v| {
                let record = receipt.validations.get(&v.id).ok_or_else(|| {
                    anyhow::anyhow!("qualified package lacks a required validation")
                })?;
                ensure!(
                    record.id == v.id && record.package_sha256 == receipt.packages[&index].sha256,
                    "qualified validation is bound to another package"
                );
                Ok(record)
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !validations.is_empty(),
            "qualified package has no required validation records"
        );
        let mut bytes = b"cli-release-kit/qualified-ci-validations/v1\0".to_vec();
        bytes.extend(serde_json::to_vec(&validations)?);
        packages.insert(
            package.id.clone(),
            super::seal::Package {
                filename: package.filename.clone(),
                size: record.size,
                sha256: record.sha256.clone(),
                validation_id: crate::source::digest(&bytes),
            },
        );
    }
    Ok(super::seal::Manifest {
        schema: 1,
        source_commit: plan.source.commit.clone(),
        engine_source_id: plan.engine_source_id.clone(),
        config_id: config::id(cfg)?,
        plan_id: plan.id.clone(),
        schedule_id: schedule_id(cfg, &plan.id, &plan.source.commit)?,
        profile: profile.into(),
        role,
        packages,
    })
}

fn artifact(kind: &str, profile: Option<&str>) -> String {
    let profile = profile.map(|p| format!("-{p}")).unwrap_or_default();
    format!(
        "relship-qualified-{kind}{profile}-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}"
    )
}
fn job_id(role: Role, profile: &str) -> String {
    format!("{}_{}", role.name(), profile.replace('-', "_"))
}
fn header(
    text: &mut String,
    id: &str,
    name: &str,
    runner: &Runner,
    needs: &[String],
    environment: Option<&str>,
) {
    text.push_str(&format!(
        "  {id}:\n    name: {}\n    runs-on: {}\n    timeout-minutes: 90\n",
        render::q(name),
        serde_json::to_string(&runner.runs_on).unwrap()
    ));
    if !needs.is_empty() {
        text.push_str(&format!(
            "    needs: {}\n",
            serde_json::to_string(needs).unwrap()
        ));
    }
    if let Some(environment) = environment {
        text.push_str(&format!("    environment: {}\n", render::q(environment)));
    }
    text.push_str("    permissions:\n      contents: read\n");
    if id == "seal" {
        text.push_str("      actions: read\n");
    }
    text.push_str("    env:\n");
    render::env(text, "RELSHIP_EXPECTED_SOURCE", "${{ github.sha }}", 6);
    text.push_str("    steps:\n");
}
fn diagnostics(text: &mut String, runner: &Runner, label: &str, path: &str) {
    let script = Script { runner };
    text.push_str(&format!("      - name: Record strict {label} outcome\n        if: always()\n        shell: {}\n        env:\n", script.shell()));
    render::env(text, "RELSHIP_JOB_STATUS", "${{ job.status }}", 10);
    text.push_str("        run: |\n");
    let body = if script.windows() {
        format!(
            "\"{label}: $env:RELSHIP_JOB_STATUS at $env:RELSHIP_EXPECTED_SOURCE\" | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8\nNew-Item -ItemType Directory -Force -Path '{path}' | Out-Null\n\"status=$env:RELSHIP_JOB_STATUS\" | Out-File -FilePath '{path}/ci-outcome.txt' -Encoding utf8\nif ($env:RELSHIP_JOB_STATUS -ne 'success') {{ throw 'qualified job failed; inspect diagnostics' }}"
        )
    } else {
        format!(
            "set -euo pipefail\nmkdir -p '{path}'\nprintf '{label}: %s at %s\\n' \"$RELSHIP_JOB_STATUS\" \"$RELSHIP_EXPECTED_SOURCE\" >> \"$GITHUB_STEP_SUMMARY\"\nprintf 'status=%s\\n' \"$RELSHIP_JOB_STATUS\" > '{path}/ci-outcome.txt'\ntest \"$RELSHIP_JOB_STATUS\" = success"
        )
    };
    for line in body.lines() {
        text.push_str(&format!("          {line}\n"));
    }
    let files = [
        "receipt.json",
        "ci-manifest.json",
        "ci-outcome.txt",
        "invocations/*/logs/**",
        "validations/**",
        "evidence/**",
    ]
    .iter()
    .map(|relative| format!("{path}/{relative}"))
    .collect::<Vec<_>>()
    .join("\n");
    render::upload(
        text,
        &artifact(&format!("diagnostics-{label}"), None),
        &files,
        Some("always()"),
    );
}

fn plan_job(text: &mut String, cfg: &Config) {
    let runner = &cfg.coordinator;
    header(
        text,
        "plan",
        "relship canonical qualified plan",
        runner,
        &["guard".into()],
        None,
    );
    render::checkout_install(text, cfg, runner, false, true, false);
    let script = Script { runner };
    script.step(
        text,
        "Create canonical source-bound qualified plan",
        &[
            script.mkdir("target/relship/input"),
            script.command(&[
                Literal("plan"),
                Literal("--protocol"),
                Literal("6"),
                Literal("--output"),
                Literal("target/relship/input/plan.json"),
            ]),
        ]
        .join("\n"),
    );
    script.step(text,"Show exact source and final-package acceptance graph before sealing approval",
        "printf 'Exact source SHA: `%s`\\n\\nCanonical package and validation graph:\\n```json\\n' \"$RELSHIP_EXPECTED_SOURCE\" >> \"$GITHUB_STEP_SUMMARY\"\ncat target/relship/input/plan.json >> \"$GITHUB_STEP_SUMMARY\"\nprintf '\\n```\\n' >> \"$GITHUB_STEP_SUMMARY\"");
    render::upload(
        text,
        &artifact("input", None),
        "target/relship/input/",
        None,
    );
    diagnostics(text, runner, "plan", "target/relship/plan-diagnostics");
}
fn worker(text: &mut String, cfg: &Config, profile: &str, runner: &Runner, role: Role) {
    let needs = if role == Role::Rebuild {
        vec!["plan".into(), job_id(Role::Candidate, profile)]
    } else {
        vec!["plan".into(), "guard".into()]
    };
    header(
        text,
        &job_id(role, profile),
        &super::seal::job_name(role, profile),
        runner,
        &needs,
        None,
    );
    render::checkout_install(text, cfg, runner, false, false, false);
    render::download(text, &artifact("input", None), "target/relship/input/");
    let script = Script { runner };
    script.step(
        text,
        if role == Role::Rebuild {
            "Rebuild exact source afresh without signing credentials"
        } else {
            "Build and validate unsigned candidate"
        },
        &script.command(&[
            Literal("ci"),
            Literal("qualified-run"),
            Literal("--config"),
            Environment("RELSHIP_CONFIG"),
            Literal("--plan"),
            Literal("target/relship/input/plan.json"),
            Literal("--profile"),
            Literal(profile),
            Literal("--expected-source"),
            Environment("RELSHIP_EXPECTED_SOURCE"),
            Literal("--role"),
            Literal(role.name()),
            Literal("--output"),
            Literal("target/relship/job"),
        ]),
    );
    render::upload(
        text,
        &artifact(role.name(), Some(profile)),
        "target/relship/job/result/",
        None,
    );
    diagnostics(
        text,
        runner,
        &format!("{}-{profile}", role.name()),
        "target/relship/job",
    );
}
fn install_without_checkout(text: &mut String, cfg: &Config) {
    let install = &cfg.installs[&cfg.coordinator.host];
    text.push_str("      - name: Install only the reviewed pinned engine\n        shell: bash\n        env:\n");
    for (key, value) in [
        ("RELSHIP_URL", install.url.as_str()),
        ("RELSHIP_SHA256", install.sha256.as_str()),
        ("RELSHIP_FORMAT", install.format.as_str()),
        ("RELSHIP_MEMBER", install.member.as_deref().unwrap_or("")),
        ("RELSHIP_VERSION", cfg.engine.version.as_str()),
        ("RELSHIP_SOURCE_ID", cfg.engine.source_id.as_str()),
        (
            "RELSHIP_INSTALL_DIR",
            "${{ runner.temp }}/relship-engine-seal-${{ github.run_attempt }}",
        ),
    ] {
        render::env(text, key, value, 10);
    }
    text.push_str("        run: |\n");
    // The bootstrap is engine-owned inline content. No file from the consumer
    // checkout or from a build artifact can replace this installer.
    for line in bootstrap::bash().lines() {
        text.push_str(&format!("          {line}\n"));
    }
}
fn seal_job(text: &mut String, cfg: &Config) {
    let needs = cfg
        .workers
        .keys()
        .flat_map(|p| [job_id(Role::Candidate, p), job_id(Role::Rebuild, p)])
        .chain(["plan".into(), "guard".into()])
        .collect::<Vec<_>>();
    let runner = &cfg.coordinator;
    header(
        text,
        "seal",
        "relship independent data-only sealing",
        runner,
        &needs,
        Some(&cfg.trusted.environment),
    );
    install_without_checkout(text, cfg);
    render::download(text, &artifact("input", None), "input/");
    text.push_str("      - name: Seal complete API-bound results without consumer execution\n        shell: bash\n        env:\n");
    render::env(
        text,
        "RELSHIP_REVIEWED_CONFIG",
        &toml::to_string(cfg).expect("validated config"),
        10,
    );
    render::env(
        text,
        "RELSHIP_SIGNING_KEY",
        &format!("${{{{ secrets.{} }}}}", cfg.trusted.signing_secret),
        10,
    );
    render::env(text, "GH_TOKEN", "${{ github.token }}", 10);
    render::env(text, "RELSHIP_RUN_ID", "${{ github.run_id }}", 10);
    render::env(text, "RELSHIP_RUN_ATTEMPT", "${{ github.run_attempt }}", 10);
    text.push_str("        run: |\n          set -euo pipefail\n          umask 077\n          RELSHIP_KEY_FILE=$(mktemp \"$RUNNER_TEMP/relship-seal-key.XXXXXXXX\")\n          RELSHIP_CONFIG=$(mktemp \"$RUNNER_TEMP/relship-seal-ci.XXXXXXXX\")\n          trap 'rm -f -- \"$RELSHIP_KEY_FILE\" \"$RELSHIP_CONFIG\"; unset RELSHIP_SIGNING_KEY' EXIT\n          printf '%s' \"$RELSHIP_SIGNING_KEY\" > \"$RELSHIP_KEY_FILE\"\n          printf '%s' \"$RELSHIP_REVIEWED_CONFIG\" > \"$RELSHIP_CONFIG\"\n          unset RELSHIP_SIGNING_KEY RELSHIP_REVIEWED_CONFIG\n          \"$RELSHIP_BIN\" ci seal --config \"$RELSHIP_CONFIG\" --plan input/plan.json --results results --expected-source \"$RELSHIP_EXPECTED_SOURCE\" --run-id \"$RELSHIP_RUN_ID\" --run-attempt \"$RELSHIP_RUN_ATTEMPT\" --key \"$RELSHIP_KEY_FILE\" --output sealed\n");
    render::upload(text, &artifact("sealed", None), "sealed/", None);
    diagnostics(text, runner, "seal", "seal-diagnostics");
}

pub fn workflows(cfg: &Config) -> Result<(String, String)> {
    validate_profiles(cfg)?;
    // This increment deliberately has one reviewed dispatch flow. Untrusted PR
    // execution does not enter the new protocol's independent sealing path.
    let check = "# Generated by relship.\nname: Relship qualified acceptance guidance\non:\n  workflow_dispatch:\npermissions:\n  contents: read\njobs:\n  review:\n    runs-on: ubuntu-24.04\n    steps:\n      - name: Record qualified acceptance requirement\n        shell: bash\n        run: |\n          printf '%s\\n' 'Run Relship qualified acceptance on the reviewed trusted branch for the exact source SHA.' >> \"$GITHUB_STEP_SUMMARY\"\n".into();
    let mut text = String::from(
        "# Generated by relship; review together with release-ci.toml.\nname: Relship qualified acceptance\nrun-name: Relship qualified acceptance at ${{ github.sha }}\non:\n  workflow_dispatch:\npermissions:\n  contents: read\nconcurrency:\n  group: relship-qualified-${{ github.repository }}-${{ github.ref }}\n  cancel-in-progress: false\njobs:\n  guard:\n    name: Require exact trusted dispatch revision\n    runs-on: ubuntu-24.04\n    steps:\n      - name: Bind source and workflow before any build\n        shell: bash\n        env:\n",
    );
    render::env(
        &mut text,
        "RELSHIP_TRUSTED_REF",
        &format!("refs/heads/{}", cfg.trusted.branch),
        10,
    );
    for (k, v) in [
        ("RELSHIP_REF", "${{ github.ref }}"),
        ("RELSHIP_SOURCE", "${{ github.sha }}"),
        ("RELSHIP_WORKFLOW_SOURCE", "${{ github.workflow_sha }}"),
        ("RELSHIP_EVENT", "${{ github.event_name }}"),
    ] {
        render::env(&mut text, k, v, 10);
    }
    text.push_str("        run: |\n          set -euo pipefail\n          test \"$RELSHIP_EVENT\" = workflow_dispatch\n          test \"$RELSHIP_REF\" = \"$RELSHIP_TRUSTED_REF\"\n          test \"$RELSHIP_SOURCE\" = \"$RELSHIP_WORKFLOW_SOURCE\"\n          printf 'Reviewed exact source/workflow SHA: `%s`\\n' \"$RELSHIP_SOURCE\" >> \"$GITHUB_STEP_SUMMARY\"\n");
    plan_job(&mut text, cfg);
    for (profile, worker_cfg) in &cfg.workers {
        worker(&mut text, cfg, profile, &worker_cfg.runner, Role::Candidate);
        worker(&mut text, cfg, profile, &worker_cfg.runner, Role::Rebuild);
    }
    seal_job(&mut text, cfg);
    Ok((check, text))
}
