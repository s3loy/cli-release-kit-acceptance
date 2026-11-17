use super::{config, model::*, schedule};
use crate::cohort::{self, bundle, crypto, plan};
use crate::{delivery, process, source, v2::model::Builder};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

pub use super::model::JobRole;

struct JobContext<'a> {
    runner: &'a Runner,
    units: &'a [usize],
    key: Option<&'a Path>,
}
impl<'a> JobContext<'a> {
    fn new(
        config: &'a Config,
        schedule: &'a Schedule,
        profile: &str,
        role: JobRole,
        key: Option<&'a Path>,
        candidate: Option<&Path>,
    ) -> Result<Self> {
        let worker = config
            .workers
            .get(profile)
            .context("unknown configured worker profile")?;
        ensure!(
            worker.runner.host == format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            "configured worker host differs from execution host"
        );
        let units = schedule
            .jobs
            .get(profile)
            .context("worker profile is absent from schedule")?;
        match role {
            JobRole::Worker => ensure!(
                key.is_none() && candidate.is_none(),
                "candidate worker cannot receive a signing key or another candidate"
            ),
            JobRole::Rebuild => ensure!(key.is_some(), "trusted rebuild requires a signing key"),
        }
        Ok(Self {
            runner: &worker.runner,
            units,
            key,
        })
    }

    fn signer(&self) -> Result<Option<ed25519_dalek::SigningKey>> {
        self.key.map(crypto::load_key).transpose()
    }
}

fn prepare_output(root: &Path, output: &Path, candidate: Option<&Path>) -> Result<PathBuf> {
    let output = cohort::io::guard_output(root, output)?;
    if let Some(candidate) = candidate {
        ensure!(
            !output.starts_with(candidate) && !candidate.starts_with(&output),
            "CI attempt output overlaps candidate inputs"
        );
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
pub fn execute_job(
    root: &Path,
    config: &Config,
    plan: &cohort::model::Plan,
    schedule: &Schedule,
    profile: &str,
    role: JobRole,
    key: Option<&Path>,
    candidate: Option<&Path>,
    output: &Path,
) -> Result<cohort::model::RunReceipt> {
    config::assert_current_engine(config)?;
    schedule::validate(root, config, plan, schedule)?;
    let context = JobContext::new(config, schedule, profile, role, key, candidate)?;
    let units = context.units.to_vec();
    // Validate the complete imported candidate before opening signing material.
    // Core bundle validation binds bytes, records, assignment, plan and engine.
    let candidate_path = candidate.map(Path::canonicalize).transpose()?;
    let candidate = candidate_path
        .as_deref()
        .map(|path| bundle::candidate_ref(root, plan, path))
        .transpose()?;
    if let Some(candidate) = &candidate {
        ensure!(
            candidate.digests.keys().copied().eq(units.iter().copied()),
            "candidate must cover exactly the configured profile units"
        );
    }
    let output = prepare_output(root, output, candidate_path.as_deref())?;
    preflight_toolchains(
        root,
        &plan.config,
        units.iter().map(|unit| plan.units[*unit].product).collect(),
        context.runner,
    )?;
    let signer = context.signer()?;
    let assignment = plan::assignment(
        plan,
        units,
        Vec::new(),
        false,
        signer.as_ref().map(crypto::public_key),
        candidate,
    )?;
    let receipt = cohort::run::execute(
        root,
        plan,
        &assignment,
        &output,
        false,
        &[],
        signer.as_ref(),
    )?;
    bundle::export_run(root, &output, &output.join("result"))?;
    Ok(receipt)
}

#[allow(clippy::too_many_arguments)]
pub fn execute_delivery_job(
    root: &Path,
    config: &Config,
    plan: &delivery::model::Plan,
    schedule: &Schedule,
    profile: &str,
    role: JobRole,
    key: Option<&Path>,
    candidate: Option<&Path>,
    output: &Path,
) -> Result<delivery::run::RunReceipt> {
    config::assert_current_engine(config)?;
    schedule::validate_delivery(root, config, plan, schedule)?;
    let context = JobContext::new(config, schedule, profile, role, key, candidate)?;
    let builds = context.units.to_vec();
    let base = delivery::config::base_config(&plan.config);
    preflight_toolchains(
        root,
        &base,
        builds
            .iter()
            .map(|index| plan.builds[*index].product)
            .collect(),
        context.runner,
    )?;
    let native_needed = plan
        .packages
        .iter()
        .any(|package| builds.contains(&package.build) && package.format.is_native());
    // Resolve the exact pinned executable before candidate imports, signing
    // material, product hooks or compilation can run.
    let native = preflight_native_tool(context.runner, native_needed)?;
    let candidate_path = candidate.map(Path::canonicalize).transpose()?;
    let candidate = candidate_path
        .as_deref()
        .map(|path| delivery::bundle::candidate_ref(root, plan, path))
        .transpose()?;
    if let Some(candidate) = &candidate {
        let expected = plan
            .packages
            .iter()
            .enumerate()
            .filter(|(_, package)| builds.contains(&package.build))
            .map(|(index, _)| index);
        ensure!(
            candidate.digests.keys().copied().eq(expected),
            "candidate must cover exactly the configured profile packages"
        );
    }
    let output = prepare_output(root, output, candidate_path.as_deref())?;
    let signer = context.signer()?;
    let assignment = delivery::run::assignment(
        plan,
        &delivery::run::RunOptions {
            units: builds,
            trusted_key: signer.as_ref().map(crypto::public_key),
            candidate,
            ..Default::default()
        },
    )?;
    let receipt = delivery::run::execute_pinned(
        root,
        plan,
        &assignment,
        &output,
        false,
        &[],
        signer.as_ref(),
        native.as_ref().map(|tool| tool.path.as_path()),
        native.as_ref(),
    )?;
    delivery::bundle::export_run(root, &output, &output.join("result"))?;
    Ok(receipt)
}

fn preflight_native_tool(
    runner: &Runner,
    needed: bool,
) -> Result<Option<delivery::native::NativeTool>> {
    if !needed {
        return Ok(None);
    }
    let path = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join(if cfg!(windows) { "nfpm.exe" } else { "nfpm" }))
        .find(|path| path.is_file())
        .context("pinned nFPM executable must be preprovisioned on PATH")?;
    validate_native_tool(runner, &path).map(Some)
}

pub(super) fn validate_native_tool(
    runner: &Runner,
    path: &Path,
) -> Result<delivery::native::NativeTool> {
    let pin = runner
        .nfpm
        .as_ref()
        .context("native package worker requires an explicit nFPM version and SHA-256")?;
    let path = path.canonicalize()?;
    ensure!(
        source::file_digest(&path)? == pin.sha256,
        "actual nFPM executable SHA-256 differs from configured pin"
    );
    let tool = delivery::native::resolve_nfpm(Some(&path))?;
    ensure!(
        tool.version == pin.version && tool.sha256 == pin.sha256,
        "actual nFPM identity differs from configured pin"
    );
    Ok(tool)
}

fn preflight_toolchains(
    root: &Path,
    release: &crate::v2::model::Config,
    products: BTreeSet<usize>,
    runner: &Runner,
) -> Result<()> {
    preflight_product_toolchains(root, &release.products, products, runner)
}

fn preflight_product_toolchains(
    root: &Path,
    release_products: &[crate::v2::model::Product],
    products: BTreeSet<usize>,
    runner: &Runner,
) -> Result<()> {
    for index in products {
        let product = &release_products[index];
        // Toolchain selection can differ between product directories. Probe in
        // the same directory as the canonical build rather than only at root.
        let cwd = crate::v2::contract::product_root(root, product)?;
        match &product.build {
            Builder::Rust { .. } => {
                let output = process::capture(&cwd, &["rustc".into(), "-vV".into()], 30)?;
                validate_rust_probe(runner, &output)?;
            }
            Builder::Go { .. } => {
                let output = process::capture(&cwd, &["go".into(), "version".into()], 30)?;
                validate_go_probe(runner, &output)?;
            }
        }
    }
    Ok(())
}

fn validate_rust_probe(runner: &Runner, output: &str) -> Result<()> {
    let releases: Vec<_> = output
        .lines()
        .filter_map(|line| line.strip_prefix("release: "))
        .collect();
    let hosts: Vec<_> = output
        .lines()
        .filter_map(|line| line.strip_prefix("host: "))
        .collect();
    ensure!(
        releases.len() == 1 && runner.rust_version.as_deref() == Some(releases[0]),
        "actual Rust release differs from configured rust-version"
    );
    ensure!(
        hosts.len() == 1 && hosts[0] == config::rust_host(runner)?,
        "actual Rust host differs from configured native rust-host"
    );
    Ok(())
}

fn validate_go_probe(runner: &Runner, output: &str) -> Result<()> {
    let words: Vec<_> = output.split_whitespace().collect();
    ensure!(
        words.len() == 4
            && words[0] == "go"
            && words[1] == "version"
            && words[2].strip_prefix("go") == runner.go_version.as_deref(),
        "actual Go release differs from configured go-version"
    );
    let (os, arch) = runner
        .host
        .split_once('-')
        .context("invalid configured runner host")?;
    let os = if os == "macos" { "darwin" } else { os };
    let arch = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        _ => arch,
    };
    ensure!(
        words[3] == format!("{os}/{arch}"),
        "actual Go host differs from configured runner host"
    );
    Ok(())
}

/// Run one exact protocol 5 profile after validating all trusted runtime pins.
#[allow(clippy::too_many_arguments)]
pub fn execute_v5_job(
    root: &Path,
    config: &Config,
    plan: &crate::v5::model::Plan,
    schedule: &Schedule,
    profile: &str,
    role: JobRole,
    key: Option<&Path>,
    candidate: Option<&Path>,
    output: &Path,
) -> Result<crate::v5::run::RunReceipt> {
    use crate::v5;
    config::assert_current_engine(config)?;
    schedule::validate_v5(root, config, plan, schedule)?;
    let context = JobContext::new(config, schedule, profile, role, key, candidate)?;
    let builds = context.units.to_vec();
    let tools = v5::runtime::RuntimeTools {
        emulators: context
            .runner
            .emulators
            .iter()
            .map(|(name, path)| (name.clone(), path.into()))
            .collect(),
        rootfs: context
            .runner
            .rootfs
            .iter()
            .map(|(name, path)| (name.clone(), path.into()))
            .collect(),
    };
    // Pin identities before loading signing material or entering product hooks.
    for index in &builds {
        let build = &plan.builds[*index];
        v5::runtime::validate_tools(
            &build.descriptor,
            &plan.config.targets[build.target].runtime,
            &tools,
        )?;
    }
    let products = plan
        .config
        .products
        .iter()
        .map(|p| p.base())
        .collect::<Vec<_>>();
    preflight_product_toolchains(
        root,
        &products,
        builds
            .iter()
            .map(|index| plan.builds[*index].product)
            .collect(),
        context.runner,
    )?;
    let native_needed = plan
        .packages
        .iter()
        .any(|package| builds.contains(&package.build) && package.format.is_native());
    let native = preflight_native_tool(context.runner, native_needed)?;
    let candidate_path = candidate.map(Path::canonicalize).transpose()?;
    let candidate = candidate_path
        .as_deref()
        .map(|path| v5::bundle::candidate_ref(root, plan, path))
        .transpose()?;
    if let Some(candidate) = &candidate {
        let expected = plan
            .packages
            .iter()
            .enumerate()
            .filter(|(_, package)| builds.contains(&package.build))
            .map(|(index, _)| index);
        ensure!(
            candidate.digests.keys().copied().eq(expected),
            "candidate must cover exactly the configured profile packages"
        );
    }
    let output = prepare_output(root, output, candidate_path.as_deref())?;
    let signer = context.signer()?;
    let assignment = v5::run::assignment(
        plan,
        &v5::run::RunOptions {
            units: builds,
            trusted_key: signer.as_ref().map(crypto::public_key),
            candidate,
            ..Default::default()
        },
    )?;
    let receipt = v5::run::execute_pinned(
        root,
        plan,
        &assignment,
        &output,
        false,
        &[],
        signer.as_ref(),
        native.as_ref().map(|tool| tool.path.as_path()),
        native.as_ref(),
        &tools,
    )?;
    v5::bundle::export_run(root, &output, &output.join("result"))?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_five_sdk_hosts_are_actual_arm_or_x86_process_hosts() {
        let mut runner = config::tests::example().workers["native"].runner.clone();
        runner.host = "linux-arm".into();
        runner.rust_host = Some("armv7-unknown-linux-gnueabihf".into());
        validate_rust_probe(
            &runner,
            "release: 1.96.0\nhost: armv7-unknown-linux-gnueabihf\n",
        )
        .unwrap();
        validate_go_probe(&runner, "go version go1.27.3 linux/arm").unwrap();
        assert!(validate_go_probe(&runner, "go version go1.27.3 linux/armv7").is_err());
        runner.host = "linux-x86".into();
        runner.rust_host = None;
        validate_rust_probe(&runner, "release: 1.96.0\nhost: i686-unknown-linux-gnu\n").unwrap();
        validate_go_probe(&runner, "go version go1.27.3 linux/386").unwrap();
        assert!(
            validate_rust_probe(&runner, "release: 1.96.0\nhost: x86_64-unknown-linux-gnu\n")
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn native_backend_hash_is_checked_before_executing_the_resolved_tool() {
        use std::{fs, os::unix::fs::PermissionsExt};
        let temporary = tempfile::tempdir().unwrap();
        let executable = temporary.path().join("nfpm");
        let invoked = temporary.path().join("invoked");
        fs::write(
            &executable,
            format!(
                "#!/bin/sh\ntouch '{}'\nprintf 'GitVersion: 2.49.0\\n'\n",
                invoked.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let mut runner = config::tests::example().workers["native"].runner.clone();
        runner.nfpm = Some(ToolPin {
            version: delivery::model::NFPM_VERSION.into(),
            sha256: "0".repeat(64),
        });
        let error = validate_native_tool(&runner, &executable).unwrap_err();
        assert!(error.to_string().contains("SHA-256 differs"));
        assert!(!invoked.exists());
        runner.nfpm.as_mut().unwrap().sha256 = source::file_digest(&executable).unwrap();
        let tool = validate_native_tool(&runner, &executable).unwrap();
        assert_eq!(tool.version, delivery::model::NFPM_VERSION);
        assert!(invoked.exists());
        assert!(preflight_native_tool(&runner, false).unwrap().is_none());
    }

    #[test]
    fn changed_toolchain_version_fails_before_loading_signing_material() {
        let (_temp, root, mut config, plan) = super::super::schedule::tests::fixture();
        config
            .workers
            .get_mut("native")
            .unwrap()
            .runner
            .rust_version = Some("0.0.0".into());
        let schedule = schedule::create(&root, &config, &plan).unwrap();
        let output = root.parent().unwrap().join("attempt");
        let nonexistent_key = root.parent().unwrap().join("missing-key.json");
        let error = execute_job(
            &root,
            &config,
            &plan,
            &schedule,
            "native",
            JobRole::Rebuild,
            Some(&nonexistent_key),
            None,
            &output,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("actual Rust release differs"),
            "{error:#}"
        );
        assert!(!output.exists());
    }

    #[test]
    fn toolchain_probes_bind_exact_releases_and_native_hosts() {
        let config = config::tests::example();
        let runner = &config.workers["native"].runner;
        assert!(
            validate_rust_probe(
                runner,
                "rustc 1.96.0\nrelease: 1.96.0\nhost: x86_64-unknown-linux-gnu\n"
            )
            .is_ok()
        );
        assert!(
            validate_rust_probe(
                runner,
                "rustc 1.96.0\nrelease: 1.96.0\nhost: x86_64-unknown-linux-musl\n"
            )
            .is_err()
        );
        assert!(
            validate_rust_probe(
                runner,
                "rustc 1.95.0\nrelease: 1.95.0\nhost: x86_64-unknown-linux-gnu\n"
            )
            .is_err()
        );
        assert!(validate_go_probe(runner, "go version go1.27.3 linux/amd64\n").is_ok());
        assert!(validate_go_probe(runner, "go version go1.27.2 linux/amd64\n").is_err());
        assert!(validate_go_probe(runner, "go version go1.27.3 linux/arm64\n").is_err());
        assert!(validate_go_probe(runner, "go version devel go1.28 linux/amd64\n").is_err());
    }
}
