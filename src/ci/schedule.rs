use super::{config, model::*};
use crate::{
    cohort, delivery, source,
    v2::model::{Builder, Recipe},
};
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeMap, path::Path};

pub fn id(schedule: &Schedule) -> Result<String> {
    let mut value = schedule.clone();
    value.id.clear();
    let mut bytes = b"cli-release-kit/ci-schedule/v1\0".to_vec();
    bytes.extend(serde_json::to_vec(&value)?);
    Ok(source::digest(&bytes))
}

pub fn create(root: &Path, config: &Config, plan: &cohort::model::Plan) -> Result<Schedule> {
    config::assert_current_engine(config)?;
    ensure!(
        config.execution_protocol == 3,
        "CI profile execution-protocol differs from plan protocol 3"
    );
    cohort::plan::validate(root, plan)?;
    ensure!(
        plan.engine_source_id == config.engine.source_id,
        "plan engine differs from CI configuration"
    );
    let jobs = assignments(config, plan)?;
    let mut schedule = Schedule {
        id: String::new(),
        schema: SCHEMA,
        config_id: config::id(config)?,
        plan_id: plan.id.clone(),
        source_commit: plan.source.commit.clone(),
        engine_source_id: plan.engine_source_id.clone(),
        jobs,
    };
    schedule.id = id(&schedule)?;
    Ok(schedule)
}

pub fn validate(
    root: &Path,
    config: &Config,
    plan: &cohort::model::Plan,
    schedule: &Schedule,
) -> Result<()> {
    // Reconstruct every job from the trusted configuration and canonical plan.
    // A self-consistent hash alone cannot authorize a different unit selection.
    let expected = create(root, config, plan)?;
    ensure!(
        schedule == &expected,
        "CI schedule differs from trusted configuration, plan or source"
    );
    Ok(())
}

/// Reconstruct static worker ownership of builds and every attached package.
pub fn create_delivery(
    root: &Path,
    config: &Config,
    plan: &delivery::model::Plan,
) -> Result<Schedule> {
    config::assert_current_engine(config)?;
    ensure!(
        config.execution_protocol == 4,
        "CI profile execution-protocol differs from plan protocol 4"
    );
    delivery::plan::validate_saved(root, plan)?;
    ensure!(
        plan.engine_source_id == config.engine.source_id,
        "plan engine differs from CI configuration"
    );
    let base = delivery::config::base_config(&plan.config);
    let jobs = assign_builds(
        config,
        &base,
        plan.builds
            .iter()
            .map(|build| (build.product, build.target, &build.recipe)),
    )?;
    for (profile, builds) in &jobs {
        if plan
            .packages
            .iter()
            .any(|package| builds.contains(&package.build) && package.format.is_native())
        {
            ensure!(
                config.workers[profile].runner.nfpm.is_some(),
                "worker profile {profile} requires an explicit nFPM version and SHA-256 for native packages"
            );
        }
    }
    let mut schedule = Schedule {
        id: String::new(),
        schema: SCHEMA,
        config_id: config::id(config)?,
        plan_id: plan.id.clone(),
        source_commit: plan.source.commit.clone(),
        engine_source_id: plan.engine_source_id.clone(),
        jobs,
    };
    schedule.id = id(&schedule)?;
    Ok(schedule)
}

pub fn validate_delivery(
    root: &Path,
    config: &Config,
    plan: &delivery::model::Plan,
    schedule: &Schedule,
) -> Result<()> {
    ensure!(
        schedule == &create_delivery(root, config, plan)?,
        "CI schedule differs from trusted configuration, plan or source"
    );
    Ok(())
}

fn assignments(
    config: &Config,
    plan: &cohort::model::Plan,
) -> Result<BTreeMap<String, Vec<usize>>> {
    assign_builds(
        config,
        &plan.config,
        plan.units
            .iter()
            .map(|unit| (unit.product, unit.target, &unit.recipe)),
    )
}

fn assign_builds<'a>(
    config: &Config,
    release: &crate::v2::model::Config,
    builds: impl Iterator<Item = (usize, usize, &'a Recipe)>,
) -> Result<BTreeMap<String, Vec<usize>>> {
    for product in &release.products {
        match product.build {
            Builder::Rust { .. } => ensure!(
                config.coordinator.rust_version.is_some(),
                "coordinator requires an explicit rust-version to resolve Rust products"
            ),
            Builder::Go { .. } => ensure!(
                config.coordinator.go_version.is_some(),
                "coordinator requires an explicit go-version to resolve Go products"
            ),
        }
    }
    let configured: BTreeMap<_, _> = release
        .targets
        .iter()
        .map(|target| (target.key(), target))
        .collect();
    for worker in config.workers.values() {
        for key in &worker.targets {
            ensure!(
                configured.contains_key(key),
                "worker target is absent from release.toml: {key}"
            );
        }
    }
    let mut jobs = config
        .workers
        .keys()
        .map(|name| (name.clone(), Vec::new()))
        .collect::<BTreeMap<_, _>>();
    for (index, (product_index, target_index, recipe)) in builds.enumerate() {
        let target = release
            .targets
            .get(target_index)
            .context("unit has an unknown target")?;
        let key = target.key();
        let matching: Vec<_> = config
            .workers
            .iter()
            .filter(|(_, worker)| worker.targets.contains(&key))
            .collect();
        ensure!(
            matching.len() == 1,
            "each unit target must belong to exactly one worker profile: {key}"
        );
        let (profile, worker) = matching[0];
        ensure!(
            worker.runner.host == format!("{}-{}", target.os, target.arch),
            "worker profile {profile} cannot run target {key} natively"
        );
        let product = release
            .products
            .get(product_index)
            .context("unit has an unknown product")?;
        match &product.build {
            Builder::Rust { .. } => {
                ensure!(
                    worker.runner.rust_version.is_some(),
                    "worker profile {profile} requires an explicit rust-version"
                );
                ensure!(
                    recipe.compiler_target == config::rust_host(&worker.runner)?,
                    "worker profile {profile} requires a matching native rust-host and runner SDK for target {key}"
                );
            }
            Builder::Go { .. } => {
                ensure!(
                    worker.runner.go_version.is_some(),
                    "worker profile {profile} requires an explicit go-version"
                );
            }
        }
        jobs.get_mut(profile)
            .context("worker profile disappeared")?
            .push(index);
    }
    ensure!(
        !jobs.is_empty() && jobs.values().all(|units| !units.is_empty()),
        "every worker profile must map to at least one planned unit"
    );
    Ok(jobs)
}

/// Reconstruct protocol 5 ownership using canonical catalog IDs.
pub fn create_v5(root: &Path, config: &Config, plan: &crate::v5::model::Plan) -> Result<Schedule> {
    config::assert_current_engine(config)?;
    ensure!(
        config.execution_protocol == 5,
        "CI profile execution-protocol differs from plan protocol 5"
    );
    crate::v5::plan::validate_saved(root, plan)?;
    ensure!(
        plan.engine_source_id == config.engine.source_id,
        "plan engine differs from CI configuration"
    );
    for product in &plan.config.products {
        match product.build {
            Builder::Rust { .. } => ensure!(
                config.coordinator.rust_version.is_some(),
                "coordinator requires an explicit rust-version to resolve Rust products"
            ),
            Builder::Go { .. } => ensure!(
                config.coordinator.go_version.is_some(),
                "coordinator requires an explicit go-version to resolve Go products"
            ),
        }
    }
    let configured = plan
        .targets
        .iter()
        .map(|target| target.id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    let mut jobs = BTreeMap::new();
    for (profile, worker) in &config.workers {
        ensure!(
            worker
                .targets
                .iter()
                .all(|id| configured.contains(id.as_str())),
            "worker target is absent from release.toml"
        );
        let mut used_emulators = std::collections::BTreeSet::new();
        let mut used_rootfs = std::collections::BTreeSet::new();
        let mut builds = Vec::new();
        for (index, build) in plan.builds.iter().enumerate() {
            if !worker.targets.contains(&build.descriptor.id) {
                continue;
            }
            let selection = &plan.config.targets[build.target];
            match selection.runtime.mode {
                crate::v5::model::RuntimeMode::Native => {
                    let arch = match build.descriptor.arch.as_str() {
                        "armv6" | "armv7" => "arm",
                        "386" | "i686" => "x86",
                        value => value,
                    };
                    ensure!(
                        worker.runner.host == format!("{}-{arch}", build.descriptor.os),
                        "worker profile {profile} cannot run target {} natively",
                        build.descriptor.id
                    );
                }
                crate::v5::model::RuntimeMode::Emulated => {
                    let emulator = crate::v5::runtime::emulator_name(
                        selection
                            .runtime
                            .emulator
                            .context("missing runtime emulator")?,
                    );
                    ensure!(
                        worker.runner.emulators.contains_key(emulator),
                        "worker profile {profile} requires an explicit emulator path for {emulator}"
                    );
                    used_emulators.insert(emulator.to_owned());
                    if selection.runtime.rootfs_sha256.is_some() {
                        ensure!(
                            worker.runner.rootfs.contains_key(&selection.id),
                            "worker profile {profile} requires an explicit rootfs path for {}",
                            selection.id
                        );
                        used_rootfs.insert(selection.id.clone());
                    }
                }
            }
            match plan.config.products[build.product].build {
                Builder::Rust { .. } => ensure!(
                    worker.runner.rust_version.is_some(),
                    "worker profile {profile} requires an explicit rust-version"
                ),
                Builder::Go { .. } => ensure!(
                    worker.runner.go_version.is_some(),
                    "worker profile {profile} requires an explicit go-version"
                ),
            }
            builds.push(index);
        }
        ensure!(
            !builds.is_empty(),
            "every worker profile must map to at least one planned build"
        );
        ensure!(
            worker.runner.emulators.keys().eq(used_emulators.iter())
                && worker.runner.rootfs.keys().eq(used_rootfs.iter()),
            "worker runtime dependency maps differ from selected runtime constraints"
        );
        if plan
            .packages
            .iter()
            .any(|package| builds.contains(&package.build) && package.format.is_native())
        {
            ensure!(
                worker.runner.nfpm.is_some(),
                "worker profile {profile} requires an explicit nFPM version and SHA-256 for native packages"
            );
        }
        jobs.insert(profile.clone(), builds);
    }
    for index in 0..plan.builds.len() {
        ensure!(
            jobs.values()
                .filter(|builds| builds.contains(&index))
                .count()
                == 1,
            "each build must belong to exactly one worker profile"
        );
    }
    let mut schedule = Schedule {
        id: String::new(),
        schema: SCHEMA,
        config_id: config::id(config)?,
        plan_id: plan.id.clone(),
        source_commit: plan.source.commit.clone(),
        engine_source_id: plan.engine_source_id.clone(),
        jobs,
    };
    schedule.id = id(&schedule)?;
    Ok(schedule)
}

pub fn validate_v5(
    root: &Path,
    config: &Config,
    plan: &crate::v5::model::Plan,
    schedule: &Schedule,
) -> Result<()> {
    ensure!(
        schedule == &create_v5(root, config, plan)?,
        "CI schedule differs from trusted configuration, plan or source"
    );
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::v2::model::{self, Product, Target};
    use std::{fs, path::PathBuf, process::Command};

    fn checked(root: &Path, args: &[&str]) {
        let output = Command::new(args[0])
            .args(&args[1..])
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    pub(crate) fn fixture() -> (tempfile::TempDir, PathBuf, Config, cohort::model::Plan) {
        let temp = tempfile::Builder::new()
            .prefix("kit-ci-schedule-")
            .tempdir_in("/tmp")
            .unwrap();
        let root = temp.path().canonicalize().unwrap().join("consumer");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join(".gitignore"), "/target/\n").unwrap();
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"bird\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(
            root.join("src/main.rs"),
            "fn main() { println!(\"bird 0.1.0\"); }\n",
        )
        .unwrap();
        let target = crate::v2::builder::native_target_at(&root, "rust").unwrap();
        let release = model::Config {
            schema: 2,
            timeout_seconds: 120,
            targets: vec![target.clone()],
            products: vec![Product {
                id: "bird".into(),
                directory: ".".into(),
                binaries: vec!["bird".into()],
                build: Builder::Rust {
                    package: "bird".into(),
                    manifest: "Cargo.toml".into(),
                    features: vec![],
                    default_features: true,
                },
                targets: vec![target.key()],
                assets: vec![],
                prepare: vec![],
                checks: vec![],
                version_args: vec!["--version".into()],
                version_binaries: None,
            }],
        };
        fs::write(
            root.join("release.toml"),
            toml::to_string(&release).unwrap(),
        )
        .unwrap();
        checked(&root, &["cargo", "generate-lockfile", "--offline"]);
        checked(&root, &["git", "init", "-q"]);
        checked(&root, &["git", "add", "--all"]);
        checked(
            &root,
            &[
                "git",
                "-c",
                "user.name=fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-qm",
                "fixture",
            ],
        );
        let mut config = config::tests::example();
        let runner_host = format!("{}-{}", target.os, target.arch);
        let install = config.installs.values().next().unwrap().clone();
        config.installs = BTreeMap::from([(runner_host.clone(), install)]);
        config.coordinator.host = runner_host.clone();
        let worker = config.workers.get_mut("native").unwrap();
        worker.runner.host = runner_host;
        worker.runner.rust_host = Some(crate::plan::host(&root).unwrap());
        worker.targets = vec![target.key()];
        let plan = cohort::plan::create(&root).unwrap();
        (temp, root, config, plan)
    }

    #[test]
    fn rehashed_schedule_tampering_cannot_change_job_authority() {
        let (_temp, root, config, plan) = fixture();
        let schedule = create(&root, &config, &plan).unwrap();
        validate(&root, &config, &plan, &schedule).unwrap();
        let mut attacks = Vec::new();
        let mut attack = schedule.clone();
        attack.jobs.get_mut("native").unwrap().clear();
        attacks.push(attack);
        let mut attack = schedule.clone();
        attack.jobs.get_mut("native").unwrap().push(0);
        attacks.push(attack);
        let mut attack = schedule.clone();
        attack.jobs.insert("native".into(), vec![1]);
        attacks.push(attack);
        let mut attack = schedule.clone();
        attack.jobs.insert("injected".into(), vec![0]);
        attacks.push(attack);
        let mut attack = schedule.clone();
        attack.config_id = "c".repeat(64);
        attacks.push(attack);
        let mut attack = schedule.clone();
        attack.plan_id = "d".repeat(64);
        attacks.push(attack);
        let mut attack = schedule.clone();
        attack.source_commit = "e".repeat(40);
        attacks.push(attack);
        for mut attack in attacks {
            attack.id = id(&attack).unwrap();
            assert!(validate(&root, &config, &plan, &attack).is_err());
        }
        let mut changed_config = config.clone();
        changed_config.trusted.branch = "another-branch".into();
        assert!(validate(&root, &changed_config, &plan, &schedule).is_err());
        let mut changed_plan = plan.clone();
        changed_plan.tasks.clear();
        changed_plan.id = cohort::plan::id(&changed_plan).unwrap();
        assert!(create(&root, &config, &changed_plan).is_err());
    }

    #[test]
    fn profiles_cannot_drop_targets_or_select_the_wrong_native_abi() {
        let (_temp, root, mut config, plan) = fixture();
        let missing = if plan.config.targets[0].key() == "linux-aarch64-musl" {
            "macos-x86_64"
        } else {
            "linux-aarch64-musl"
        };
        config.workers.get_mut("native").unwrap().targets = vec![missing.into()];
        assert!(create(&root, &config, &plan).is_err());
        let target = &plan.config.targets[0];
        config.workers.get_mut("native").unwrap().targets = vec![target.key()];
        let worker = config.workers.get("native").unwrap().clone();
        config.workers.insert("extra".into(), worker);
        assert!(create(&root, &config, &plan).is_err());
        config.workers.remove("extra");
        let mut spare_plan = plan.clone();
        let spare = Target {
            os: "linux".into(),
            arch: "aarch64".into(),
            abi: Some("musl".into()),
        };
        spare_plan.config.targets.push(spare.clone());
        let mut extra = config.workers["native"].clone();
        extra.targets = vec![spare.key()];
        config.workers.insert("extra".into(), extra);
        assert!(assignments(&config, &spare_plan).is_err());
        config.workers.remove("extra");
        let mut musl_plan = plan.clone();
        musl_plan.config.targets[0] = Target {
            os: "linux".into(),
            arch: "x86_64".into(),
            abi: Some("musl".into()),
        };
        musl_plan.units[0].recipe.compiler_target = "x86_64-unknown-linux-musl".into();
        let worker = config.workers.get_mut("native").unwrap();
        worker.runner.host = "linux-x86_64".into();
        worker.runner.rust_host = None;
        worker.targets = vec!["linux-x86_64-musl".into()];
        assert!(assignments(&config, &musl_plan).is_err());
        config.workers.get_mut("native").unwrap().runner.rust_host =
            Some("x86_64-unknown-linux-musl".into());
        assert_eq!(assignments(&config, &musl_plan).unwrap()["native"], vec![0]);
        config
            .workers
            .get_mut("native")
            .unwrap()
            .runner
            .rust_version = None;
        assert!(assignments(&config, &musl_plan).is_err());
    }
}
