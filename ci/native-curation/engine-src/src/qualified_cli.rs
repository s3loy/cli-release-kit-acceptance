use super::{Command, config_schema, json_schema, write_new_json};
use anyhow::{Context, Result, ensure};
use qualified::model::{Builder, Compatibility, Config, Product};
use relship::{
    catalog, cmake, compatibility, process, qualified, settings::Snapshot, source, v2, v5,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub(super) fn supports(root: &Path, command: &Command) -> Result<bool> {
    Ok(match command {
        Command::Init {
            schema,
            builder,
            directory,
            ..
        } => {
            if *schema == Some(5) || builder.as_deref() == Some("cmake") {
                true
            } else if schema.is_none() && builder.is_none() {
                let directory = if directory == "." {
                    root.to_path_buf()
                } else {
                    relship::config::safe_join(root, directory)?
                };
                directory.join("CMakeLists.txt").is_file()
                    && !directory.join("Cargo.toml").is_file()
                    && !directory.join("go.mod").is_file()
            } else {
                false
            }
        }
        Command::Migrate { schema, .. } => *schema == 5,
        Command::Targets { builder, .. } => builder.as_deref() == Some("cmake"),
        Command::Doctor => config_schema(root)? == 5,
        Command::Plan { protocol, .. } => *protocol == Some(6) || config_schema(root)? == 5,
        Command::Rehearse { plan, .. }
        | Command::Assign { plan, .. }
        | Command::Worker { plan, .. }
        | Command::Import { plan, .. }
        | Command::Rebuild { plan, .. }
        | Command::Merge { plan, .. } => json_schema(plan)? == 6,
        Command::Status { output, .. } => json_schema(&output.join("receipt.json"))? == 6,
        Command::Resume { output, .. }
        | Command::Export {
            attempt: output, ..
        }
        | Command::Verify { output, .. } => json_schema(&output.join("plan.json"))? == 6,
        _ => false,
    })
}

pub(super) fn from_existing(product: relship::delivery::model::Product) -> Product {
    Product {
        id: product.id,
        directory: product.directory,
        binaries: product.binaries,
        build: Builder::Existing(product.build),
        targets: product.targets,
        assets: product.assets,
        prepare: product.prepare,
        checks: product.checks,
        version_args: product.version_args,
        version_binaries: product.version_binaries,
        inputs: vec![],
        packaging: product.packaging,
    }
}

fn tracked_inputs(root: &Path) -> Result<BTreeMap<String, String>> {
    source::git(root, &["ls-files", "-z"])?
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|name| {
            relship::config::relative(name)?;
            let path = match name.rsplit_once('/') {
                Some((parent, leaf)) => relship::config::safe_join(root, parent)?.join(leaf),
                None => root.join(name),
            };
            let digest = if fs::symlink_metadata(&path)?.file_type().is_symlink() {
                source::digest(
                    fs::read_link(&path)?
                        .to_str()
                        .context("non-UTF8 tracked source link")?
                        .as_bytes(),
                )
            } else {
                source::file_digest(&relship::config::safe_join(root, name)?)?
            };
            Ok((name.to_owned(), digest))
        })
        .collect()
}

fn host_target(kind: &str) -> Result<String> {
    let os = std::env::consts::OS;
    let os = if os == "macos" { "macos" } else { os };
    let arch = compatibility::Architecture::parse(std::env::consts::ARCH)?.name();
    Ok(match os {
        "linux" if kind == "go" => format!("linux-{arch}"),
        "linux" => format!("linux-{arch}-gnu"),
        "macos" => format!("macos-{arch}"),
        "windows" if kind == "go" => format!("windows-{arch}"),
        "windows" => format!("windows-{arch}-msvc"),
        _ => anyhow::bail!("this host has no qualified native target"),
    })
}

pub(super) fn initialization_proposal(
    root: &Path,
    directory: &str,
    kind: &str,
    version: Option<&str>,
    mappings: &[String],
    configure_preset: Option<&str>,
    generator: Option<&str>,
) -> Result<Config> {
    let path = relship::config::safe_join(root, "release.toml")?;
    ensure!(!path.exists(), "release.toml already exists");
    let products = if kind == "cmake" {
        let version=version.context("CMake initialization requires --app-version; the CMake tool version is not an application version")?;
        ensure!(
            !mappings.is_empty(),
            "CMake initialization requires --cmake-target BINARY=TARGET; target discovery never runs during planning"
        );
        let binary_targets = mappings
            .iter()
            .map(|mapping| {
                let (binary, target) = mapping
                    .split_once('=')
                    .context("CMake target mapping must be BINARY=TARGET")?;
                Ok(cmake::BinaryTarget {
                    binary: binary.into(),
                    target: target.into(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let spec = cmake::Spec {
            version: version.into(),
            configuration: "Release".into(),
            configure_preset: configure_preset.map(str::to_owned),
            generator: generator.map(str::to_owned),
            binary_targets,
            cache_variables: BTreeMap::new(),
        };
        cmake::source_inputs(root, directory, &spec, &tracked_inputs(root)?)?;
        let binaries = spec
            .binary_targets
            .iter()
            .map(|m| m.binary.clone())
            .collect::<Vec<_>>();
        let id = if binaries.len() == 1 {
            binaries[0].clone()
        } else {
            let project = if directory == "." {
                root
            } else {
                Path::new(directory)
            };
            project
                .file_name()
                .and_then(|s| s.to_str())
                .filter(|s| relship::config::identifier(s).is_ok())
                .context("CMake project directory needs a portable product identifier")?
                .to_owned()
        };
        vec![Product {
            id,
            directory: directory.into(),
            binaries,
            build: Builder::Cmake(spec),
            targets: vec![],
            assets: vec![],
            prepare: vec![],
            checks: vec![],
            version_args: vec!["--version".into()],
            version_binaries: None,
            inputs: vec![],
            packaging: Default::default(),
        }]
    } else {
        ensure!(
            mappings.is_empty() && configure_preset.is_none() && generator.is_none(),
            "CMake options require --builder cmake"
        );
        v2::builder::discover(root, directory, kind, version)?
            .into_iter()
            .map(relship::delivery::model::Product::from_base)
            .map(from_existing)
            .collect()
    };
    let config = Config {
        schema: 5,
        targets: vec![host_target(kind)?],
        products,
        packaging: Default::default(),
        compatibility: Compatibility::default(),
        timeout_seconds: 2400,
    };
    qualified::config::validate(&config)?;
    Ok(config)
}

pub(super) fn initialize(
    root: &Path,
    directory: &str,
    kind: &str,
    version: Option<&str>,
    mappings: &[String],
    configure_preset: Option<&str>,
    generator: Option<&str>,
) -> Result<PathBuf> {
    let config = initialization_proposal(
        root,
        directory,
        kind,
        version,
        mappings,
        configure_preset,
        generator,
    )?;
    let path = relship::config::safe_join(root, "release.toml")?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    output.write_all(toml::to_string_pretty(&config)?.as_bytes())?;
    output.sync_all()?;
    Ok(path)
}

pub(super) fn migration_proposal(root: &Path) -> Result<v5::migrate::MigrationProposal> {
    let snapshot = Snapshot::load(root)?;
    let original = snapshot.text();
    let old:v5::model::Config=toml::from_str(original).context("schema 5 migration currently requires schema 4; migrate older configurations explicitly to schema 4 first")?;
    v5::config::validate(&old)?;
    ensure!(
        old.targets
            .iter()
            .all(|t| t.runtime == v5::model::RuntimeConstraint::default()),
        "schema 5 native qualification cannot preserve controlled-emulator/runtime constraints; review those targets before migrating"
    );
    let config = Config {
        schema: 5,
        targets: old.targets.into_iter().map(|t| t.id).collect(),
        products: old.products.into_iter().map(from_existing).collect(),
        packaging: old.packaging,
        compatibility: Compatibility::default(),
        timeout_seconds: old.timeout_seconds,
    };
    qualified::config::validate(&config)?;
    let mut doc = original.parse::<toml_edit::DocumentMut>()?;
    doc["schema"] = toml_edit::value(5);
    let mut targets = toml_edit::Array::new();
    for target in &config.targets {
        targets.push(target.as_str());
    }
    doc["targets"] = toml_edit::value(targets);
    // Schema 4's omitted timeout is 1200; schema 5 defaults to 2400.
    // Preserve the effective old value explicitly rather than changing behavior.
    if !doc.contains_key("timeout-seconds") {
        doc["timeout-seconds"] = toml_edit::value(i64::try_from(config.timeout_seconds)?);
    }
    doc["compatibility"]["linux"]["policy"] = toml_edit::value("broad");
    let proposed = doc.to_string();
    ensure!(
        qualified::config::parse(&proposed)? == config,
        "migration proposal differs from reviewed qualified contract"
    );
    Ok(v5::migrate::MigrationProposal{from_schema:4,to_schema:5,original:original.into(),proposed,warnings:vec![
        "This explicit upgrade selects Linux broad compatibility: glibc 2.17 build inputs plus independent final-package checks in each required runtime.".into(),
        "macOS and Windows planning requires reviewed native SDK environments in release-ci.toml; existing runner labels do not establish SDK identity.".into(),
        "Existing schema 4 plans and receipts retain their original execution contract.".into(),
    ]})
}

pub(super) fn apply_migration(
    root: &Path,
    proposal: &v5::migrate::MigrationProposal,
) -> Result<PathBuf> {
    let snapshot = Snapshot::load(root)?;
    ensure!(
        snapshot.text() == proposal.original,
        "release.toml changed after migration review"
    );
    ensure!(
        migration_proposal(root)? == *proposal,
        "migration proposal differs from canonical conversion"
    );
    let backup = relship::config::safe_join(root, "release.toml.schema-4.backup")?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&backup)
        .context("schema 4 backup already exists or cannot be created")?;
    output.write_all(proposal.original.as_bytes())?;
    output.sync_all()?;
    snapshot.save(&proposal.proposed, |candidate| {
        qualified::config::parse(candidate)?;
        Ok(())
    })?;
    Ok(snapshot.path().to_path_buf())
}

fn choose_kind(root: &Path, directory: &str, requested: Option<&str>) -> Result<String> {
    if let Some(kind) = requested {
        return Ok(kind.into());
    }
    let directory = if directory == "." {
        root.to_path_buf()
    } else {
        relship::config::safe_join(root, directory)?
    };
    let kinds = [
        ("rust", "Cargo.toml"),
        ("go", "go.mod"),
        ("cmake", "CMakeLists.txt"),
    ]
    .into_iter()
    .filter(|(_, file)| directory.join(file).is_file())
    .map(|(kind, _)| kind)
    .collect::<Vec<_>>();
    ensure!(
        kinds.len() == 1,
        "select --builder rust, go or cmake for this directory"
    );
    Ok(kinds[0].into())
}

pub(super) fn compatibility_summary(config: &Config) -> Result<()> {
    println!(
        "Linux policy: broad — glibc 2.17 build baseline; final artifacts require ABI/closure checks and every applicable runtime/package validation."
    );
    println!(
        "Windows CRT: {}; imported CRT DLLs require app-local delivery from reviewed SDK provider and license pins.",
        match config.compatibility.windows.crt {
            compatibility::windows_crt::WindowsRuntimeMode::FollowProject => "follow-project",
            compatibility::windows_crt::WindowsRuntimeMode::Static => "static",
            compatibility::windows_crt::WindowsRuntimeMode::Dynamic => "dynamic",
        }
    );
    for (index, product) in config.products.iter().enumerate() {
        for target in config
            .targets
            .iter()
            .filter(|id| product.targets.is_empty() || product.targets.contains(id))
        {
            let descriptor = qualified::plan::descriptor(target, &product.build)?;
            println!(
                "  {}@{}: native {}; packages {}",
                product.id,
                target,
                descriptor.arch,
                qualified::config::formats(config, index, &descriptor.os)
                    .iter()
                    .map(|f| f.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    println!(
        "macOS/Windows require reviewed SDK pins in release-ci.toml.environments. Configuration selection alone is not platform acceptance."
    );
    Ok(())
}

pub(super) fn doctor(root: &Path) -> Result<serde_json::Value> {
    let config = qualified::config::load(root)?;
    let mut probes = BTreeMap::new();
    let existing = config
        .products
        .iter()
        .filter(|p| matches!(p.build, Builder::Existing(_)))
        .map(|p| p.legacy())
        .collect::<Vec<_>>();
    for (key, spec) in v2::builder::probes(&existing) {
        let cwd = if spec.cwd == "." {
            root.to_path_buf()
        } else {
            relship::config::safe_join(root, &spec.cwd)?
        };
        probes.insert(
            key,
            match process::capture_spec(&cwd, &spec.argv, &spec.env, 60) {
                Ok(output) => serde_json::json!({"available":true,"output":output}),
                Err(error) => serde_json::json!({"available":false,"error":format!("{error:#}")}),
            },
        );
    }
    if config
        .products
        .iter()
        .any(|p| matches!(p.build, Builder::Cmake(_)))
    {
        probes.insert(
            "cmake".into(),
            match process::capture(root, &["cmake".into(), "--version".into()], 30) {
                Ok(output) => serde_json::json!({"available":true,"output":output}),
                Err(error) => serde_json::json!({"available":false,"error":format!("{error:#}")}),
            },
        );
    }
    let ci_path = relship::config::safe_join(root, "release-ci.toml")?;
    let ci = if ci_path.exists() {
        Some(toml::from_str::<relship::ci::model::Config>(
            &fs::read_to_string(ci_path)?,
        )?)
    } else {
        None
    };
    let mut environments = BTreeMap::new();
    for product in &config.products {
        for id in config
            .targets
            .iter()
            .filter(|id| product.targets.is_empty() || product.targets.contains(id))
        {
            let target = qualified::plan::descriptor(id, &product.build)?;
            let host = format!("{}-{}", target.os, target.arch);
            let observed = if let Some(profile) = ci
                .as_ref()
                .and_then(|c| c.environments.get(id).or_else(|| c.environments.get(&host)))
            {
                profile.validate().map(|_| profile.clone())
            } else if target.os == "linux" {
                compatibility::Profile::linux_glibc217(compatibility::Architecture::parse(
                    &target.arch,
                )?)
            } else {
                Err(anyhow::anyhow!(
                    "native SDK is not pinned for {id}; configure release-ci.toml.environments.{id}"
                ))
            };
            environments.insert(
                format!("{}@{id}", product.id),
                match observed {
                    Ok(profile) => {
                        serde_json::json!({"configured":true,"profile":profile,"qualified":false})
                    }
                    Err(error) => {
                        serde_json::json!({"configured":false,"blocker":format!("{error:#}")})
                    }
                },
            );
        }
    }
    Ok(
        serde_json::json!({"schema":5,"execution_protocols":[6],"targets":config.targets,"compatibility":config.compatibility,"toolchain":probes,"environments":environments,"publication_ready":false}),
    )
}

fn selected_builds(plan: &qualified::model::Plan, names: &[String]) -> Result<Vec<usize>> {
    let mut selected = BTreeSet::new();
    for name in names {
        let candidates = plan
            .builds
            .iter()
            .enumerate()
            .filter(|(_, build)| {
                *name == build.id
                    || *name
                        == format!(
                            "{}@{}",
                            plan.config.products[build.product].id, build.target
                        )
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        ensure!(
            candidates.len() == 1,
            "unknown or ambiguous qualified build unit: {name}"
        );
        ensure!(
            selected.insert(candidates[0]),
            "duplicate build unit selection"
        );
    }
    Ok(selected.into_iter().collect())
}

pub(super) fn run(root: &Path, command: Command) -> Result<()> {
    match command {
        Command::Init {
            builder,
            directory,
            app_version,
            cmake_target,
            configure_preset,
            generator,
            schema,
        } => {
            ensure!(
                schema.is_none_or(|v| v == 5),
                "CMake/environment-qualified initialization requires schema 5"
            );
            let kind = choose_kind(root, &directory, builder.as_deref())?;
            let path = initialize(
                root,
                &directory,
                &kind,
                app_version.as_deref(),
                &cmake_target,
                configure_preset.as_deref(),
                generator.as_deref(),
            )?;
            println!(
                "created {}; review source version, explicit targets and environment pins before committing the schema 5 contract",
                path.display()
            );
            compatibility_summary(&qualified::config::load(root)?)?;
        }
        Command::Targets { builder: _, json } => {
            let targets = catalog::all()
                .into_iter()
                .filter(|t| {
                    matches!(t.arch.as_str(), "x86_64" | "aarch64")
                        && ((t.os == "linux" && t.libc == "glibc")
                            || t.os == "macos"
                            || (t.os == "windows" && t.c_abi == "msvc"))
                })
                .collect::<Vec<_>>();
            if json {
                println!("{}", serde_json::to_string_pretty(&targets)?);
            } else {
                for target in targets {
                    println!(
                        "{} — CMake C / {} / {} / {}",
                        target.id, target.os, target.arch, target.c_abi
                    );
                }
                println!(
                    "Linux broad compatibility uses glibc 2.17; SDK pins and final-package acceptance remain required."
                );
            }
        }
        Command::Migrate { schema: _, apply } => {
            let proposal = migration_proposal(root)?;
            println!("Configuration upgrade: schema 4 -> 5");
            for warning in &proposal.warnings {
                println!("{warning}");
            }
            println!(
                "--- current\n{}\n--- proposed\n{}",
                proposal.original, proposal.proposed
            );
            if apply {
                println!(
                    "saved {}; review and commit before planning",
                    apply_migration(root, &proposal)?.display()
                );
            } else {
                println!(
                    "Review only; use migrate --schema 5 --apply to save this explicit upgrade."
                );
            }
        }
        Command::Doctor => println!("{}", serde_json::to_string_pretty(&doctor(root)?)?),
        Command::Plan { protocol, output } => {
            ensure!(
                protocol.is_none_or(|v| v == 6),
                "schema 5 requires execution protocol 6"
            );
            let plan = qualified::plan::create(root)?;
            if let Some(output) = output {
                write_new_json(root, &output, &plan)?;
                println!("saved protocol 6 plan {} to {}", plan.id, output.display());
            } else {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            }
        }
        Command::Rehearse {
            plan,
            output,
            skip_runtime,
            nfpm,
            runtime,
        } => {
            ensure!(
                !skip_runtime,
                "protocol 6 requires its planned runtime validations; build-only bypass is unsupported"
            );
            ensure!(
                runtime.emulators.is_empty() && runtime.rootfs.is_empty(),
                "protocol 6 uses planned environment profiles; emulator/rootfs overrides belong to legacy protocol 5"
            );
            let plan = qualified::plan::load(&plan)?;
            let selected = (0..plan.builds.len()).collect::<Vec<_>>();
            let receipt =
                qualified::run::execute(root, &plan, &output, &selected, false, nfpm.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        Command::Status { output, json } => {
            let receipt = qualified::run::status(&output)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&receipt)?);
            } else {
                println!(
                    "{}: {} ({} payloads, {} packages, {} independent validations)",
                    receipt.plan_id,
                    if receipt.complete {
                        "complete"
                    } else {
                        "incomplete"
                    },
                    receipt.payloads.len(),
                    receipt.packages.len(),
                    receipt.validations.len()
                );
                for failure in receipt.failures {
                    println!("{}: {}", failure.stage, failure.message);
                }
            }
        }
        Command::Verify { output, policy } => {
            ensure!(
                policy.is_none(),
                "protocol 6 attempt verification does not consume a worker merge policy"
            );
            let receipt = qualified::run::verify(&output, true)?;
            println!(
                "verified protocol 6 preparation {}: {} packages and {} independent validations; publication_ready={}",
                receipt.plan_id,
                receipt.packages.len(),
                receipt.validations.len(),
                receipt.publication_ready
            );
        }
        Command::Resume {
            output,
            allow_retry,
            key,
            nfpm,
            runtime,
        } => {
            ensure!(
                key.is_none() && runtime.emulators.is_empty() && runtime.rootfs.is_empty(),
                "protocol 6 resume uses saved environment pins and does not accept legacy signing/emulator overrides"
            );
            let plan = qualified::plan::load(&output.join("plan.json"))?;
            let selected = qualified::run::verify(&output, false)?.selected;
            let retry = selected_builds(&plan, &allow_retry)?;
            ensure!(
                retry.iter().all(|index| selected.contains(index)),
                "retry permission includes a build outside the saved attempt selection"
            );
            let receipt = qualified::run::execute_with_retry(
                root,
                &plan,
                &output,
                &selected,
                true,
                nfpm.as_deref(),
                &retry,
            )?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        Command::Export { attempt, output } => {
            qualified::run::export(&attempt, &output)?;
            println!(
                "exported protocol 6 preparation evidence to {}",
                output.display()
            );
        }
        _ => anyhow::bail!(
            "this operation is unavailable for protocol 6; use plan/rehearse/status/verify/resume/export with the saved qualified contract"
        ),
    }
    Ok(())
}
