use super::{Command, RuntimeArgs, RuntimeCommand, config_schema, json_schema, v5, write_new_json};
use anyhow::{Context, Result, ensure};
use relship::{catalog, cohort, process, v2};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

pub(super) fn supports(root: &Path, command: &Command) -> Result<bool> {
    Ok(match command {
        Command::Targets { .. } | Command::Runtime { .. } | Command::Migrate { .. } => true,
        Command::Init {
            schema: Some(4), ..
        } => true,
        Command::Doctor => config_schema(root)? == 4,
        Command::Plan { protocol, .. } => *protocol == Some(5) || config_schema(root)? == 4,
        Command::Rehearse { plan, .. }
        | Command::Assign { plan, .. }
        | Command::Worker { plan, .. }
        | Command::Import { plan, .. }
        | Command::Rebuild { plan, .. }
        | Command::Merge { plan, .. } => json_schema(plan)? == 5,
        Command::Status { output, .. } => json_schema(&output.join("receipt.json"))? == 5,
        Command::Resume { output, .. }
        | Command::Export {
            attempt: output, ..
        } => json_schema(&output.join("plan.json"))? == 5,
        Command::Verify { output, .. } => {
            let file = if output.join("collection.json").exists() {
                "collection.json"
            } else {
                "plan.json"
            };
            json_schema(&output.join(file))? == 5
        }
        _ => false,
    })
}

pub(super) fn select_builds(plan: &v5::model::Plan, names: &[String]) -> Result<Vec<usize>> {
    if names.is_empty() {
        return Ok((0..plan.builds.len()).collect());
    }
    let mut selected = BTreeSet::new();
    for name in names {
        let matches: Vec<_> = plan
            .builds
            .iter()
            .enumerate()
            .filter(|(_, build)| {
                let product = &plan.config.products[build.product];
                let target = &plan.config.targets[build.target];
                *name == build.id || *name == format!("{}@{}", product.id, target.id)
            })
            .map(|(index, _)| index)
            .collect();
        ensure!(
            matches.len() == 1,
            "unknown or ambiguous build unit: {name}"
        );
        ensure!(
            selected.insert(matches[0]),
            "duplicate build unit selection: {name}"
        );
    }
    Ok(selected.into_iter().collect())
}

fn retry_builds(plan: &v5::model::Plan, names: &[String]) -> Result<Vec<usize>> {
    if names.is_empty() {
        Ok(Vec::new())
    } else {
        select_builds(plan, names)
    }
}

pub(super) fn export_default(root: &Path, output: &Path) -> Result<()> {
    let plan = v5::plan::load(&output.join("plan.json"))?;
    let result = output.join("result");
    if result.exists() {
        v5::bundle::validate(root, &plan, &result)?;
    } else {
        v5::bundle::export_run(root, output, &result)?;
    }
    Ok(())
}

pub(super) fn run(root: &Path, command: Command) -> Result<()> {
    match command {
        Command::Init {
            builder,
            directory,
            app_version,
            ..
        } => {
            let kind = match builder.as_deref() {
                Some(kind) => kind,
                None => match (
                    root.join(&directory).join("Cargo.toml").is_file(),
                    root.join(&directory).join("go.mod").is_file(),
                ) {
                    (true, false) => "rust",
                    (false, true) => "go",
                    _ => anyhow::bail!("select --builder rust or go for this directory"),
                },
            };
            let path = v5::plan::initialize(root, &directory, kind, app_version.as_deref())?;
            println!(
                "created {}; review and commit the schema 4 contract",
                path.display()
            );
        }
        Command::Targets { builder, json } => show_catalog(builder.as_deref(), json)?,
        Command::Runtime {
            command:
                RuntimeCommand::Inspect {
                    emulator,
                    rootfs,
                    json,
                },
        } => {
            let observed = v5::runtime::inspect(&emulator, rootfs.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&observed)?);
            } else {
                println!("Emulator SHA256: {}", observed.emulator_sha256);
                println!("Emulator: {}", observed.emulator_version.trim());
                if let Some(rootfs) = observed.rootfs_sha256 {
                    println!("Rootfs SHA256: {rootfs}");
                }
            }
        }
        Command::Migrate { schema: _, apply } => {
            let proposal = v5::migrate::propose(root)?;
            println!(
                "Configuration upgrade: schema {} -> {}",
                proposal.from_schema, proposal.to_schema
            );
            for warning in &proposal.warnings {
                println!("{warning}");
            }
            println!(
                "--- current\n{}\n--- proposed\n{}",
                proposal.original, proposal.proposed
            );
            if apply {
                let path = v5::migrate::apply(root, &proposal)?;
                println!(
                    "saved {}; review and commit configuration before planning",
                    path.display()
                );
            } else {
                println!(
                    "Review only; use migrate --schema 4 --apply to save this explicit upgrade."
                );
            }
        }
        Command::Doctor => {
            let config = v5::config::load(root)?;
            v5::config::validate_build_environment(&config)?;
            let products = config.products.iter().map(|p| p.base()).collect::<Vec<_>>();
            let mut tools = std::collections::BTreeMap::new();
            for (key, spec) in v2::builder::probes(&products) {
                let cwd = if spec.cwd == "." {
                    root.to_path_buf()
                } else {
                    relship::config::safe_join(root, &spec.cwd)?
                };
                tools.insert(key, process::capture_spec(&cwd, &spec.argv, &spec.env, 60)?);
            }
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"schema":4,"execution_protocols":[5],"targets":config.targets,"toolchain":tools,"publication_ready":false})
                )?
            );
        }
        Command::Plan { protocol, output } => {
            ensure!(
                protocol.is_none_or(|value| value == 5),
                "schema 4 requires execution protocol 5"
            );
            let plan = v5::plan::create(root)?;
            if let Some(output) = output {
                write_new_json(root, &output, &plan)?;
                println!("saved protocol 5 plan {} to {}", plan.id, output.display());
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
            let plan = v5::plan::load(&plan)?;
            let assignment = v5::run::assignment(
                &plan,
                &v5::run::RunOptions {
                    skip_runtime,
                    ..Default::default()
                },
            )?;
            let tools = runtime_tools(&runtime)?;
            let receipt = v5::run::execute(
                root,
                &plan,
                &assignment,
                &output,
                false,
                &[],
                None,
                nfpm.as_deref(),
                &tools,
            )?;
            export_default(root, &output)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        Command::Assign {
            plan,
            units,
            retry_safe,
            skip_runtime,
            output,
        } => {
            let plan = v5::plan::load(&plan)?;
            v5::plan::validate_saved(root, &plan)?;
            let assignment = v5::run::assignment(
                &plan,
                &v5::run::RunOptions {
                    units: select_builds(&plan, &units)?,
                    retry_safe_units: retry_builds(&plan, &retry_safe)?,
                    skip_runtime,
                    ..Default::default()
                },
            )?;
            write_new_json(root, &output, &assignment)?;
            println!(
                "assigned {}: {} builds",
                assignment.id,
                assignment.units.len()
            );
        }
        Command::Worker {
            plan,
            assignment,
            output,
            nfpm,
            runtime,
        } => {
            let plan = v5::plan::load(&plan)?;
            let assignment = cohort::io::read_json(&assignment)?;
            let tools = runtime_tools(&runtime)?;
            let receipt = v5::run::execute(
                root,
                &plan,
                &assignment,
                &output,
                false,
                &[],
                None,
                nfpm.as_deref(),
                &tools,
            )?;
            export_default(root, &output)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        Command::Resume {
            output,
            allow_retry,
            key,
            nfpm,
            runtime,
        } => {
            let plan = v5::plan::load(&output.join("plan.json"))?;
            let assignment = cohort::io::read_json(&output.join("assignment.json"))?;
            v5::plan::validate_saved(root, &plan)?;
            v5::run::validate_assignment(&plan, &assignment)?;
            let retry = retry_builds(&plan, &allow_retry)?;
            let key = key.as_deref().map(cohort::crypto::load_key).transpose()?;
            let tools = runtime_tools(&runtime)?;
            let receipt = v5::run::execute(
                root,
                &plan,
                &assignment,
                &output,
                true,
                &retry,
                key.as_ref(),
                nfpm.as_deref(),
                &tools,
            )?;
            export_default(root, &output)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        Command::Status { output, json } => {
            let receipt = v5::run::status(&output)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&receipt)?);
            } else {
                println!(
                    "{}: last recorded {} ({} payloads, {} packages; updated {} ms since Unix epoch)",
                    receipt.plan_id,
                    receipt.status,
                    receipt.payloads.len(),
                    receipt.packages.len(),
                    receipt.updated_at_ms
                );
                if receipt.finished_at_ms.is_none() {
                    println!("Unfinished snapshot; process liveness is not inferred.");
                }
                if let Some(error) = receipt.error {
                    println!("{error}");
                }
            }
        }
        Command::Verify { output, policy } => {
            if output.join("collection.json").is_file() {
                let policy = load_policy(
                    policy
                        .as_deref()
                        .context("collection verification requires --policy")?,
                )?;
                let collection = v5::bundle::verify_collection(root, &output, &policy)?;
                println!(
                    "verified delivery collection {}: {} policy-authorized packages (not published)",
                    collection.id,
                    collection.selections.len()
                );
            } else {
                let receipt = v5::run::verify_run(root, &output)?;
                println!(
                    "checked protocol 5 preparation {}: {} payloads and {} packages (trust requires merge policy)",
                    receipt.plan_id,
                    receipt.payloads.len(),
                    receipt.packages.len()
                );
            }
        }
        Command::Export { attempt, output } => {
            let bundle = v5::bundle::export_run(root, &attempt, &output)?;
            println!("exported delivery bundle {}", bundle.id);
        }
        Command::Import {
            plan,
            bundle,
            output,
        } => {
            let plan = v5::plan::load(&plan)?;
            let bundle = v5::bundle::import_candidate(root, &plan, &bundle, &output)?;
            println!(
                "imported candidate {} as data; trusted rebuild required",
                bundle.id
            );
        }
        Command::Rebuild {
            plan,
            units,
            retry_safe,
            candidate,
            key,
            skip_runtime,
            output,
            nfpm,
            runtime,
        } => {
            let plan = v5::plan::load(&plan)?;
            v5::plan::validate_saved(root, &plan)?;
            let candidate = candidate
                .as_deref()
                .map(|path| v5::bundle::candidate_ref(root, &plan, path))
                .transpose()?;
            let units = if units.is_empty() {
                candidate
                    .as_ref()
                    .map(|reference| {
                        reference
                            .digests
                            .keys()
                            .map(|index| plan.packages[*index].build)
                            .collect::<BTreeSet<_>>()
                            .into_iter()
                            .collect()
                    })
                    .unwrap_or_else(|| (0..plan.builds.len()).collect())
            } else {
                select_builds(&plan, &units)?
            };
            let candidate = candidate.map(|mut reference| {
                reference
                    .digests
                    .retain(|index, _| units.contains(&plan.packages[*index].build));
                reference
            });
            let key = cohort::crypto::load_key(&key)?;
            let assignment = v5::run::assignment(
                &plan,
                &v5::run::RunOptions {
                    units,
                    retry_safe_units: retry_builds(&plan, &retry_safe)?,
                    skip_runtime,
                    trusted_key: Some(cohort::crypto::public_key(&key)),
                    candidate,
                },
            )?;
            let tools = runtime_tools(&runtime)?;
            let receipt = v5::run::execute(
                root,
                &plan,
                &assignment,
                &output,
                false,
                &[],
                Some(&key),
                nfpm.as_deref(),
                &tools,
            )?;
            export_default(root, &output)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        Command::Merge {
            plan,
            results,
            policy,
            output,
        } => {
            let plan = v5::plan::load(&plan)?;
            let policy = load_policy(&policy)?;
            let collection = v5::bundle::merge(root, &plan, &results, &policy, &output)?;
            println!(
                "merged trusted delivery collection {}: {} packages",
                collection.id,
                collection.selections.len()
            );
        }
        _ => anyhow::bail!("command has no protocol 5 dispatch"),
    }
    Ok(())
}

pub(super) fn runtime_args(command: &Command) -> Option<&RuntimeArgs> {
    match command {
        Command::Rehearse { runtime, .. }
        | Command::Worker { runtime, .. }
        | Command::Resume { runtime, .. }
        | Command::Rebuild { runtime, .. } => Some(runtime),
        _ => None,
    }
}
pub(super) fn runtime_tools(args: &RuntimeArgs) -> Result<v5::runtime::RuntimeTools> {
    let mut tools = v5::runtime::RuntimeTools::default();
    for value in &args.emulators {
        let (name, path) = value
            .split_once('=')
            .context("--emulator expects NAME=PATH")?;
        ensure!(
            matches!(name, "qemu-arm" | "qemu-i386") && !path.is_empty(),
            "unknown emulator name or empty path"
        );
        ensure!(
            tools
                .emulators
                .insert(name.into(), PathBuf::from(path))
                .is_none(),
            "duplicate emulator mapping"
        );
    }
    for name in ["qemu-arm", "qemu-i386"] {
        if !tools.emulators.contains_key(name)
            && let Some(path) = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .map(|p| p.join(name))
                .find(|p| p.is_file())
        {
            tools.emulators.insert(name.into(), path);
        }
    }
    for value in &args.rootfs {
        let (name, path) = value
            .split_once('=')
            .context("--rootfs expects TARGET_ID=PATH")?;
        catalog::resolve(name)?;
        ensure!(!path.is_empty(), "empty rootfs path");
        ensure!(
            tools
                .rootfs
                .insert(name.into(), PathBuf::from(path))
                .is_none(),
            "duplicate rootfs mapping"
        );
    }
    Ok(tools)
}
pub(super) fn load_policy(path: &Path) -> Result<v5::proof::Policy> {
    let policy = toml::from_str(&std::fs::read_to_string(path)?)?;
    v5::proof::validate_policy(&policy)?;
    Ok(policy)
}
fn show_catalog(builder: Option<&str>, json: bool) -> Result<()> {
    let mut rows = vec![];
    for logical in catalog::all() {
        if builder.is_some_and(|b| logical.builder != "any" && logical.builder != b) {
            continue;
        }
        let target = if let Some(builder) = builder {
            let kind = if builder == "rust" {
                v2::model::Builder::Rust {
                    package: "catalog".into(),
                    manifest: "Cargo.toml".into(),
                    features: vec![],
                    default_features: true,
                }
            } else {
                v2::model::Builder::Go {
                    version: "0.0.0".into(),
                    packages: vec![],
                    ldflags: vec![],
                }
            };
            catalog::for_builder(&logical, &kind)?
        } else {
            logical
        };
        let formats = [
            relship::delivery::model::Format::TarGz,
            relship::delivery::model::Format::Zip,
            relship::delivery::model::Format::Deb,
            relship::delivery::model::Format::Rpm,
            relship::delivery::model::Format::Apk,
            relship::delivery::model::Format::Pacman,
            relship::delivery::model::Format::Ipk,
        ]
        .into_iter()
        .map(|format| match catalog::package_support(&target, format) {
            Ok(profile) => serde_json::json!({"format":format,"supported":true,"profile":profile}),
            Err(error) => {
                serde_json::json!({"format":format,"supported":false,"reason":error.to_string()})
            }
        })
        .collect::<Vec<_>>();
        rows.push(serde_json::json!({"target":target,"formats":formats}));
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else {
        for row in rows {
            let target = &row["target"];
            println!(
                "{} [{}] {}",
                target["id"].as_str().unwrap_or_default(),
                target["builder"].as_str().unwrap_or_default(),
                target["compiler-target"].as_str().unwrap_or_default()
            );
            for format in row["formats"].as_array().unwrap() {
                if format["supported"] == true {
                    println!(
                        "  {}: supported; package arch {}",
                        format["format"].as_str().unwrap_or_default(),
                        format["profile"]["package-arch"]
                            .as_str()
                            .unwrap_or_default()
                    );
                    if let Some(compatibility) = format["profile"]["compatibility"].as_str() {
                        println!("    {compatibility}");
                    }
                } else {
                    println!(
                        "  {}: {}",
                        format["format"].as_str().unwrap_or_default(),
                        format["reason"].as_str().unwrap_or_default()
                    );
                }
            }
        }
    }
    Ok(())
}
