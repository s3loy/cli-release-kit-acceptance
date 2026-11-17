use super::{Command, config_schema, delivery, json_schema, write_new_json};
use anyhow::{Context, Result, ensure};
use relship::{cohort, process, v2};
use std::{collections::BTreeSet, path::Path};

pub(super) fn supports(root: &Path, command: &Command) -> Result<bool> {
    Ok(match command {
        Command::Init {
            schema: Some(3), ..
        } => true,
        Command::Doctor => config_schema(root)? == 3,
        Command::Plan { protocol, .. } => *protocol == Some(4) || config_schema(root)? == 3,
        Command::Rehearse { plan, .. }
        | Command::Assign { plan, .. }
        | Command::Worker { plan, .. }
        | Command::Import { plan, .. }
        | Command::Rebuild { plan, .. }
        | Command::Merge { plan, .. } => json_schema(plan)? == 4,
        Command::Status { output, .. } => json_schema(&output.join("receipt.json"))? == 4,
        Command::Resume { output, .. }
        | Command::Export {
            attempt: output, ..
        } => json_schema(&output.join("plan.json"))? == 4,
        Command::Verify { output, .. } => {
            let file = if output.join("collection.json").exists() {
                "collection.json"
            } else {
                "plan.json"
            };
            json_schema(&output.join(file))? == 4
        }
        _ => false,
    })
}

pub(super) fn select_builds(plan: &delivery::model::Plan, names: &[String]) -> Result<Vec<usize>> {
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
                *name == build.id || *name == format!("{}@{}", product.id, target.key())
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

fn retry_builds(plan: &delivery::model::Plan, names: &[String]) -> Result<Vec<usize>> {
    if names.is_empty() {
        Ok(Vec::new())
    } else {
        select_builds(plan, names)
    }
}

pub(super) fn export_default(root: &Path, output: &Path) -> Result<()> {
    let plan = delivery::plan::load(&output.join("plan.json"))?;
    let result = output.join("result");
    if result.exists() {
        delivery::bundle::validate(root, &plan, &result)?;
    } else {
        delivery::bundle::export_run(root, output, &result)?;
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
            let path = delivery::plan::initialize(root, &directory, kind, app_version.as_deref())?;
            println!(
                "created {}; review and commit the schema 3 contract",
                path.display()
            );
        }
        Command::Doctor => {
            let config = delivery::config::load(root)?;
            let base = delivery::config::base_config(&config);
            let mut tools = std::collections::BTreeMap::new();
            for (key, spec) in v2::builder::probes(&base.products) {
                let cwd = if spec.cwd == "." {
                    root.to_path_buf()
                } else {
                    relship::config::safe_join(root, &spec.cwd)?
                };
                tools.insert(key, process::capture_spec(&cwd, &spec.argv, &spec.env, 60)?);
            }
            let native = config.products.iter().enumerate().any(|(index, product)| {
                config
                    .targets
                    .iter()
                    .filter(|target| {
                        product.targets.is_empty() || product.targets.contains(&target.key())
                    })
                    .any(|target| {
                        delivery::config::effective_formats(&config, index, &target.os)
                            .iter()
                            .any(|format| format.is_native())
                    })
            });
            let nfpm = if native {
                Some(delivery::native::resolve_nfpm(None)?)
            } else {
                None
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "schema": 3, "execution_protocols": [4], "targets": config.targets,
                    "toolchain": tools, "nfpm": nfpm, "publication_ready": false,
                    "available": ["multi-format-plan", "payload-checkpoints", "package-checkpoints", "tar.gz", "zip", "deb", "rpm", "apk-v2", "pacman", "ipk", "offline-verify", "trusted-rebuild", "github-draft"],
                    "unavailable": ["install-scripts", "services", "native-package-signing", "release-publish"]
                }))?
            );
        }
        Command::Plan { protocol, output } => {
            ensure!(
                protocol.is_none_or(|value| value == 4),
                "schema 3 requires execution protocol 4"
            );
            let plan = delivery::plan::create(root)?;
            if let Some(output) = output {
                write_new_json(root, &output, &plan)?;
                println!("saved protocol 4 plan {} to {}", plan.id, output.display());
            } else {
                println!("{}", serde_json::to_string_pretty(&plan)?);
            }
        }
        Command::Rehearse {
            plan,
            output,
            skip_runtime,
            nfpm,
            ..
        } => {
            let plan = delivery::plan::load(&plan)?;
            let assignment = delivery::run::assignment(
                &plan,
                &delivery::run::RunOptions {
                    skip_runtime,
                    ..Default::default()
                },
            )?;
            let receipt = delivery::run::execute(
                root,
                &plan,
                &assignment,
                &output,
                false,
                &[],
                None,
                nfpm.as_deref(),
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
            let plan = delivery::plan::load(&plan)?;
            delivery::plan::validate_saved(root, &plan)?;
            let assignment = delivery::run::assignment(
                &plan,
                &delivery::run::RunOptions {
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
            ..
        } => {
            let plan = delivery::plan::load(&plan)?;
            let assignment = cohort::io::read_json(&assignment)?;
            let receipt = delivery::run::execute(
                root,
                &plan,
                &assignment,
                &output,
                false,
                &[],
                None,
                nfpm.as_deref(),
            )?;
            export_default(root, &output)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        Command::Resume {
            output,
            allow_retry,
            key,
            nfpm,
            ..
        } => {
            let plan = delivery::plan::load(&output.join("plan.json"))?;
            let assignment = cohort::io::read_json(&output.join("assignment.json"))?;
            delivery::plan::validate_saved(root, &plan)?;
            delivery::run::validate_assignment(&plan, &assignment)?;
            let retry = retry_builds(&plan, &allow_retry)?;
            let key = key.as_deref().map(cohort::crypto::load_key).transpose()?;
            let receipt = delivery::run::execute(
                root,
                &plan,
                &assignment,
                &output,
                true,
                &retry,
                key.as_ref(),
                nfpm.as_deref(),
            )?;
            export_default(root, &output)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        Command::Status { output, json } => {
            let receipt = delivery::run::status(&output)?;
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
                let policy = cohort::crypto::load_policy(
                    policy
                        .as_deref()
                        .context("collection verification requires --policy")?,
                )?;
                let collection = delivery::bundle::verify_collection(root, &output, &policy)?;
                println!(
                    "verified delivery collection {}: {} policy-authorized packages (not published)",
                    collection.id,
                    collection.selections.len()
                );
            } else {
                let receipt = delivery::run::verify_run(root, &output)?;
                println!(
                    "checked protocol 4 preparation {}: {} payloads and {} packages (trust requires merge policy)",
                    receipt.plan_id,
                    receipt.payloads.len(),
                    receipt.packages.len()
                );
            }
        }
        Command::Export { attempt, output } => {
            let bundle = delivery::bundle::export_run(root, &attempt, &output)?;
            println!("exported delivery bundle {}", bundle.id);
        }
        Command::Import {
            plan,
            bundle,
            output,
        } => {
            let plan = delivery::plan::load(&plan)?;
            let bundle = delivery::bundle::import_candidate(root, &plan, &bundle, &output)?;
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
            ..
        } => {
            let plan = delivery::plan::load(&plan)?;
            delivery::plan::validate_saved(root, &plan)?;
            let candidate = candidate
                .as_deref()
                .map(|path| delivery::bundle::candidate_ref(root, &plan, path))
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
            let assignment = delivery::run::assignment(
                &plan,
                &delivery::run::RunOptions {
                    units,
                    retry_safe_units: retry_builds(&plan, &retry_safe)?,
                    skip_runtime,
                    trusted_key: Some(cohort::crypto::public_key(&key)),
                    candidate,
                },
            )?;
            let receipt = delivery::run::execute(
                root,
                &plan,
                &assignment,
                &output,
                false,
                &[],
                Some(&key),
                nfpm.as_deref(),
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
            let plan = delivery::plan::load(&plan)?;
            let policy = cohort::crypto::load_policy(&policy)?;
            let collection = delivery::bundle::merge(root, &plan, &results, &policy, &output)?;
            println!(
                "merged trusted delivery collection {}: {} packages",
                collection.id,
                collection.selections.len()
            );
        }
        _ => anyhow::bail!("command has no protocol 4 dispatch"),
    }
    Ok(())
}
