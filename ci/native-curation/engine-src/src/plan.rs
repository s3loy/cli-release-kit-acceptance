use crate::{
    config,
    model::{Config, IMPLEMENTATION, Output, Plan, PlannedProduct, Product, SCHEMA, Task},
    process, source,
};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

fn metadata(root: &Path, extra: &[String]) -> Result<Value> {
    let mut argv = vec![
        "cargo".into(),
        "metadata".into(),
        "--format-version".into(),
        "1".into(),
        "--locked".into(),
    ];
    argv.extend_from_slice(extra);
    eprintln!("engine: resolving locked Cargo metadata");
    serde_json::from_str(&process::capture(root, &argv, 1200)?).context("invalid Cargo metadata")
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("Cargo metadata missing {key}"))
}

fn check_metadata(
    root: &Path,
    data: &Value,
    files: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    ensure!(
        Path::new(text(data, "workspace_root")?).canonicalize()? == root,
        "Cargo workspace root must equal source root"
    );
    for package in data["packages"]
        .as_array()
        .context("Cargo packages missing")?
    {
        if !package["source"].is_null() {
            continue;
        }
        let manifest = Path::new(text(package, "manifest_path")?);
        let relative = manifest
            .strip_prefix(root)
            .context("local dependency leaves the tracked source tree")?;
        let name = relative
            .to_str()
            .context("non-UTF8 manifest path")?
            .replace('\\', "/");
        config::safe_join(root, &name)?;
        ensure!(
            files.contains_key(&name),
            "local dependency manifest is not tracked: {name}"
        );
        for target in package["targets"]
            .as_array()
            .context("Cargo targets missing")?
        {
            let src = Path::new(text(target, "src_path")?)
                .strip_prefix(root)
                .context("Cargo target source leaves the tracked source tree")?;
            let name = src
                .to_str()
                .context("non-UTF8 target path")?
                .replace('\\', "/");
            config::safe_join(root, &name)?;
            ensure!(
                files.contains_key(&name),
                "Cargo target source is not tracked: {name}"
            );
        }
    }
    Ok(())
}

pub fn host(root: &Path) -> Result<String> {
    let output = process::capture(root, &["rustc".into(), "-vV".into()], 60)?;
    output
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(str::to_owned)
        .context("rustc did not identify host")
}

pub fn initialize(root: &Path) -> Result<PathBuf> {
    let path = config::safe_join(root, "release.toml")?;
    ensure!(!path.exists(), "release.toml already exists");
    let data = metadata(root, &["--no-deps".into()])?;
    ensure!(
        Path::new(text(&data, "workspace_root")?).canonicalize()? == root,
        "initialize from Cargo workspace root"
    );
    let members: BTreeSet<&str> = data["workspace_members"]
        .as_array()
        .context("workspace members missing")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut products = Vec::new();
    for package in data["packages"].as_array().context("packages missing")? {
        if !members.contains(text(package, "id")?) {
            continue;
        }
        let binaries: Vec<String> = package["targets"]
            .as_array()
            .context("targets missing")?
            .iter()
            .filter(|t| {
                t["kind"]
                    .as_array()
                    .is_some_and(|k| k.iter().any(|v| v.as_str() == Some("bin")))
            })
            .map(|t| text(t, "name").map(str::to_owned))
            .collect::<Result<_>>()?;
        if binaries.is_empty() {
            continue;
        }
        products.push(Product {
            package: text(package, "name")?.into(),
            manifest: Path::new(text(package, "manifest_path")?)
                .strip_prefix(root)?
                .to_str()
                .context("non-UTF8 manifest")?
                .replace('\\', "/"),
            binaries,
            assets: vec![],
            features: vec![],
            default_features: true,
            checks: vec![],
            version_args: vec!["--version".into()],
            version_binaries: None,
        });
    }
    ensure!(!products.is_empty(), "workspace has no binary products");
    let config = Config {
        schema: SCHEMA,
        targets: vec![host(root)?],
        products,
        generated: vec![],
        prepare: vec![],
        timeout_seconds: 1200,
    };
    config::validate(&config)?;
    let encoded = toml::to_string_pretty(&config)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?
        .write_all(encoded.as_bytes())?;
    Ok(path)
}

pub fn outputs(products: &[PlannedProduct], targets: &[String]) -> Result<Vec<Output>> {
    let mut outputs = Vec::new();
    let mut names = BTreeSet::new();
    for product in products {
        ensure!(
            !product.version.is_empty()
                && product
                    .version
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b".-+".contains(&c)),
            "unsafe Cargo version"
        );
        for target in targets {
            let suffix = if target.contains("windows") {
                "zip"
            } else {
                "tar.gz"
            };
            let filename = format!("{}-{}-{target}.{suffix}", product.package, product.version);
            config::relative(&filename)?;
            ensure!(names.insert(filename.clone()), "duplicate output identity");
            outputs.push(Output {
                product: product.package.clone(),
                target: target.clone(),
                filename,
            });
        }
    }
    Ok(outputs)
}

pub fn id(plan: &Plan) -> Result<String> {
    let mut semantic = plan.clone();
    semantic.id.clear();
    Ok(source::digest(&serde_json::to_vec(&semantic)?))
}

pub fn build_argv(product: &PlannedProduct, target: &str, directory: &str) -> Vec<String> {
    let mut argv = vec![
        "cargo".into(),
        "build".into(),
        "--locked".into(),
        "--release".into(),
        "--package".into(),
        product.package.clone(),
        "--target".into(),
        target.into(),
        "--target-dir".into(),
        directory.into(),
    ];
    for binary in &product.binaries {
        argv.extend(["--bin".into(), binary.clone()]);
    }
    if !product.default_features {
        argv.push("--no-default-features".into());
    }
    if !product.features.is_empty() {
        argv.extend(["--features".into(), product.features.join(",")]);
    }
    argv
}

fn tasks(config: &Config, products: &[PlannedProduct]) -> Vec<Task> {
    let mut tasks = Vec::new();
    let mut previous_target = Vec::new();
    for (ti, target) in config.targets.iter().enumerate() {
        let cleanup = format!("clean-{ti}");
        tasks.push(Task {
            id: cleanup.clone(),
            kind: "clean-generated".into(),
            depends_on: previous_target,
            command: vec![],
            runtime: false,
        });
        let mut prepared = cleanup;
        for (hi, hook) in config.prepare.iter().enumerate() {
            let id = format!("prepare-{ti}-{hi}");
            tasks.push(Task {
                id: id.clone(),
                kind: "prepare".into(),
                depends_on: vec![prepared],
                command: hook.command.clone(),
                runtime: false,
            });
            prepared = id;
        }
        let mut finished = Vec::new();
        for (pi, product) in products.iter().enumerate() {
            let build = format!("build-{ti}-{pi}");
            tasks.push(Task {
                id: build.clone(),
                kind: "cargo-build".into(),
                depends_on: vec![prepared.clone()],
                command: build_argv(
                    product,
                    target,
                    &format!("{{attempt}}/work/build-{ti}-{pi}"),
                ),
                runtime: false,
            });
            let archive = format!("archive-{ti}-{pi}");
            tasks.push(Task {
                id: archive.clone(),
                kind: "archive-and-content-check".into(),
                depends_on: vec![build],
                command: vec![],
                runtime: false,
            });
            let mut previous = archive;
            for (bi, binary) in config::effective_version_binaries(
                &product.binaries,
                product.version_binaries.as_deref(),
            )
            .iter()
            .enumerate()
            {
                let id = format!("version-{ti}-{pi}-{bi}");
                let name = crate::execute::binary_name(binary, target);
                let mut command = vec![format!("{{attempt}}/work/run-{ti}-{pi}/{name}")];
                command.extend(product.version_args.clone());
                tasks.push(Task {
                    id: id.clone(),
                    kind: "version-check".into(),
                    depends_on: vec![previous],
                    command,
                    runtime: true,
                });
                previous = id;
            }
            for (hi, hook) in product.checks.iter().enumerate() {
                let id = format!("check-{ti}-{pi}-{hi}");
                tasks.push(Task {
                    id: id.clone(),
                    kind: "product-check".into(),
                    depends_on: vec![previous],
                    command: hook.command.clone(),
                    runtime: true,
                });
                previous = id;
            }
            finished.push(previous);
        }
        previous_target = finished;
    }
    tasks.push(Task {
        id: "seal".into(),
        kind: "recheck-checksum-and-expose".into(),
        depends_on: previous_target,
        command: vec![],
        runtime: false,
    });
    tasks
}

pub fn create(root: &Path) -> Result<Plan> {
    let config = config::load(root)?;
    let identity = source::snapshot(root)?;
    config::require_tracked(&config, &identity.files)?;
    config::validate_hooks(root, &config, &identity.files)?;
    let data = metadata(root, &[])?;
    check_metadata(root, &data, &identity.files)?;
    let members: BTreeSet<&str> = data["workspace_members"]
        .as_array()
        .context("workspace members missing")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut products = Vec::new();
    for selected in &config.products {
        let package = data["packages"]
            .as_array()
            .context("packages missing")?
            .iter()
            .find(|p| {
                p["name"].as_str() == Some(&selected.package)
                    && p["id"].as_str().is_some_and(|id| members.contains(id))
            })
            .with_context(|| {
                format!(
                    "selected package is not a workspace member: {}",
                    selected.package
                )
            })?;
        ensure!(
            config::safe_join(root, &selected.manifest)?.canonicalize()?
                == Path::new(text(package, "manifest_path")?).canonicalize()?,
            "configured manifest is not the selected Cargo workspace product: {}",
            selected.manifest
        );
        let available: BTreeSet<&str> = package["targets"]
            .as_array()
            .context("targets missing")?
            .iter()
            .filter(|t| {
                t["kind"]
                    .as_array()
                    .is_some_and(|k| k.iter().any(|v| v.as_str() == Some("bin")))
            })
            .filter_map(|t| t["name"].as_str())
            .collect();
        for binary in &selected.binaries {
            ensure!(
                available.contains(binary.as_str()),
                "unknown binary {binary}"
            );
        }
        for feature in &selected.features {
            ensure!(
                package["features"].get(feature).is_some(),
                "unknown feature {feature}"
            );
        }
        if !selected.features.is_empty() || !selected.default_features {
            let mut extra = vec![];
            if !selected.default_features {
                extra.push("--no-default-features".into());
            }
            if !selected.features.is_empty() {
                extra.extend([
                    "--features".into(),
                    selected
                        .features
                        .iter()
                        .map(|f| format!("{}/{f}", selected.package))
                        .collect::<Vec<_>>()
                        .join(","),
                ]);
            }
            check_metadata(root, &metadata(root, &extra)?, &identity.files)?;
        }
        products.push(PlannedProduct {
            package: selected.package.clone(),
            manifest: Path::new(text(package, "manifest_path")?)
                .strip_prefix(root)?
                .to_str()
                .context("non-UTF8 manifest")?
                .replace('\\', "/"),
            version: text(package, "version")?.into(),
            binaries: selected.binaries.clone(),
            assets: selected.assets.clone(),
            features: selected.features.clone(),
            default_features: selected.default_features,
            checks: selected.checks.clone(),
            version_args: selected.version_args.clone(),
            version_binaries: selected.version_binaries.clone(),
        });
    }
    ensure!(
        source::snapshot(root)? == identity,
        "source changed during planning"
    );
    let outputs = outputs(&products, &config.targets)?;
    let tasks = tasks(&config, &products);
    let mut plan = Plan {
        schema: SCHEMA,
        id: String::new(),
        implementation: IMPLEMENTATION.into(),
        source: identity,
        config,
        products,
        outputs,
        tasks,
    };
    plan.id = id(&plan)?;
    Ok(plan)
}

pub fn validate_saved(root: &Path, plan: &Plan) -> Result<()> {
    ensure!(
        plan.schema == SCHEMA && plan.implementation == IMPLEMENTATION,
        "unsupported plan schema/implementation"
    );
    config::validate(&plan.config)?;
    ensure!(plan.id == id(plan)?, "plan identity mismatch");
    ensure!(
        config::load(root)? == plan.config,
        "release.toml changed since planning"
    );
    ensure!(
        source::snapshot(root)? == plan.source,
        "source identity changed since planning"
    );
    config::require_tracked(&plan.config, &plan.source.files)?;
    config::validate_hooks(root, &plan.config, &plan.source.files)?;
    ensure!(
        plan.products.len() == plan.config.products.len(),
        "plan product set mismatch"
    );
    for (actual, selected) in plan.products.iter().zip(&plan.config.products) {
        ensure!(
            actual.manifest == selected.manifest,
            "product manifest differs from consumer contract"
        );
        ensure!(
            plan.source.files.contains_key(&actual.manifest),
            "product manifest is not tracked"
        );
        let manifest: toml::Value = toml::from_str(&fs::read_to_string(config::safe_join(
            root,
            &actual.manifest,
        )?)?)?;
        ensure!(
            manifest
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(toml::Value::as_str)
                == Some(&actual.package),
            "product manifest package differs from plan"
        );
        let version = manifest
            .get("package")
            .and_then(|p| p.get("version"))
            .context("manifest version missing")?;
        let version = if version.get("workspace").and_then(toml::Value::as_bool) == Some(true) {
            let workspace: toml::Value =
                toml::from_str(&fs::read_to_string(root.join("Cargo.toml"))?)?;
            workspace
                .get("workspace")
                .and_then(|w| w.get("package"))
                .and_then(|p| p.get("version"))
                .and_then(toml::Value::as_str)
                .context("workspace version missing")?
                .to_owned()
        } else {
            version
                .as_str()
                .context("invalid manifest version")?
                .to_owned()
        };
        ensure!(
            actual.version == version,
            "product version differs from tracked Cargo manifest"
        );
        let selected = PlannedProduct {
            package: selected.package.clone(),
            manifest: actual.manifest.clone(),
            version: actual.version.clone(),
            binaries: selected.binaries.clone(),
            assets: selected.assets.clone(),
            features: selected.features.clone(),
            default_features: selected.default_features,
            checks: selected.checks.clone(),
            version_args: selected.version_args.clone(),
            version_binaries: selected.version_binaries.clone(),
        };
        ensure!(
            actual == &selected,
            "plan product differs from consumer contract"
        );
    }
    ensure!(
        plan.outputs == outputs(&plan.products, &plan.config.targets)?,
        "plan artifact set mismatch"
    );
    ensure!(
        plan.tasks == tasks(&plan.config, &plan.products),
        "plan task graph mismatch"
    );
    Ok(())
}

pub fn load(path: &Path) -> Result<Plan> {
    crate::cohort::io::read_json(path)
}
