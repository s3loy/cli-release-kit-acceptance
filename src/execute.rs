use crate::{
    archive::{self, Content},
    config::safe_join,
    model::{Artifact, Hook, IMPLEMENTATION, Plan, PlannedProduct, Receipt, SCHEMA},
    process::{self, Commands},
    source::file_digest,
};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

pub fn run(root: &Path, plan: &Plan, output: &Path, skip_runtime: bool) -> Result<Receipt> {
    crate::plan::validate_saved(root, plan)?;
    let root = root.canonicalize()?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent
        .canonicalize()
        .context("output parent must already exist")?;
    let name = output
        .file_name()
        .context("output must name a fresh attempt directory")?;
    let output = parent.join(name);
    if output.starts_with(&root) {
        ensure!(
            output.starts_with(root.join("target")) && output != root.join("target"),
            "attempt directories inside the source tree must be beneath target/"
        );
        let relative = output
            .strip_prefix(&root)?
            .to_str()
            .context("non-UTF8 output path")?;
        safe_join(&root, relative)?;
    }
    ensure!(
        fs::symlink_metadata(&output).is_err(),
        "output already exists: {}",
        output.display()
    );
    for generated in &plan.config.generated {
        let path = safe_join(&root, generated)?;
        ensure!(
            !output.starts_with(&path) && !path.starts_with(&output),
            "output overlaps generated directory"
        );
    }
    fs::create_dir(&output)?;
    fs::write(output.join("plan.json"), serde_json::to_vec_pretty(plan)?)?;
    let mut receipt = Receipt {
        schema: SCHEMA,
        implementation: IMPLEMENTATION.into(),
        plan_id: plan.id.clone(),
        status: "failed".into(),
        publication_ready: false,
        toolchain: BTreeMap::new(),
        artifacts: Vec::new(),
        error: None,
    };
    save_receipt(&output, &receipt)?;
    let result = execute(&root, plan, &output, skip_runtime, &mut receipt);
    if let Err(error) = result {
        receipt.status = "failed".into();
        receipt.error = Some(format!("{error:#}"));
        // A failure must not leave a successful selection, including a late receipt write failure.
        let _ = fs::remove_dir_all(output.join("verified"));
        save_receipt(&output, &receipt)?;
        return Err(error);
    }
    if let Err(error) = save_receipt(&output, &receipt) {
        let _ = fs::remove_dir_all(output.join("verified"));
        return Err(error);
    }
    Ok(receipt)
}

fn save_receipt(output: &Path, receipt: &Receipt) -> Result<()> {
    fs::write(
        output.join("receipt.json.tmp"),
        serde_json::to_vec_pretty(receipt)?,
    )?;
    fs::rename(output.join("receipt.json.tmp"), output.join("receipt.json"))?;
    Ok(())
}

fn execute(
    root: &Path,
    plan: &Plan,
    output: &Path,
    skip: bool,
    receipt: &mut Receipt,
) -> Result<()> {
    let mut commands = Commands::new(root, &output.join("logs"), plan.config.timeout_seconds)?;
    let rustc = commands.run(&["rustc".into(), "-vV".into()], "rustc", &BTreeMap::new())?;
    let host = rustc
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .context("rustc did not identify its host")?
        .to_owned();
    receipt.toolchain.insert("rustc".into(), rustc);
    receipt.toolchain.insert(
        "cargo".into(),
        commands.run(
            &["cargo".into(), "--version".into()],
            "cargo",
            &BTreeMap::new(),
        )?,
    );
    receipt.toolchain.insert(
        "engine_sha256".into(),
        file_digest(&std::env::current_exe()?)?,
    );
    if !skip {
        ensure!(
            plan.config.targets.iter().all(|target| target == &host),
            "cross-target execution requires a matching host; use --skip-runtime for build-only evidence"
        );
    }
    let staging = output.join("staging");
    fs::create_dir(&staging)?;
    fs::create_dir(output.join("work"))?;
    for (target_index, target) in plan.config.targets.iter().enumerate() {
        clear_generated(root, plan)?;
        let mut context = BTreeMap::from([
            (
                "KIT_PROJECT_DIR".into(),
                root.to_string_lossy().into_owned(),
            ),
            ("KIT_TARGET".into(), target.clone()),
        ]);
        hooks(
            &mut commands,
            &plan.config.prepare,
            &format!("prepare-{target_index}"),
            &context,
        )?;
        for generated in &plan.config.generated {
            let path = safe_join(root, generated)?;
            ensure!(
                path.is_dir(),
                "prepare did not create generated directory: {generated}"
            );
        }
        for (product_index, product) in plan.products.iter().enumerate() {
            let target_dir = output
                .join("work")
                .join(format!("build-{target_index}-{product_index}"));
            let argv = crate::plan::build_argv(product, target, &target_dir.to_string_lossy());
            commands.run(
                &argv,
                &format!("build-{target_index}-{product_index}"),
                &BTreeMap::new(),
            )?;
            let content = collect(root, product, target, &target_dir)?;
            let planned = plan
                .outputs
                .iter()
                .find(|o| o.product == product.package && &o.target == target)
                .context("plan has no matching output")?;
            let archive_path = safe_join(&staging, &planned.filename)?;
            archive::write(&archive_path, &content)?;
            let members = archive::validate(&archive_path, &content)?;
            if !skip {
                let extracted = output
                    .join("work")
                    .join(format!("run-{target_index}-{product_index}"));
                archive::extract(&archive::inspect(&archive_path)?, &extracted)?;
                for (binary_index, binary) in crate::config::effective_version_binaries(
                    &product.binaries,
                    product.version_binaries.as_deref(),
                )
                .iter()
                .enumerate()
                {
                    let binary = binary_name(binary, target);
                    let mut argv = vec![
                        safe_join(&extracted, &binary)?
                            .to_string_lossy()
                            .into_owned(),
                    ];
                    argv.extend(product.version_args.clone());
                    let stdout = commands.run(
                        &argv,
                        &format!("version-{target_index}-{product_index}-{binary_index}"),
                        &BTreeMap::new(),
                    )?;
                    ensure!(
                        stdout
                            .split_whitespace()
                            .any(|token| token == product.version),
                        "binary version output has no complete version token {}",
                        product.version
                    );
                }
                context.extend([
                    ("KIT_PRODUCT".into(), product.package.clone()),
                    ("KIT_VERSION".into(), product.version.clone()),
                    (
                        "KIT_BINARY".into(),
                        safe_join(&extracted, &binary_name(&product.binaries[0], target))?
                            .to_string_lossy()
                            .into_owned(),
                    ),
                    (
                        "KIT_ARCHIVE_DIR".into(),
                        extracted.to_string_lossy().into_owned(),
                    ),
                ]);
                hooks(
                    &mut commands,
                    &product.checks,
                    &format!("check-{target_index}-{product_index}"),
                    &context,
                )?;
            }
            receipt.artifacts.push(Artifact {
                filename: planned.filename.clone(),
                sha256: file_digest(&archive_path)?,
                members,
            });
        }
    }
    crate::plan::validate_saved(root, plan)?;
    // Recheck all saved bytes after trusted hooks have run, before exposing anything.
    crate::verify::check_artifacts(root, plan, receipt, &staging)?;
    let checksum = checksum_text(&receipt.artifacts);
    fs::write(staging.join("SHA256SUMS"), checksum)?;
    receipt.status = if skip { "build-only" } else { "verified" }.into();
    fs::rename(&staging, output.join(&receipt.status))?;
    Ok(())
}

fn collect(
    root: &Path,
    product: &PlannedProduct,
    target: &str,
    build: &Path,
) -> Result<BTreeMap<String, Content>> {
    let mut content = BTreeMap::new();
    for binary in &product.binaries {
        let name = binary_name(binary, target);
        let source = safe_join(build, &format!("{target}/release/{name}"))?;
        ensure!(
            source.is_file(),
            "missing built binary: {}",
            source.display()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                fs::metadata(&source)?.permissions().mode() & 0o111 != 0,
                "built binary is not executable"
            );
        }
        content.insert(
            name,
            Content {
                bytes: read_content(&source)?,
                executable: true,
            },
        );
    }
    for asset in &product.assets {
        let path = safe_join(root, &asset.source)?;
        ensure!(
            fs::symlink_metadata(&path)?.is_file(),
            "asset is not a regular file: {}",
            asset.source
        );
        ensure!(
            content
                .insert(
                    asset.path.clone(),
                    Content {
                        bytes: read_content(&path)?,
                        executable: false
                    }
                )
                .is_none(),
            "duplicate archive destination"
        );
    }
    Ok(content)
}

fn hooks(
    commands: &mut Commands,
    hooks: &[Hook],
    label: &str,
    context: &BTreeMap<String, String>,
) -> Result<()> {
    for (index, hook) in hooks.iter().enumerate() {
        let mut extra = hook.env.clone();
        extra.extend(context.clone());
        commands.run(&hook.command, &format!("{label}-{index}"), &extra)?;
    }
    Ok(())
}

fn clear_generated(root: &Path, plan: &Plan) -> Result<()> {
    let mut paths = Vec::new();
    for generated in &plan.config.generated {
        ensure!(
            generated.starts_with("target/"),
            "generated directory must be beneath target/"
        );
        let path = safe_join(root, generated)?;
        let tracked = process::capture(
            root,
            &[
                "git".into(),
                "ls-files".into(),
                "--".into(),
                generated.clone(),
            ],
            30,
        )?;
        ensure!(
            tracked.is_empty(),
            "generated cleanup would remove tracked inputs: {generated}"
        );
        paths.push(path);
    }
    for path in paths {
        if path.is_dir() {
            fs::remove_dir_all(path)?;
        } else if path.exists() {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

pub fn binary_name(binary: &str, target: &str) -> String {
    format!(
        "{binary}{}",
        if target.contains("windows") {
            ".exe"
        } else {
            ""
        }
    )
}

pub fn checksum_text(artifacts: &[Artifact]) -> String {
    let mut entries: Vec<_> = artifacts.iter().collect();
    entries.sort_by_key(|artifact| &artifact.filename);
    entries
        .iter()
        .map(|a| format!("{}  {}\n", a.sha256, a.filename))
        .collect()
}

fn read_content(path: &Path) -> Result<Vec<u8>> {
    let limit = archive::CONTENT_LIMIT;
    ensure!(
        fs::metadata(path)?.len() <= limit,
        "input exceeds archive content limit: {}",
        path.display()
    );
    let mut content = Vec::new();
    File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut content)?;
    ensure!(
        content.len() as u64 <= limit,
        "input grew beyond archive content limit"
    );
    Ok(content)
}
