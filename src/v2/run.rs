use super::model::{Action, CommandSpec, Plan, Receipt, SCHEMA, Task, TaskResult, TaskState};
use crate::{
    archive::{self, Content},
    config::safe_join,
    execute::checksum_text,
    model::{Artifact, IMPLEMENTATION},
    process::{self, Commands},
    source::{digest, file_digest},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

pub fn execute(root: &Path, plan: &Plan, output: &Path, skip_runtime: bool) -> Result<Receipt> {
    super::plan::validate_saved(root, plan)?;
    let root = root.canonicalize()?;
    let output = fresh_attempt(&root, output)?;
    fs::create_dir(&output)?;
    let started_at_ms = now_ms();
    let mut receipt = Receipt {
        schema: SCHEMA,
        implementation: IMPLEMENTATION.into(),
        plan_id: plan.id.clone(),
        status: "running".into(),
        publication_ready: false,
        started_at_ms,
        updated_at_ms: started_at_ms,
        finished_at_ms: None,
        toolchain: BTreeMap::new(),
        tasks: plan
            .tasks
            .iter()
            .map(|task| TaskResult {
                id: task.id.clone(),
                state: TaskState::Pending,
                elapsed_ms: 0,
                error: None,
                log: None,
            })
            .collect(),
        artifacts: Vec::new(),
        error: None,
    };
    let result = (|| {
        fs::write(output.join("plan.json"), serde_json::to_vec_pretty(plan)?)?;
        save_receipt(&output, &mut receipt)?;
        run_tasks(&root, plan, &output, skip_runtime, &mut receipt)
    })();
    if let Err(error) = result {
        receipt.status = "failed".into();
        receipt.error = Some(format!("{error:#}"));
        receipt.finished_at_ms = Some(now_ms().max(receipt.updated_at_ms));
        for task in &mut receipt.tasks {
            if matches!(task.state, TaskState::Pending | TaskState::Running) {
                task.state = TaskState::Blocked;
                task.error = Some("attempt stopped after a failure".into());
            }
        }
        // A late snapshot failure must also withdraw the artifact selection.
        remove_selections(&output);
        save_receipt(&output, &mut receipt).with_context(|| {
            format!("attempt failed ({error:#}); could not save its failure snapshot")
        })?;
        return Err(error);
    }
    Ok(receipt)
}

fn fresh_attempt(root: &Path, output: &Path) -> Result<PathBuf> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = parent
        .canonicalize()
        .context("output parent must already exist")?;
    ensure!(parent.is_dir(), "output parent is not a directory");
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .context("output must name a fresh UTF-8 attempt directory")?;
    crate::config::relative(name)?;
    let output = safe_join(&parent, name)?;
    ensure!(
        matches!(fs::symlink_metadata(&output), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
        "output already exists or cannot be inspected: {}",
        output.display()
    );
    ensure!(
        !root.starts_with(&output),
        "attempt directory overlaps the source root"
    );
    if output.starts_with(root) {
        ensure!(
            output.starts_with(root.join("target")) && output != root.join("target"),
            "attempt directories inside the source tree must be beneath ignored target/"
        );
        let relative = output
            .strip_prefix(root)?
            .to_str()
            .context("non-UTF8 attempt path")?;
        safe_join(root, relative)?;
        process::capture(
            root,
            &[
                "git".into(),
                "check-ignore".into(),
                "--quiet".into(),
                "--".into(),
                relative.into(),
            ],
            30,
        )
        .context("attempt directory inside target/ must be ignored by Git")?;
        let tracked = process::capture(
            root,
            &[
                "git".into(),
                "ls-files".into(),
                "--".into(),
                relative.into(),
            ],
            30,
        )?;
        ensure!(tracked.is_empty(), "attempt overlaps tracked source inputs");
    }
    Ok(output)
}

fn run_tasks(
    root: &Path,
    plan: &Plan,
    output: &Path,
    skip: bool,
    receipt: &mut Receipt,
) -> Result<()> {
    fs::create_dir(output.join("staging"))?;
    fs::create_dir(output.join("work"))?;
    for index in 0..plan.units.len() {
        fs::create_dir(generated_dir(output, index))?;
        fs::create_dir(output.join("work").join(format!("build-{index}")))?;
    }
    receipt.toolchain.insert(
        "engine_sha256".into(),
        file_digest(&std::env::current_exe()?)?,
    );
    for (index, task) in plan.tasks.iter().enumerate() {
        let started = Instant::now();
        let result = (|| {
            for dependency in &task.depends_on {
                let dependency = receipt
                    .tasks
                    .iter()
                    .find(|result| &result.id == dependency)
                    .context("task dependency is absent")?;
                ensure!(
                    matches!(dependency.state, TaskState::Succeeded | TaskState::Skipped),
                    "task dependency did not complete: {}",
                    dependency.id
                );
            }
            if skip && task.runtime {
                receipt.tasks[index].state = TaskState::Skipped;
                receipt.tasks[index].error =
                    Some("runtime verification disabled by --skip-runtime".into());
                return Ok(());
            }
            receipt.tasks[index].state = TaskState::Running;
            receipt.tasks[index].log = command(task).map(|_| format!("logs/{}", task.id));
            save_receipt(output, receipt)?;
            perform(root, plan, output, task, skip, receipt)?;
            receipt.tasks[index].state = TaskState::Succeeded;
            Ok(())
        })();
        receipt.tasks[index].elapsed_ms =
            started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        if let Err(error) = result {
            receipt.tasks[index].state = TaskState::Failed;
            receipt.tasks[index].error = Some(format!("{error:#}"));
            return Err(error.context(format!("task {} failed", task.id)));
        }
        save_receipt(output, receipt)?;
    }
    receipt.status = if skip { "build-only" } else { "verified" }.into();
    receipt.finished_at_ms = Some(now_ms().max(receipt.updated_at_ms));
    save_receipt(output, receipt)?;
    Ok(())
}

pub(crate) fn perform(
    root: &Path,
    plan: &Plan,
    output: &Path,
    task: &Task,
    skip: bool,
    receipt: &mut Receipt,
) -> Result<()> {
    if task.runtime {
        let unit = task_unit(task).context("runtime task has no unit")?;
        let unit = &plan.units[unit];
        ensure!(
            super::builder::can_run(
                &plan.config.targets[unit.target],
                &unit.recipe,
                &receipt.toolchain
            ),
            "target cannot run with this host toolchain; use --skip-runtime for build-only evidence"
        );
    }
    match &task.action {
        Action::Probe { key, command } => {
            let stdout = run_command(root, plan, output, task, command)?;
            ensure!(
                !stdout.trim().is_empty(),
                "tool probe returned no identity: {key}"
            );
            ensure!(
                receipt.toolchain.insert(key.clone(), stdout).is_none(),
                "duplicate probe key"
            );
        }
        Action::Prepare { command, .. }
        | Action::Build { command, .. }
        | Action::Check { command, .. } => {
            run_command(root, plan, output, task, command)?;
            ensure!(
                crate::source::snapshot_plain(root)
                    .context("command invalidated the planned source identity")?
                    == plan.source,
                "command changed the planned source identity"
            );
        }
        Action::Version { unit, command, .. } => {
            let stdout = run_command(root, plan, output, task, command)?;
            let version = &plan.resolved[plan.units[*unit].product].version;
            ensure!(
                stdout.split_whitespace().any(|token| token == version),
                "binary version output has no complete version token {version}"
            );
            ensure!(
                crate::source::snapshot_plain(root)
                    .context("version command invalidated the planned source identity")?
                    == plan.source,
                "version command changed the planned source identity"
            );
        }
        Action::Archive { unit } => {
            let planned = &plan.units[*unit];
            let content = collect(root, plan, output, *unit)?;
            let path = safe_join(&safe_join(output, "staging")?, &planned.filename)?;
            archive::write(&path, &content)?;
            let members = archive::validate(&path, &content)?;
            archive::extract(
                &archive::inspect(&path)?,
                &safe_join(output, &format!("work/run-{unit}"))?,
            )?;
            receipt.artifacts.push(Artifact {
                filename: planned.filename.clone(),
                sha256: file_digest(&path)?,
                members,
            });
        }
        Action::Seal => {
            super::plan::validate_saved(root, plan)?;
            let staging = safe_join(output, "staging")?;
            check_artifacts(root, plan, receipt, &staging, false)?;
            fs::write(
                safe_join(&staging, "SHA256SUMS")?,
                checksum_text(&receipt.artifacts),
            )?;
            fs::rename(
                &staging,
                safe_join(output, if skip { "build-only" } else { "verified" })?,
            )?;
        }
    }
    Ok(())
}

pub(crate) fn command(task: &Task) -> Option<&CommandSpec> {
    match &task.action {
        Action::Probe { command, .. }
        | Action::Prepare { command, .. }
        | Action::Build { command, .. }
        | Action::Version { command, .. }
        | Action::Check { command, .. } => Some(command),
        Action::Archive { .. } | Action::Seal => None,
    }
}

pub(crate) fn task_unit(task: &Task) -> Option<usize> {
    match &task.action {
        Action::Prepare { unit, .. }
        | Action::Build { unit, .. }
        | Action::Archive { unit }
        | Action::Version { unit, .. }
        | Action::Check { unit, .. } => Some(*unit),
        Action::Probe { .. } | Action::Seal => None,
    }
}

pub(crate) fn run_command(
    root: &Path,
    plan: &Plan,
    output: &Path,
    task: &Task,
    command: &CommandSpec,
) -> Result<String> {
    let unit = task_unit(task);
    let expanded = |value: &str| expand(value, root, plan, output, unit);
    let argv = command
        .argv
        .iter()
        .map(|arg| expanded(arg))
        .collect::<Result<Vec<_>>>()?;
    let mut env = command
        .env
        .iter()
        .map(|(key, value)| Ok((key.clone(), expanded(value)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    env.insert("KIT_PROJECT_DIR".into(), path_text(root)?);
    env.insert("KIT_ATTEMPT_DIR".into(), path_text(output)?);
    if let Some(index) = unit {
        let unit = &plan.units[index];
        let product = &plan.config.products[unit.product];
        let target = &plan.config.targets[unit.target];
        env.extend([
            ("KIT_PRODUCT".into(), product.id.clone()),
            (
                "KIT_PRODUCT_DIR".into(),
                path_text(&super::contract::product_root(root, product)?)?,
            ),
            ("KIT_TARGET".into(), target.key()),
            (
                "KIT_VERSION".into(),
                plan.resolved[unit.product].version.clone(),
            ),
            (
                "KIT_GENERATED_DIR".into(),
                path_text(&generated_dir(output, index))?,
            ),
            (
                "KIT_ARCHIVE_DIR".into(),
                path_text(&run_dir(output, index))?,
            ),
            ("KIT_BINARY".into(), expanded("{binary}")?),
        ]);
    }
    let cwd = if command.cwd == "." {
        root.to_owned()
    } else {
        safe_join(root, &command.cwd)?
    };
    ensure!(
        cwd.is_dir(),
        "command working directory is absent: {}",
        cwd.display()
    );
    Commands::new(&cwd, &output.join("logs"), plan.config.timeout_seconds)?
        .run(&argv, &task.id, &env)
}

pub(crate) fn expand(
    value: &str,
    root: &Path,
    plan: &Plan,
    output: &Path,
    unit: Option<usize>,
) -> Result<String> {
    let mut value = value
        .replace("{project}", &path_text(root)?)
        .replace("{attempt}", &path_text(output)?);
    if let Some(index) = unit {
        let unit = &plan.units[index];
        let product = &plan.config.products[unit.product];
        let target = &plan.config.targets[unit.target];
        let binary = safe_join(
            &safe_join(output, &format!("work/run-{index}"))?,
            &target.binary_name(&product.binaries[0]),
        )?;
        for (placeholder, replacement) in [
            ("{generated}", path_text(&generated_dir(output, index))?),
            ("{archive}", path_text(&run_dir(output, index))?),
            ("{binary}", path_text(&binary)?),
            ("{version}", plan.resolved[unit.product].version.clone()),
            ("{target}", target.key()),
        ] {
            value = value.replace(placeholder, &replacement);
        }
    }
    Ok(value)
}

fn generated_dir(output: &Path, unit: usize) -> PathBuf {
    output.join("work").join(format!("generated-{unit}"))
}
fn run_dir(output: &Path, unit: usize) -> PathBuf {
    output.join("work").join(format!("run-{unit}"))
}
fn path_text(path: &Path) -> Result<String> {
    Ok(path.to_str().context("non-UTF8 execution path")?.into())
}

pub(crate) fn collect(
    root: &Path,
    plan: &Plan,
    output: &Path,
    index: usize,
) -> Result<BTreeMap<String, Content>> {
    let unit = &plan.units[index];
    let product = &plan.config.products[unit.product];
    let mut content = BTreeMap::new();
    let mut remaining = archive::CONTENT_LIMIT;
    for binary in &unit.recipe.binaries {
        let source = PathBuf::from(expand(&binary.source, root, plan, output, Some(index))?);
        let relative = source
            .strip_prefix(output.join("work"))
            .context("built binary must be isolated beneath attempt/work")?;
        let source = safe_join(
            &safe_join(output, "work")?,
            relative.to_str().context("non-UTF8 binary path")?,
        )?;
        let bytes = read_content_limit(&source, remaining)?;
        remaining -= bytes.len() as u64;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                fs::metadata(&source)?.permissions().mode() & 0o111 != 0,
                "built binary is not executable"
            );
        }
        ensure!(
            content
                .insert(
                    binary.path.clone(),
                    Content {
                        bytes,
                        executable: true
                    }
                )
                .is_none(),
            "duplicate archive binary"
        );
    }
    for asset in &product.assets {
        let source = if let Some(relative) = asset.source.strip_prefix("{generated}/") {
            safe_join(
                &safe_join(output, &format!("work/generated-{index}"))?,
                relative,
            )?
        } else {
            safe_join(root, &asset.source)?
        };
        let bytes = read_content_limit(&source, remaining)?;
        remaining -= bytes.len() as u64;
        ensure!(
            content
                .insert(
                    asset.path.clone(),
                    Content {
                        bytes,
                        executable: false
                    }
                )
                .is_none(),
            "duplicate archive asset destination"
        );
    }
    Ok(content)
}

fn read_content(path: &Path) -> Result<Vec<u8>> {
    read_content_limit(path, archive::CONTENT_LIMIT)
}

fn read_content_limit(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "content must be a regular file: {}",
        path.display()
    );
    ensure!(
        metadata.len() <= limit,
        "input exceeds archive content limit"
    );
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "input grew beyond archive content limit"
    );
    Ok(bytes)
}

pub fn verify(root: &Path, output: &Path) -> Result<Receipt> {
    let output = output.canonicalize()?;
    let plan: Plan = read_json(&safe_join(&output, "plan.json")?)?;
    let receipt = status(&output)?;
    super::plan::validate_saved(root, &plan)?;
    ensure!(
        receipt.plan_id == plan.id,
        "receipt references a different plan"
    );
    ensure!(
        receipt.status == "verified" && receipt.error.is_none() && !receipt.publication_ready,
        "receipt is not a successful local verified result"
    );
    ensure!(
        receipt.tasks.len() == plan.tasks.len(),
        "receipt task set differs from plan"
    );
    for (result, task) in receipt.tasks.iter().zip(&plan.tasks) {
        ensure!(
            result.id == task.id
                && matches!(result.state, TaskState::Succeeded)
                && result.error.is_none(),
            "planned task is missing, reordered or unsuccessful: {}",
            task.id
        );
        ensure!(
            result.log == command(task).map(|_| format!("logs/{}", task.id)),
            "task log reference differs from plan"
        );
    }
    let mut keys = BTreeSet::from(["engine_sha256"]);
    for task in &plan.tasks {
        if let Action::Probe { key, .. } = &task.action {
            ensure!(keys.insert(key), "duplicate planned probe identity");
        }
    }
    ensure!(
        receipt
            .toolchain
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == keys
            && receipt
                .toolchain
                .values()
                .all(|value| !value.trim().is_empty()),
        "missing or extra execution tool identities"
    );
    ensure!(
        is_digest(&receipt.toolchain["engine_sha256"]),
        "invalid engine digest"
    );
    for unit in &plan.units {
        ensure!(
            super::builder::can_run(
                &plan.config.targets[unit.target],
                &unit.recipe,
                &receipt.toolchain
            ),
            "recorded toolchain cannot support the claimed runtime verification: {}",
            unit.id
        );
    }
    check_artifacts(
        root,
        &plan,
        &receipt,
        &safe_join(&output, "verified")?,
        true,
    )?;
    Ok(receipt)
}

pub fn status(output: &Path) -> Result<Receipt> {
    let output = output.canonicalize()?;
    let receipt: Receipt = read_json(&safe_join(&output, "receipt.json")?)?;
    ensure!(
        receipt.schema == SCHEMA && receipt.implementation == IMPLEMENTATION,
        "unsupported receipt schema or implementation"
    );
    ensure!(is_digest(&receipt.plan_id), "invalid receipt plan id");
    ensure!(
        !receipt.publication_ready,
        "unsupported publication-ready receipt"
    );
    ensure!(
        receipt.updated_at_ms >= receipt.started_at_ms,
        "receipt timestamps are inconsistent"
    );
    ensure!(
        matches!(
            receipt.status.as_str(),
            "running" | "failed" | "verified" | "build-only"
        ),
        "unknown receipt status"
    );
    ensure!(
        (receipt.status == "running") == receipt.finished_at_ms.is_none(),
        "receipt completion timestamp is inconsistent"
    );
    if let Some(finished) = receipt.finished_at_ms {
        ensure!(
            (receipt.started_at_ms..=receipt.updated_at_ms).contains(&finished),
            "receipt completion timestamp is inconsistent"
        );
    }
    let mut ids = BTreeSet::new();
    ensure!(!receipt.tasks.is_empty(), "receipt has no tasks");
    for task in &receipt.tasks {
        ensure!(
            !task.id.is_empty()
                && task
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && ids.insert(&task.id),
            "invalid or duplicate receipt task id"
        );
        ensure!(
            task.log
                .as_ref()
                .is_none_or(|log| log == &format!("logs/{}", task.id)),
            "unsafe receipt log reference"
        );
        let error_matches = if matches!(
            task.state,
            TaskState::Failed | TaskState::Blocked | TaskState::Skipped
        ) {
            task.error.as_ref().is_some_and(|error| !error.is_empty())
        } else {
            task.error.is_none()
        };
        ensure!(error_matches, "task error does not match its state");
    }
    ensure!(
        receipt
            .tasks
            .iter()
            .filter(|task| matches!(task.state, TaskState::Running))
            .count()
            <= 1,
        "serial receipt has several running tasks"
    );
    if receipt.status != "running" {
        ensure!(
            receipt
                .tasks
                .iter()
                .all(|task| !matches!(task.state, TaskState::Pending | TaskState::Running)),
            "finished receipt still has unfinished tasks"
        );
    }
    let error_matches = if receipt.status == "failed" {
        receipt
            .error
            .as_ref()
            .is_some_and(|error| !error.is_empty())
    } else {
        receipt.error.is_none()
    };
    ensure!(error_matches, "attempt error does not match its status");
    Ok(receipt)
}

fn check_artifacts(
    root: &Path,
    plan: &Plan,
    receipt: &Receipt,
    directory: &Path,
    checksums: bool,
) -> Result<()> {
    let expected = plan
        .units
        .iter()
        .map(|unit| unit.filename.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        expected.len() == plan.units.len(),
        "duplicate planned artifact"
    );
    let actual = receipt
        .artifacts
        .iter()
        .map(|artifact| artifact.filename.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        actual.len() == receipt.artifacts.len() && actual == expected,
        "receipt artifact set differs from plan"
    );
    let mut directory_files = BTreeSet::new();
    for entry in fs::read_dir(directory).context("artifact selection is absent")? {
        let entry = entry?;
        ensure!(
            entry.file_type()?.is_file(),
            "non-regular artifact selection entry"
        );
        directory_files.insert(
            entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 artifact filename"))?,
        );
    }
    if checksums {
        ensure!(
            directory_files.remove("SHA256SUMS"),
            "checksum file is absent"
        );
    }
    ensure!(
        directory_files
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == expected,
        "artifact directory has missing or extra files"
    );
    for artifact in &receipt.artifacts {
        check_artifact(root, plan, artifact, directory)?;
    }
    if checksums {
        let bytes = read_content(&safe_join(directory, "SHA256SUMS")?)?;
        ensure!(
            bytes == checksum_text(&receipt.artifacts).as_bytes(),
            "checksum coverage, order or bytes differ"
        );
    }
    Ok(())
}

pub(crate) fn check_artifact(
    root: &Path,
    plan: &Plan,
    artifact: &Artifact,
    directory: &Path,
) -> Result<()> {
    let path = safe_join(directory, &artifact.filename)?;
    ensure!(
        file_digest(&path)? == artifact.sha256,
        "archive digest changed: {}",
        artifact.filename
    );
    let content = archive::inspect(&path)?;
    ensure!(
        archive::members(&content) == artifact.members,
        "archive members differ from receipt"
    );
    let unit = plan
        .units
        .iter()
        .find(|unit| unit.filename == artifact.filename)
        .context("unknown artifact")?;
    let product = &plan.config.products[unit.product];
    let target = &plan.config.targets[unit.target];
    let mut names = BTreeSet::new();
    for binary in &product.binaries {
        let name = target.binary_name(binary);
        ensure!(
            content.get(&name).is_some_and(|item| item.executable),
            "archive binary missing or not executable: {name}"
        );
        ensure!(names.insert(name), "duplicate contract binary");
    }
    for asset in &product.assets {
        ensure!(
            names.insert(asset.path.clone()),
            "duplicate contract member"
        );
        let item = content
            .get(&asset.path)
            .context("declared asset is absent")?;
        ensure!(
            !item.executable,
            "resource unexpectedly executable: {}",
            asset.path
        );
        if !asset.source.starts_with("{generated}/") {
            ensure!(
                digest(&item.bytes) == file_digest(&safe_join(root, &asset.source)?)?,
                "archive resource bytes differ from tracked source: {}",
                asset.path
            );
        }
    }
    ensure!(
        names == content.keys().cloned().collect(),
        "archive has extra or missing contract members"
    );
    Ok(())
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    crate::cohort::io::read_json(path)
}

fn save_receipt(output: &Path, receipt: &mut Receipt) -> Result<()> {
    receipt.updated_at_ms = now_ms()
        .max(receipt.updated_at_ms)
        .max(receipt.finished_at_ms.unwrap_or_default());
    let temporary = safe_join(output, "receipt.json.tmp")?;
    fs::write(&temporary, serde_json::to_vec_pretty(receipt)?)?;
    fs::rename(temporary, safe_join(output, "receipt.json")?)?;
    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn remove_selections(output: &Path) {
    let _ = fs::remove_dir_all(output.join("verified"));
    let _ = fs::remove_dir_all(output.join("build-only"));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running_receipt() -> Receipt {
        Receipt {
            schema: SCHEMA,
            implementation: IMPLEMENTATION.into(),
            plan_id: "a".repeat(64),
            status: "running".into(),
            publication_ready: false,
            started_at_ms: 100,
            updated_at_ms: 200,
            finished_at_ms: None,
            toolchain: BTreeMap::new(),
            tasks: vec![TaskResult {
                id: "u0-build-0".into(),
                state: TaskState::Running,
                elapsed_ms: 0,
                error: None,
                log: Some("logs/u0-build-0".into()),
            }],
            artifacts: vec![],
            error: None,
        }
    }

    fn write_snapshot(output: &Path, receipt: &Receipt) {
        fs::write(
            output.join("receipt.json"),
            serde_json::to_vec(receipt).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn unfinished_snapshot_is_readable_without_source_or_process() {
        let temporary = tempfile::tempdir().unwrap();
        let receipt = running_receipt();
        write_snapshot(temporary.path(), &receipt);
        let saved = status(temporary.path()).unwrap();
        assert_eq!(saved.status, "running");
        assert_eq!(saved.updated_at_ms, 200);
        assert!(saved.finished_at_ms.is_none());
        assert!(matches!(saved.tasks[0].state, TaskState::Running));
    }

    #[test]
    fn snapshot_rejects_duplicates_unsafe_logs_and_inconsistent_completion() {
        let temporary = tempfile::tempdir().unwrap();
        let mut receipt = running_receipt();
        receipt.tasks.push(receipt.tasks[0].clone());
        write_snapshot(temporary.path(), &receipt);
        assert!(status(temporary.path()).is_err());
        receipt = running_receipt();
        receipt.tasks[0].log = Some("../outside".into());
        write_snapshot(temporary.path(), &receipt);
        assert!(status(temporary.path()).is_err());
        receipt = running_receipt();
        receipt.finished_at_ms = Some(150);
        write_snapshot(temporary.path(), &receipt);
        assert!(status(temporary.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn attempt_rejects_dangling_leaf_symlink() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("source");
        fs::create_dir(&root).unwrap();
        let output = temporary.path().join("attempt");
        std::os::unix::fs::symlink(temporary.path().join("absent"), &output).unwrap();
        assert!(fresh_attempt(&root.canonicalize().unwrap(), &output).is_err());
    }
}
