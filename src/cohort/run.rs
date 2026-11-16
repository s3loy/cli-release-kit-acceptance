use super::{crypto, io, model::*, plan};
use crate::{
    config::safe_join,
    source,
    v2::{
        self,
        model::{Action, Task, TaskResult, TaskState},
    },
};
use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::SigningKey;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    time::Instant,
};

const SKIP_REASON: &str = "runtime verification disabled by assignment";

pub fn execute(
    root: &Path,
    plan: &Plan,
    assignment: &Assignment,
    output: &Path,
    resume: bool,
    allow_retry: &[usize],
    signer: Option<&SigningKey>,
) -> Result<RunReceipt> {
    let root = source::root(root)?;
    plan::validate(&root, plan)?;
    ensure!(
        plan.engine_source_id == ENGINE_SOURCE_ID,
        "execution requires the engine source identity approved by the plan"
    );
    plan::validate_assignment(plan, assignment)?;
    validate_signer(assignment, signer)?;
    ensure!(
        allow_retry
            .iter()
            .all(|unit| assignment.units.contains(unit)),
        "retry override contains a unit outside the assignment"
    );
    let output = attempt_directory(&root, output, resume)?;
    // The lock file remains in place: deleting it would allow two different
    // inodes to represent the same attempt's writer lock.
    let _writer = lock_attempt(&output)?;

    let mut receipt = if resume {
        let saved_plan: Plan = io::read_json(&safe_join(&output, "plan.json")?)?;
        let saved_assignment: Assignment = io::read_json(&safe_join(&output, "assignment.json")?)?;
        ensure!(
            saved_plan == *plan,
            "resume plan differs from the immutable saved plan"
        );
        ensure!(
            saved_assignment == *assignment,
            "resume assignment differs from the immutable saved assignment"
        );
        status(&output)?
    } else {
        io::write_json_atomic(&output.join("plan.json"), plan)?;
        io::write_json_atomic(&output.join("assignment.json"), assignment)?;
        fs::create_dir(output.join("units"))?;
        fs::create_dir(output.join("invocations"))?;
        new_receipt(plan, assignment)
    };
    ensure!(
        receipt.plan_id == plan.id
            && receipt.assignment_id == assignment.id
            && receipt.engine_source_id == plan.engine_source_id,
        "receipt belongs to another plan, assignment or engine"
    );

    let completed = scan_units(&root, plan, assignment, &output)?;
    for (unit, id) in &receipt.units {
        ensure!(
            completed.get(unit).is_some_and(|record| &record.id == id),
            "previously recorded unit checkpoint is missing or changed: {unit}"
        );
    }
    receipt.units = completed
        .iter()
        .map(|(unit, record)| (*unit, record.id.clone()))
        .collect();
    interrupt_old_invocations(&mut receipt);

    let unsafe_units = assignment
        .units
        .iter()
        .copied()
        .filter(|unit| {
            !completed.contains_key(unit)
                && has_hooks(plan, *unit)
                && previously_started(plan, &receipt, *unit)
                && !assignment.retry_safe_units.contains(unit)
                && !allow_retry.contains(unit)
        })
        .collect::<Vec<_>>();
    if !unsafe_units.is_empty() {
        let unit_ids = unsafe_units
            .iter()
            .map(|unit| plan.units[*unit].id.as_str())
            .collect::<Vec<_>>();
        let message = format!(
            "incomplete units with hooks need a retry decision: {unit_ids:?}; explicitly allow retry with --allow-retry UNIT_ID or start a new assignment"
        );
        receipt.status = "needs-decision".into();
        receipt.error = Some(message.clone());
        receipt.finished_at_ms = Some(io::now_ms().max(receipt.updated_at_ms));
        save_receipt(&output, &mut receipt)?;
        bail!(message);
    }

    let invocation_id = io::random_id()?;
    let invocation_dir = safe_join(&safe_join(&output, "invocations")?, &invocation_id)?;
    fs::create_dir(&invocation_dir)?;
    let selected = plan::tasks_for_units(plan, &assignment.units)?;
    let tasks = selected
        .into_iter()
        .filter(|task| v2::run::task_unit(task).is_none_or(|unit| !completed.contains_key(&unit)))
        .collect::<Vec<_>>();
    let started = io::now_ms().max(receipt.updated_at_ms);
    let mut execution = execution_receipt(plan, &tasks, started);
    receipt.status = "running".into();
    receipt.error = None;
    receipt.finished_at_ms = None;
    receipt.invocations.push(Invocation {
        id: invocation_id.clone(),
        status: "running".into(),
        started_at_ms: started,
        finished_at_ms: None,
        tasks: execution.tasks.clone(),
        toolchain: BTreeMap::new(),
        error: None,
    });
    save_receipt(&output, &mut receipt)?;

    let result = (|| -> Result<()> {
        execution.toolchain.insert(
            "engine_sha256".into(),
            source::file_digest(&std::env::current_exe()?)?,
        );
        sync_invocation(&mut receipt, &execution);
        save_receipt(&output, &mut receipt)?;
        validate_execution_source(&root, plan, assignment)?;
        let checkout = clone_source(&root, plan, &invocation_dir)?;
        plan::validate(&checkout, plan)?;
        validate_execution_source(&checkout, plan, assignment)?;
        fs::create_dir(invocation_dir.join("staging"))?;
        fs::create_dir(invocation_dir.join("work"))?;
        for unit in assignment
            .units
            .iter()
            .filter(|unit| !completed.contains_key(unit))
        {
            fs::create_dir(
                invocation_dir
                    .join("work")
                    .join(format!("generated-{unit}")),
            )?;
            fs::create_dir(invocation_dir.join("work").join(format!("build-{unit}")))?;
        }
        let view = plan::as_v2(plan);
        // Probe all selected units before deciding whether any checkpoint can
        // be reused. Old evidence is never relabeled with this invocation's tools.
        for (index, task) in tasks
            .iter()
            .enumerate()
            .filter(|(_, task)| matches!(task.action, Action::Probe { .. }))
        {
            run_task(
                &checkout,
                &view,
                &output,
                &invocation_dir,
                task,
                index,
                assignment.skip_runtime,
                &mut execution,
                &mut receipt,
            )?;
        }
        for (unit, record) in &completed {
            ensure!(
                record.toolchain == unit_toolchain(plan, *unit, &execution.toolchain)?,
                "toolchain changed for completed unit {unit}; start a new plan and attempt instead of reusing old evidence"
            );
        }
        let terminal = assignment
            .units
            .iter()
            .filter(|unit| !completed.contains_key(unit))
            .map(|unit| {
                let id = tasks
                    .iter()
                    .rev()
                    .find(|task| v2::run::task_unit(task) == Some(*unit))
                    .context("selected unit has no task chain")?
                    .id
                    .clone();
                Ok((*unit, id))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        for (index, task) in tasks
            .iter()
            .enumerate()
            .filter(|(_, task)| !matches!(task.action, Action::Probe { .. }))
        {
            ensure!(
                !matches!(task.action, Action::Seal),
                "cohort execution cannot run legacy seal"
            );
            run_task(
                &checkout,
                &view,
                &output,
                &invocation_dir,
                task,
                index,
                assignment.skip_runtime,
                &mut execution,
                &mut receipt,
            )?;
            if let Some(unit) = v2::run::task_unit(task)
                && terminal.get(&unit) == Some(&task.id)
            {
                let record = commit_unit(
                    &checkout,
                    plan,
                    assignment,
                    &output,
                    &invocation_dir,
                    &invocation_id,
                    unit,
                    &execution,
                    signer,
                )?;
                receipt.units.insert(unit, record.id);
                save_receipt(&output, &mut receipt)?;
            }
        }
        ensure!(
            receipt.units.len() == assignment.units.len(),
            "assignment did not complete all selected units"
        );
        Ok(())
    })();
    if let Err(error) = result {
        let message = format!("{error:#}");
        sync_invocation(&mut receipt, &execution);
        let invocation = receipt
            .invocations
            .last_mut()
            .context("missing invocation")?;
        invocation.status = "failed".into();
        invocation.error = Some(message.clone());
        invocation.finished_at_ms = Some(io::now_ms().max(invocation.started_at_ms));
        block_unfinished(&mut invocation.tasks, "invocation stopped after a failure");
        receipt.status = "failed".into();
        receipt.error = Some(message);
        receipt.finished_at_ms = Some(io::now_ms().max(receipt.updated_at_ms));
        save_receipt(&output, &mut receipt).with_context(|| {
            format!("attempt failed ({error:#}); could not save failure receipt")
        })?;
        return Err(error);
    }
    let finished = io::now_ms().max(receipt.updated_at_ms);
    receipt.status = completion_status(assignment).into();
    receipt.finished_at_ms = Some(finished);
    let invocation = receipt
        .invocations
        .last_mut()
        .context("missing invocation")?;
    invocation.status = receipt.status.clone();
    invocation.finished_at_ms = Some(finished.max(invocation.started_at_ms));
    save_receipt(&output, &mut receipt)?;
    Ok(receipt)
}

fn completion_status(assignment: &Assignment) -> &'static str {
    if assignment.skip_runtime {
        "build-only"
    } else {
        "complete"
    }
}

fn validate_signer(assignment: &Assignment, signer: Option<&SigningKey>) -> Result<()> {
    match (&assignment.trusted_key, signer) {
        (Some(expected), Some(key)) => ensure!(
            *expected == crypto::public_key(key),
            "signing key differs from assignment trusted key"
        ),
        (Some(_), None) => bail!("trusted rebuild assignment requires its signing key"),
        (None, Some(_)) => bail!("unsigned candidate assignment cannot use a signing key"),
        (None, None) => (),
    }
    Ok(())
}

pub(crate) fn attempt_directory(root: &Path, output: &Path, resume: bool) -> Result<PathBuf> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()
        .context("attempt parent must already exist")?;
    let name = output
        .file_name()
        .and_then(|name| name.to_str())
        .context("attempt must name a UTF-8 directory")?;
    let output = safe_join(&parent, name)?;
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
        crate::process::capture(
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
        ensure!(
            source::git(root, &["ls-files", "--", relative])?.is_empty(),
            "attempt overlaps tracked source inputs"
        );
    }
    if resume {
        let meta = fs::symlink_metadata(&output)?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "attempt must be a regular directory"
        );
        Ok(output)
    } else {
        io::fresh_directory(&output)
    }
}

pub(crate) fn lock_attempt(output: &Path) -> Result<io::WriterLock> {
    let path = safe_join(output, ".writer.lock")?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    let meta = file.metadata()?;
    ensure!(meta.is_file(), "attempt writer lock is not a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            meta.nlink() == 1,
            "attempt writer lock must not be hardlinked"
        );
    }
    io::WriterLock::acquire(file)
        .context("attempt already has a writer or cannot acquire its advisory lock")
}

fn new_receipt(plan: &Plan, assignment: &Assignment) -> RunReceipt {
    let now = io::now_ms();
    RunReceipt {
        schema: SCHEMA,
        plan_id: plan.id.clone(),
        assignment_id: assignment.id.clone(),
        engine_source_id: plan.engine_source_id.clone(),
        status: "running".into(),
        started_at_ms: now,
        updated_at_ms: now,
        finished_at_ms: None,
        invocations: Vec::new(),
        units: BTreeMap::new(),
        error: None,
    }
}

fn execution_receipt(plan: &Plan, tasks: &[Task], now: u64) -> v2::model::Receipt {
    v2::model::Receipt {
        schema: v2::model::SCHEMA,
        implementation: plan.implementation.clone(),
        plan_id: plan.id.clone(),
        status: "running".into(),
        publication_ready: false,
        started_at_ms: now,
        updated_at_ms: now,
        finished_at_ms: None,
        toolchain: BTreeMap::new(),
        tasks: tasks
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
    }
}

fn validate_execution_source(root: &Path, plan: &Plan, assignment: &Assignment) -> Result<()> {
    let products = assignment
        .units
        .iter()
        .map(|unit| plan.units[*unit].product)
        .collect::<BTreeSet<_>>();
    for product in products {
        v2::builder::validate_offline(
            root,
            &plan.config.products[product],
            &plan.resolved[product],
            &plan.source.files,
        )?;
    }
    Ok(())
}

fn clone_source(root: &Path, plan: &Plan, invocation: &Path) -> Result<PathBuf> {
    clone_source_at(
        root,
        &plan.source.commit,
        plan.config.timeout_seconds,
        invocation,
    )
}

pub(crate) fn clone_source_at(
    root: &Path,
    commit: &str,
    timeout_seconds: u64,
    invocation: &Path,
) -> Result<PathBuf> {
    let checkout = safe_join(invocation, "source")?;
    let hooks = safe_join(invocation, "empty-git-hooks")?;
    fs::create_dir(&hooks)?;
    let hooks = hooks.to_str().context("non-UTF8 hooks directory")?;
    let mut commands =
        crate::process::Commands::new(root, &invocation.join("logs"), timeout_seconds)?;
    commands.run(
        &[
            "git".into(),
            "-c".into(),
            format!("core.hooksPath={hooks}"),
            "clone".into(),
            "--no-hardlinks".into(),
            "--no-checkout".into(),
            "--".into(),
            root.to_str().context("non-UTF8 source path")?.into(),
            checkout.to_str().context("non-UTF8 checkout path")?.into(),
        ],
        "clone-source",
        &BTreeMap::new(),
    )?;
    crate::process::Commands::new(&checkout, &invocation.join("logs"), timeout_seconds)?.run(
        &[
            "git".into(),
            "-c".into(),
            format!("core.hooksPath={hooks}"),
            "checkout".into(),
            "--detach".into(),
            commit.to_owned(),
        ],
        "checkout-source",
        &BTreeMap::new(),
    )?;
    Ok(checkout)
}

#[allow(clippy::too_many_arguments)]
fn run_task(
    root: &Path,
    plan: &v2::model::Plan,
    output: &Path,
    invocation: &Path,
    task: &Task,
    index: usize,
    skip: bool,
    execution: &mut v2::model::Receipt,
    receipt: &mut RunReceipt,
) -> Result<()> {
    let started = Instant::now();
    let result = (|| -> Result<()> {
        for dependency in &task.depends_on {
            let result = execution
                .tasks
                .iter()
                .find(|result| result.id == *dependency)
                .context("task dependency is absent")?;
            ensure!(
                matches!(result.state, TaskState::Succeeded | TaskState::Skipped),
                "task dependency did not complete: {dependency}"
            );
        }
        if skip && task.runtime {
            execution.tasks[index].state = TaskState::Skipped;
            execution.tasks[index].error = Some(SKIP_REASON.into());
            return Ok(());
        }
        execution.tasks[index].state = TaskState::Running;
        execution.tasks[index].log = v2::run::command(task).map(|_| format!("logs/{}", task.id));
        sync_invocation(receipt, execution);
        save_receipt(output, receipt)?;
        v2::run::perform(root, plan, invocation, task, skip, execution)?;
        execution.tasks[index].state = TaskState::Succeeded;
        Ok(())
    })();
    execution.tasks[index].elapsed_ms =
        started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    if let Err(error) = &result {
        execution.tasks[index].state = TaskState::Failed;
        execution.tasks[index].error = Some(format!("{error:#}"));
    }
    sync_invocation(receipt, execution);
    save_receipt(output, receipt)?;
    result.with_context(|| format!("task {} failed", task.id))
}

fn sync_invocation(receipt: &mut RunReceipt, execution: &v2::model::Receipt) {
    if let Some(invocation) = receipt.invocations.last_mut() {
        invocation.tasks = execution.tasks.clone();
        invocation.toolchain = execution.toolchain.clone();
    }
}

pub(crate) fn journal_time(
    started_at_ms: u64,
    updated_at_ms: u64,
    finished_at_ms: Option<u64>,
    invocations: &[Invocation],
) -> u64 {
    invocations.iter().fold(
        io::now_ms()
            .max(started_at_ms)
            .max(updated_at_ms)
            .max(finished_at_ms.unwrap_or_default()),
        |time, invocation| {
            time.max(invocation.started_at_ms)
                .max(invocation.finished_at_ms.unwrap_or_default())
        },
    )
}
fn save_receipt(output: &Path, receipt: &mut RunReceipt) -> Result<()> {
    receipt.updated_at_ms = journal_time(
        receipt.started_at_ms,
        receipt.updated_at_ms,
        receipt.finished_at_ms,
        &receipt.invocations,
    );
    io::write_json_atomic(&safe_join(output, "receipt.json")?, receipt)
}

fn block_unfinished(tasks: &mut [TaskResult], reason: &str) {
    for task in tasks {
        if matches!(task.state, TaskState::Pending | TaskState::Running) {
            task.state = TaskState::Blocked;
            task.error = Some(reason.into());
        }
    }
}

pub(crate) fn interrupt_invocations(
    invocations: &mut [Invocation],
    floor: u64,
    reason: &str,
    task_reason: &str,
) {
    for invocation in invocations {
        if invocation.status == "running" {
            invocation.status = "interrupted".into();
            invocation.error = Some(reason.into());
            invocation.finished_at_ms = Some(io::now_ms().max(floor).max(invocation.started_at_ms));
            block_unfinished(&mut invocation.tasks, task_reason);
        }
    }
}
fn interrupt_old_invocations(receipt: &mut RunReceipt) {
    interrupt_invocations(
        &mut receipt.invocations,
        receipt.updated_at_ms,
        "previous writer stopped before completing its invocation",
        "previous invocation was interrupted",
    );
}

fn has_hooks(plan: &Plan, unit: usize) -> bool {
    let product = &plan.config.products[plan.units[unit].product];
    !product.prepare.is_empty() || !product.checks.is_empty()
}

fn previously_started(plan: &Plan, receipt: &RunReceipt, unit: usize) -> bool {
    let ids = plan
        .tasks
        .iter()
        .filter(|task| v2::run::task_unit(task) == Some(unit))
        .map(|task| task.id.as_str())
        .collect::<BTreeSet<_>>();
    receipt
        .invocations
        .iter()
        .flat_map(|invocation| &invocation.tasks)
        .any(|task| {
            ids.contains(task.id.as_str())
                && (task.log.is_some()
                    || matches!(
                        task.state,
                        TaskState::Running
                            | TaskState::Succeeded
                            | TaskState::Failed
                            | TaskState::Skipped
                    ))
        })
}

fn unit_toolchain(
    plan: &Plan,
    unit: usize,
    observed: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let tasks = plan::tasks_for_units(plan, &[unit])?;
    let mut keys = BTreeSet::from(["engine_sha256".to_string()]);
    for task in &tasks {
        if let Action::Probe { key, .. } = &task.action {
            ensure!(keys.insert(key.clone()), "duplicate unit probe key");
        }
    }
    keys.into_iter()
        .map(|key| {
            let value = observed
                .get(&key)
                .with_context(|| format!("missing unit tool identity: {key}"))?;
            ensure!(!value.trim().is_empty(), "empty unit tool identity: {key}");
            Ok((key, value.clone()))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn commit_unit(
    root: &Path,
    plan: &Plan,
    assignment: &Assignment,
    output: &Path,
    invocation: &Path,
    invocation_id: &str,
    unit: usize,
    execution: &v2::model::Receipt,
    signer: Option<&SigningKey>,
) -> Result<UnitRecord> {
    let ids = plan::task_ids_for_unit(plan, unit)?;
    let tasks = ids
        .iter()
        .map(|id| {
            execution
                .tasks
                .iter()
                .find(|task| task.id == *id)
                .cloned()
                .context("completed unit task is absent")
        })
        .collect::<Result<Vec<_>>>()?;
    let artifact = execution
        .artifacts
        .iter()
        .find(|artifact| artifact.filename == plan.units[unit].filename)
        .cloned()
        .context("completed unit artifact is absent")?;
    let mut record = UnitRecord {
        schema: SCHEMA,
        id: String::new(),
        plan_id: plan.id.clone(),
        assignment_id: assignment.id.clone(),
        engine_source_id: plan.engine_source_id.clone(),
        unit,
        invocation: invocation_id.into(),
        status: completion_status(assignment).into(),
        toolchain: unit_toolchain(plan, unit, &execution.toolchain)?,
        tasks,
        candidate_match: assignment
            .candidate
            .as_ref()
            .and_then(|candidate| candidate.digests.get(&unit))
            .map(|expected| expected == &artifact.sha256),
        artifact,
        proof: None,
    };
    if let Some(signer) = signer {
        crypto::seal_unit(&mut record, signer)?;
    } else {
        record.id = crypto::unit_id(&record)?;
    }
    let units = safe_join(output, "units")?;
    let temporary = safe_join(&units, &format!(".pending-{}", io::random_id()?))?;
    fs::create_dir(&temporary)?;
    let source_path = safe_join(
        &safe_join(invocation, "staging")?,
        &record.artifact.filename,
    )?;
    let expected = FileEntry {
        sha256: record.artifact.sha256.clone(),
        size: fs::symlink_metadata(&source_path)?.len(),
    };
    io::copy_file_checked(
        &source_path,
        &safe_join(&temporary, &record.artifact.filename)?,
        &expected,
    )?;
    io::write_json_atomic(&temporary.join("unit.json"), &record)?;
    validate_record(root, plan, assignment, &temporary, unit, &record)?;
    io::sync_directory(&temporary)?;
    let destination = safe_join(&units, &unit.to_string())?;
    ensure!(
        matches!(fs::symlink_metadata(&destination), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
        "completed unit checkpoint already exists: {unit}"
    );
    fs::rename(&temporary, &destination)?;
    io::sync_directory(&units)?;
    Ok(record)
}

fn scan_units(
    root: &Path,
    plan: &Plan,
    assignment: &Assignment,
    output: &Path,
) -> Result<BTreeMap<usize, UnitRecord>> {
    let units = safe_join(output, "units")?;
    let meta = fs::symlink_metadata(&units)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "unit checkpoint root must be a regular directory"
    );
    let mut completed = BTreeMap::new();
    for entry in fs::read_dir(&units)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF8 unit checkpoint name"))?;
        let meta = fs::symlink_metadata(entry.path())?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "unit checkpoint must be a regular directory"
        );
        if let Some(id) = name.strip_prefix(".pending-") {
            ensure!(is_invocation_id(id), "invalid temporary checkpoint name");
            continue;
        }
        let unit = name
            .parse::<usize>()
            .context("unexpected unit checkpoint directory")?;
        ensure!(
            unit.to_string() == name && assignment.units.contains(&unit),
            "checkpoint is outside the assignment"
        );
        let record = read_unit_validated(root, plan, assignment, output, unit)?;
        ensure!(
            completed.insert(unit, record).is_none(),
            "duplicate unit checkpoint"
        );
    }
    Ok(completed)
}

pub fn read_unit(
    root: &Path,
    plan: &Plan,
    assignment: &Assignment,
    attempt: &Path,
    unit: usize,
) -> Result<UnitRecord> {
    let root = source::root(root)?;
    plan::validate(&root, plan)?;
    plan::validate_assignment(plan, assignment)?;
    read_unit_validated(&root, plan, assignment, attempt, unit)
}

fn read_unit_validated(
    root: &Path,
    plan: &Plan,
    assignment: &Assignment,
    attempt: &Path,
    unit: usize,
) -> Result<UnitRecord> {
    ensure!(
        assignment.units.contains(&unit),
        "unit is outside the assignment"
    );
    let directory = safe_join(&safe_join(attempt, "units")?, &unit.to_string())?;
    let record = io::read_json(&safe_join(&directory, "unit.json")?)?;
    validate_record(root, plan, assignment, &directory, unit, &record)?;
    Ok(record)
}

fn validate_record(
    root: &Path,
    plan: &Plan,
    assignment: &Assignment,
    directory: &Path,
    unit: usize,
    record: &UnitRecord,
) -> Result<()> {
    let planned = plan.units.get(unit).context("unknown checkpoint unit")?;
    ensure!(
        record.schema == SCHEMA
            && record.plan_id == plan.id
            && record.assignment_id == assignment.id
            && record.engine_source_id == plan.engine_source_id
            && record.unit == unit,
        "checkpoint belongs to another schema, plan, assignment, engine or unit"
    );
    ensure!(
        is_invocation_id(&record.invocation),
        "invalid checkpoint invocation id"
    );
    ensure!(
        record.id == crypto::unit_id(record)?,
        "unit record identity mismatch"
    );
    ensure!(
        record.status == completion_status(assignment),
        "unit completion status differs from assignment"
    );
    match &assignment.trusted_key {
        Some(key) => {
            ensure!(
                record
                    .proof
                    .as_ref()
                    .is_some_and(|proof| &proof.public_key == key),
                "unit proof key differs from assignment"
            );
            crypto::verify_unit_proof(record)?;
        }
        None => ensure!(
            record.proof.is_none(),
            "unsigned assignment contains a trusted unit proof"
        ),
    }
    let tasks = plan::tasks_for_units(plan, &[unit])?;
    ensure!(
        record.tasks.len() == tasks.len(),
        "unit task closure differs from canonical plan"
    );
    for (observed, task) in record.tasks.iter().zip(&tasks) {
        ensure!(
            observed.id == task.id,
            "unit task closure is missing or reordered"
        );
        if assignment.skip_runtime && task.runtime {
            ensure!(
                matches!(observed.state, TaskState::Skipped)
                    && observed.log.is_none()
                    && observed.error.as_deref() == Some(SKIP_REASON),
                "unit runtime skip evidence differs from assignment"
            );
        } else {
            ensure!(
                matches!(observed.state, TaskState::Succeeded) && observed.error.is_none(),
                "unit contains an incomplete or unsuccessful task"
            );
            ensure!(
                observed.log == v2::run::command(task).map(|_| format!("logs/{}", task.id)),
                "unit task log reference differs from canonical plan"
            );
        }
    }
    ensure!(
        record.toolchain == unit_toolchain(plan, unit, &record.toolchain)?,
        "unit has missing or extra tool identities"
    );
    ensure!(
        is_digest(&record.toolchain["engine_sha256"]),
        "invalid unit engine digest"
    );
    if !assignment.skip_runtime {
        ensure!(
            v2::builder::can_run(
                &plan.config.targets[planned.target],
                &planned.recipe,
                &record.toolchain
            ),
            "saved toolchain cannot support claimed unit runtime verification"
        );
    }
    ensure!(
        record.artifact.filename == planned.filename,
        "checkpoint artifact differs from planned unit"
    );
    ensure!(
        is_digest(&record.artifact.sha256),
        "invalid checkpoint artifact digest"
    );
    let expected_match = assignment
        .candidate
        .as_ref()
        .and_then(|candidate| candidate.digests.get(&unit))
        .map(|expected| expected == &record.artifact.sha256);
    ensure!(
        record.candidate_match == expected_match,
        "candidate comparison differs from assignment and rebuilt artifact"
    );
    let actual = fs::read_dir(directory)?
        .map(|entry| {
            let entry = entry?;
            let meta = fs::symlink_metadata(entry.path())?;
            ensure!(
                meta.is_file() && !meta.file_type().is_symlink(),
                "checkpoint entry must be a regular file"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                ensure!(meta.nlink() == 1, "checkpoint file must not be hardlinked");
            }
            entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 checkpoint member"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        actual == BTreeSet::from(["unit.json".into(), planned.filename.clone()]),
        "checkpoint contains missing or extra files"
    );
    v2::run::check_artifact(root, &plan::as_v2(plan), &record.artifact, directory)?;
    Ok(())
}

/// Return a persisted snapshot; a running status is not a liveness claim.
pub fn status(output: &Path) -> Result<RunReceipt> {
    let meta = fs::symlink_metadata(output)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "attempt must be a regular directory"
    );
    let receipt: RunReceipt = io::read_json(&safe_join(output, "receipt.json")?)?;
    ensure!(
        receipt.schema == SCHEMA && is_digest(&receipt.engine_source_id),
        "unsupported receipt schema or engine source identity"
    );
    ensure!(
        is_digest(&receipt.plan_id) && is_digest(&receipt.assignment_id),
        "invalid receipt plan or assignment identity"
    );
    validate_invocation_journal(
        &receipt.status,
        receipt.started_at_ms,
        receipt.updated_at_ms,
        receipt.finished_at_ms,
        &receipt.error,
        &receipt.invocations,
    )?;
    ensure!(
        receipt.units.values().all(|id| is_digest(id)),
        "invalid completed unit identity"
    );
    Ok(receipt)
}

pub(crate) fn validate_invocation_journal(
    status: &str,
    started_at_ms: u64,
    updated_at_ms: u64,
    finished_at_ms: Option<u64>,
    error: &Option<String>,
    invocations: &[Invocation],
) -> Result<()> {
    ensure!(
        matches!(
            status,
            "running" | "complete" | "build-only" | "failed" | "needs-decision"
        ),
        "unknown receipt status"
    );
    validate_times(
        started_at_ms,
        updated_at_ms,
        finished_at_ms,
        status == "running",
    )?;
    ensure!(
        error_matches(status, error),
        "receipt error does not match its status"
    );
    let mut ids = BTreeSet::new();
    let mut running = 0;
    for invocation in invocations {
        ensure!(
            is_invocation_id(&invocation.id) && ids.insert(&invocation.id),
            "invalid or duplicate invocation identity"
        );
        ensure!(
            matches!(
                invocation.status.as_str(),
                "running" | "complete" | "build-only" | "failed" | "interrupted"
            ),
            "unknown invocation status"
        );
        validate_times(
            invocation.started_at_ms,
            updated_at_ms,
            invocation.finished_at_ms,
            invocation.status == "running",
        )?;
        ensure!(
            invocation.started_at_ms >= started_at_ms,
            "invocation precedes attempt"
        );
        ensure!(
            error_matches(&invocation.status, &invocation.error),
            "invocation error does not match its status"
        );
        running += usize::from(invocation.status == "running");
        let mut task_ids = BTreeSet::new();
        let mut running_tasks = 0;
        for task in &invocation.tasks {
            ensure!(
                !task.id.is_empty()
                    && task
                        .id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    && task_ids.insert(&task.id),
                "invalid or duplicate invocation task id"
            );
            ensure!(
                task.log
                    .as_ref()
                    .is_none_or(|log| log == &format!("logs/{}", task.id)),
                "unsafe invocation task log reference"
            );
            let needs_error = matches!(
                task.state,
                TaskState::Failed | TaskState::Blocked | TaskState::Skipped
            );
            ensure!(
                if needs_error {
                    task.error.as_ref().is_some_and(|error| !error.is_empty())
                } else {
                    task.error.is_none()
                },
                "invocation task error does not match its state"
            );
            running_tasks += usize::from(matches!(task.state, TaskState::Running));
            ensure!(
                invocation.status == "running"
                    || !matches!(task.state, TaskState::Running | TaskState::Pending),
                "finished invocation still has unfinished tasks"
            );
            if matches!(invocation.status.as_str(), "complete" | "build-only") {
                ensure!(
                    matches!(task.state, TaskState::Succeeded | TaskState::Skipped),
                    "successful invocation contains an unsuccessful task"
                );
            }
        }
        ensure!(
            running_tasks <= 1,
            "serial invocation has several running tasks"
        );
    }
    ensure!(
        running <= 1 && (status == "running" || running == 0),
        "receipt and running invocations disagree"
    );
    Ok(())
}

pub fn verify_run(root: &Path, output: &Path) -> Result<RunReceipt> {
    let root = source::root(root)?;
    let plan: Plan = io::read_json(&safe_join(output, "plan.json")?)?;
    let assignment: Assignment = io::read_json(&safe_join(output, "assignment.json")?)?;
    plan::validate(&root, &plan)?;
    plan::validate_assignment(&plan, &assignment)?;
    let receipt = status(output)?;
    ensure!(
        receipt.plan_id == plan.id
            && receipt.assignment_id == assignment.id
            && receipt.engine_source_id == plan.engine_source_id,
        "receipt belongs to another plan, assignment or engine"
    );
    ensure!(
        receipt.status == completion_status(&assignment) && receipt.error.is_none(),
        "attempt is not a complete assignment result"
    );
    let completed = scan_units(&root, &plan, &assignment, output)?;
    ensure!(
        completed.keys().copied().collect::<Vec<_>>() == assignment.units,
        "assignment checkpoint coverage is incomplete"
    );
    ensure!(
        receipt.units
            == completed
                .iter()
                .map(|(unit, record)| (*unit, record.id.clone()))
                .collect(),
        "receipt checkpoint identities differ from committed units"
    );
    Ok(receipt)
}

fn validate_times(started: u64, updated: u64, finished: Option<u64>, running: bool) -> Result<()> {
    ensure!(
        updated >= started && running == finished.is_none(),
        "record timestamps are inconsistent"
    );
    if let Some(finished) = finished {
        ensure!(
            (started..=updated).contains(&finished),
            "completion timestamp is inconsistent"
        );
    }
    Ok(())
}

fn error_matches(status: &str, error: &Option<String>) -> bool {
    if matches!(status, "failed" | "needs-decision" | "interrupted") {
        error.as_ref().is_some_and(|error| !error.is_empty())
    } else {
        error.is_none()
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_invocation_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_lock_excludes_other_writers_and_is_reusable_after_release() {
        let directory = tempfile::tempdir().unwrap();
        let first = lock_attempt(directory.path()).unwrap();
        assert!(lock_attempt(directory.path()).is_err());
        assert!(directory.path().join(".writer.lock").is_file());
        drop(first);
        let next = lock_attempt(directory.path()).unwrap();
        assert!(lock_attempt(directory.path()).is_err());
        drop(next);
    }

    #[test]
    fn interruption_preserves_which_commands_might_have_started() {
        let mut tasks = vec![
            TaskResult {
                id: "u0-prepare-0".into(),
                state: TaskState::Running,
                elapsed_ms: 0,
                error: None,
                log: Some("logs/u0-prepare-0".into()),
            },
            TaskResult {
                id: "u1-prepare-0".into(),
                state: TaskState::Pending,
                elapsed_ms: 0,
                error: None,
                log: None,
            },
        ];
        block_unfinished(&mut tasks, "previous invocation was interrupted");
        assert!(
            tasks
                .iter()
                .all(|task| matches!(task.state, TaskState::Blocked))
        );
        assert_eq!(tasks[0].log.as_deref(), Some("logs/u0-prepare-0"));
        assert!(tasks[1].log.is_none());
        assert!(tasks.iter().all(|task| task.error.is_some()));
    }

    #[test]
    fn status_is_a_source_independent_snapshot_with_checked_state_transitions() {
        let directory = tempfile::tempdir().unwrap();
        let mut receipt = RunReceipt {
            schema: SCHEMA,
            plan_id: "a".repeat(64),
            assignment_id: "b".repeat(64),
            engine_source_id: ENGINE_SOURCE_ID.into(),
            status: "running".into(),
            started_at_ms: 1,
            updated_at_ms: 2,
            finished_at_ms: None,
            invocations: vec![Invocation {
                id: "c".repeat(32),
                status: "running".into(),
                started_at_ms: 2,
                finished_at_ms: None,
                tasks: vec![TaskResult {
                    id: "probe-0".into(),
                    state: TaskState::Running,
                    elapsed_ms: 0,
                    error: None,
                    log: Some("logs/probe-0".into()),
                }],
                toolchain: BTreeMap::new(),
                error: None,
            }],
            units: BTreeMap::new(),
            error: None,
        };
        let path = directory.path().join("receipt.json");
        io::write_json_atomic(&path, &receipt).unwrap();
        assert_eq!(status(directory.path()).unwrap().status, "running");
        receipt.status = "complete".into();
        receipt.finished_at_ms = Some(2);
        receipt.invocations[0].status = "complete".into();
        receipt.invocations[0].finished_at_ms = Some(2);
        io::write_json_atomic(&path, &receipt).unwrap();
        assert!(status(directory.path()).is_err());
        receipt.invocations[0].tasks[0].state = TaskState::Succeeded;
        io::write_json_atomic(&path, &receipt).unwrap();
        assert_eq!(status(directory.path()).unwrap().status, "complete");
    }
}
