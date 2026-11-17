use super::{inspect, model::*, native, plan, proof};
use crate::{
    archive,
    cohort::{
        crypto, io,
        model::{FileEntry, Invocation, Proof},
    },
    config::safe_join,
    source,
    v2::{
        self,
        model::{Action, Task, TaskResult, TaskState},
    },
};
use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::Instant,
};

const SKIP_REASON: &str = "runtime verification disabled by assignment";
#[derive(Clone, Debug, Default)]
pub struct RunOptions {
    pub units: Vec<usize>,
    pub retry_safe_units: Vec<usize>,
    pub skip_runtime: bool,
    pub trusted_key: Option<String>,
    pub candidate: Option<CandidateRef>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CandidateRef {
    pub bundle_id: String,
    pub digests: BTreeMap<usize, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub schema: u32,
    pub id: String,
    pub plan_id: String,
    pub units: Vec<usize>,
    pub retry_safe_units: Vec<usize>,
    pub skip_runtime: bool,
    pub trusted_key: Option<String>,
    pub candidate: Option<CandidateRef>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PayloadRecord {
    pub schema: u32,
    pub id: String,
    pub plan_id: String,
    pub assignment_id: String,
    pub engine_source_id: String,
    pub build: usize,
    pub invocation: String,
    pub status: String,
    pub toolchain: BTreeMap<String, String>,
    pub tasks: Vec<TaskResult>,
    pub files: PayloadManifest,
    pub proof: Option<Proof>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageRecord {
    pub schema: u32,
    pub id: String,
    pub plan_id: String,
    pub assignment_id: String,
    pub engine_source_id: String,
    pub package: usize,
    pub payload_id: String,
    pub status: String,
    pub toolchain: BTreeMap<String, String>,
    pub filename: String,
    pub sha256: String,
    pub size: u64,
    pub files: PayloadManifest,
    pub metadata: Option<PackageMetadata>,
    pub native_fields: BTreeMap<String, Vec<String>>,
    pub candidate_match: Option<bool>,
    pub proof: Option<Proof>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunReceipt {
    pub schema: u32,
    pub plan_id: String,
    pub assignment_id: String,
    pub engine_source_id: String,
    pub status: String,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub finished_at_ms: Option<u64>,
    pub invocations: Vec<Invocation>,
    pub payloads: BTreeMap<usize, String>,
    pub packages: BTreeMap<usize, String>,
    pub error: Option<String>,
}
pub fn assignment_id(value: &Assignment) -> Result<String> {
    let mut copy = value.clone();
    copy.id.clear();
    proof::content_id(b"cli-release-kit/delivery-assignment/v1\0", &copy)
}
pub fn assignment(plan: &Plan, options: &RunOptions) -> Result<Assignment> {
    let mut units = options.units.clone();
    if units.is_empty() {
        units = (0..plan.builds.len()).collect();
    }
    units.sort_unstable();
    let mut retry = options.retry_safe_units.clone();
    retry.sort_unstable();
    let mut value = Assignment {
        schema: SCHEMA,
        id: String::new(),
        plan_id: plan.id.clone(),
        units,
        retry_safe_units: retry,
        skip_runtime: options.skip_runtime,
        trusted_key: options.trusted_key.clone(),
        candidate: options.candidate.clone(),
    };
    value.id = assignment_id(&value)?;
    validate_assignment(plan, &value)?;
    Ok(value)
}
pub fn validate_assignment(plan: &Plan, value: &Assignment) -> Result<()> {
    ensure!(
        value.schema == SCHEMA && value.plan_id == plan.id && value.id == assignment_id(value)?,
        "assignment belongs to another protocol or plan"
    );
    ensure!(
        !value.units.is_empty()
            && value.units.iter().all(|i| *i < plan.builds.len())
            && value.units.windows(2).all(|p| p[0] < p[1]),
        "invalid assigned build indices"
    );
    ensure!(
        value.retry_safe_units.windows(2).all(|p| p[0] < p[1])
            && value
                .retry_safe_units
                .iter()
                .all(|i| value.units.contains(i)),
        "invalid retry-safe build set"
    );
    if let Some(key) = &value.trusted_key {
        ensure!(is_digest(key), "invalid trusted key");
    }
    if let Some(candidate) = &value.candidate {
        ensure!(
            is_digest(&candidate.bundle_id) && !candidate.digests.is_empty(),
            "invalid candidate reference"
        );
        ensure!(
            candidate.digests.iter().all(|(i, d)| plan
                .packages
                .get(*i)
                .is_some_and(|p| value.units.contains(&p.build))
                && is_digest(d)),
            "candidate packages outside assignment"
        );
        ensure!(
            value.trusted_key.is_some(),
            "candidate comparison requires a fresh trusted rebuild assignment"
        );
    }
    Ok(())
}
pub fn selected_packages(plan: &Plan, assignment: &Assignment) -> Vec<usize> {
    plan.packages
        .iter()
        .enumerate()
        .filter(|(_, p)| assignment.units.contains(&p.build))
        .map(|(i, _)| i)
        .collect()
}
pub(crate) fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn completion(assignment: &Assignment) -> &'static str {
    if assignment.skip_runtime {
        "build-only"
    } else {
        "complete"
    }
}
fn runtime_view(plan: &Plan) -> Result<v2::model::Plan> {
    let mut view = plan::build_view(plan)?;
    let probes = view
        .tasks
        .iter()
        .filter_map(|task| {
            if let Action::Probe { key, .. } = &task.action {
                Some((task.id.clone(), key.clone()))
            } else {
                None
            }
        })
        .collect::<BTreeMap<_, _>>();
    for task in &mut view.tasks {
        if let Some(build) = v2::run::task_unit(task) {
            let needed = v2::builder::probes(std::slice::from_ref(
                &view.config.products[view.units[build].product],
            ))
            .into_iter()
            .map(|(key, _)| key)
            .collect::<BTreeSet<_>>();
            task.depends_on
                .retain(|id| probes.get(id).is_none_or(|key| needed.contains(key)));
        }
    }
    Ok(view)
}
fn tasks_for(view: &v2::model::Plan, build: usize) -> Vec<Task> {
    let needed = v2::builder::probes(std::slice::from_ref(
        &view.config.products[view.units[build].product],
    ))
    .into_iter()
    .map(|(key, _)| key)
    .collect::<BTreeSet<_>>();
    view.tasks
        .iter()
        .filter(|task| match &task.action {
            Action::Probe { key, .. } => needed.contains(key),
            _ => v2::run::task_unit(task) == Some(build),
        })
        .cloned()
        .collect()
}
pub(crate) fn validate_probe_outputs(tools: &BTreeMap<String, String>) -> Result<()> {
    for (key, value) in tools {
        if key.starts_with("go:") {
            let words = value.split_whitespace().collect::<Vec<_>>();
            ensure!(
                words.len() == 4
                    && words[0] == "go"
                    && words[1] == "version"
                    && words[2].starts_with("go")
                    && words[3].contains('/'),
                "invalid Go probe identity"
            );
        }
        if key.starts_with("cargo:") {
            ensure!(
                value.starts_with("cargo ")
                    && value
                        .split_whitespace()
                        .nth(1)
                        .is_some_and(|v| v.chars().next().is_some_and(|c| c.is_ascii_digit())),
                "invalid Cargo probe identity"
            );
        }
        if key.starts_with("rustc:") {
            ensure!(
                value.starts_with("rustc ")
                    && value
                        .lines()
                        .filter(|line| line.starts_with("host: "))
                        .count()
                        == 1
                    && value.lines().any(|line| line.starts_with("release: ")),
                "invalid rustc probe identity"
            );
        }
    }
    Ok(())
}
fn build_tools(
    view: &v2::model::Plan,
    build: usize,
    observed: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let mut keys = BTreeSet::from(["engine_sha256".to_string()]);
    for task in tasks_for(view, build) {
        if let Action::Probe { key, .. } = task.action {
            keys.insert(format!("executable:{key}"));
            keys.insert(format!("launcher:{key}"));
            keys.insert(key);
        }
    }
    keys.into_iter()
        .map(|key| {
            Ok((
                key.clone(),
                observed
                    .get(&key)
                    .with_context(|| format!("missing tool identity: {key}"))?
                    .clone(),
            ))
        })
        .collect()
}
fn execution(plan: &Plan, tasks: &[Task]) -> v2::model::Receipt {
    let now = io::now_ms();
    v2::model::Receipt {
        schema: 2,
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
        artifacts: vec![],
        error: None,
    }
}
fn save(output: &Path, receipt: &mut RunReceipt) -> Result<()> {
    receipt.updated_at_ms = crate::cohort::run::journal_time(
        receipt.started_at_ms,
        receipt.updated_at_ms,
        receipt.finished_at_ms,
        &receipt.invocations,
    );
    io::write_json_atomic(&safe_join(output, "receipt.json")?, receipt)
}
fn sync(receipt: &mut RunReceipt, execution: &v2::model::Receipt) {
    if let Some(invocation) = receipt.invocations.last_mut() {
        invocation.tasks = execution.tasks.clone();
        invocation.toolchain = execution.toolchain.clone();
    }
}
#[allow(clippy::too_many_arguments)]
fn task(
    root: &Path,
    view: &v2::model::Plan,
    output: &Path,
    invocation: &Path,
    task: &Task,
    index: usize,
    skip: bool,
    execution: &mut v2::model::Receipt,
    receipt: &mut RunReceipt,
    staged: &mut BTreeMap<usize, PayloadManifest>,
) -> Result<()> {
    let started = Instant::now();
    let result = (|| -> Result<()> {
        for dependency in &task.depends_on {
            ensure!(
                execution.tasks.iter().any(|r| r.id == *dependency
                    && matches!(r.state, TaskState::Succeeded | TaskState::Skipped)),
                "task dependency incomplete: {dependency}"
            );
        }
        if skip && task.runtime {
            execution.tasks[index].state = TaskState::Skipped;
            execution.tasks[index].error = Some(SKIP_REASON.into());
            return Ok(());
        }
        execution.tasks[index].state = TaskState::Running;
        execution.tasks[index].log = v2::run::command(task).map(|_| format!("logs/{}", task.id));
        sync(receipt, execution);
        save(output, receipt)?;
        if let Action::Archive { unit } = &task.action {
            ensure!(
                staged
                    .insert(*unit, stage_payload(root, view, invocation, *unit)?)
                    .is_none(),
                "payload was already staged"
            );
        } else {
            v2::run::perform(root, view, invocation, task, skip, execution)?;
        }
        execution.tasks[index].state = TaskState::Succeeded;
        Ok(())
    })();
    execution.tasks[index].elapsed_ms =
        started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
    if let Err(error) = &result {
        execution.tasks[index].state = TaskState::Failed;
        execution.tasks[index].error = Some(format!("{error:#}"));
    }
    sync(receipt, execution);
    save(output, receipt)?;
    result.with_context(|| format!("task {} failed", task.id))
}
pub(crate) fn compiler_files(root: &Path, tasks: &[Task]) -> Result<BTreeMap<String, String>> {
    let mut identities = BTreeMap::new();
    for task in tasks {
        if let Action::Probe { key, command } = &task.action {
            let program = command.argv.first().context("empty compiler probe")?;
            let path = if Path::new(program).is_absolute() {
                PathBuf::from(program)
            } else {
                std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                    .map(|p| {
                        p.join(if cfg!(windows) && !program.ends_with(".exe") {
                            format!("{program}.exe")
                        } else {
                            program.clone()
                        })
                    })
                    .find(|p| p.is_file())
                    .with_context(|| format!("tool executable unavailable: {program}"))?
            }
            .canonicalize()?;
            identities.insert(format!("launcher:{key}"), source::file_digest(&path)?);
            let executable = if path.file_stem().and_then(|name| name.to_str()) == Some("rustup") {
                let directory = if command.cwd == "." {
                    root.to_path_buf()
                } else {
                    safe_join(root, &command.cwd)?
                };
                let resolved = crate::process::capture_spec(
                    &directory,
                    &[
                        path.to_string_lossy().into_owned(),
                        "which".into(),
                        program.trim_end_matches(".exe").into(),
                    ],
                    &command.env,
                    30,
                )?;
                let resolved = PathBuf::from(resolved.trim());
                ensure!(
                    resolved.is_absolute(),
                    "rustup returned a relative executable path"
                );
                resolved.canonicalize()?
            } else {
                path
            };
            identities.insert(
                format!("executable:{key}"),
                source::file_digest(&executable)?,
            );
        }
    }
    identities.insert(
        "engine_sha256".into(),
        source::file_digest(&std::env::current_exe()?)?,
    );
    Ok(identities)
}
pub(crate) fn backend(tool: Option<&native::NativeTool>) -> Result<BTreeMap<String, String>> {
    Ok(match tool {
        Some(t) => BTreeMap::from([
            ("backend".into(), "nfpm".into()),
            ("version".into(), t.version.clone()),
            ("sha256".into(), t.sha256.clone()),
        ]),
        None => BTreeMap::from([
            ("backend".into(), "builtin-archive".into()),
            (
                "engine_sha256".into(),
                source::file_digest(&std::env::current_exe()?)?,
            ),
        ]),
    })
}
fn has_hooks(plan: &Plan, build: usize) -> bool {
    let product = &plan.config.products[plan.builds[build].product];
    !product.prepare.is_empty() || !product.checks.is_empty()
}
fn previously_started(view: &v2::model::Plan, receipt: &RunReceipt, build: usize) -> bool {
    let ids = view
        .tasks
        .iter()
        .filter(|task| v2::run::task_unit(task) == Some(build))
        .map(|t| &t.id)
        .collect::<BTreeSet<_>>();
    receipt
        .invocations
        .iter()
        .flat_map(|i| &i.tasks)
        .any(|task| {
            ids.contains(&task.id)
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
#[allow(clippy::too_many_arguments)]
pub fn execute(
    root: &Path,
    plan: &Plan,
    assignment: &Assignment,
    output: &Path,
    resume: bool,
    allow_retry: &[usize],
    signer: Option<&SigningKey>,
    nfpm_path: Option<&Path>,
) -> Result<RunReceipt> {
    execute_pinned(
        root,
        plan,
        assignment,
        output,
        resume,
        allow_retry,
        signer,
        nfpm_path,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execute_pinned(
    root: &Path,
    plan: &Plan,
    assignment: &Assignment,
    output: &Path,
    resume: bool,
    allow_retry: &[usize],
    signer: Option<&SigningKey>,
    nfpm_path: Option<&Path>,
    expected_tool: Option<&native::NativeTool>,
) -> Result<RunReceipt> {
    let root = source::root(root)?;
    plan::validate_saved(&root, plan)?;
    ensure!(
        plan.engine_source_id == crate::cohort::model::ENGINE_SOURCE_ID,
        "execution requires the planned engine source identity"
    );
    validate_assignment(plan, assignment)?;
    match (&assignment.trusted_key, signer) {
        (Some(expected), Some(key)) => ensure!(
            *expected == crypto::public_key(key),
            "signer differs from assignment"
        ),
        (None, None) => (),
        _ => bail!(
            "trusted assignment requires matching signing key; unsigned candidate cannot sign"
        ),
    }
    ensure!(
        allow_retry.iter().all(|i| assignment.units.contains(i)),
        "retry override outside assignment"
    );
    let output = crate::cohort::run::attempt_directory(&root, output, resume)?;
    let _lock = crate::cohort::run::lock_attempt(&output)?;
    let mut receipt = if resume {
        ensure!(
            io::read_json::<Plan>(&output.join("plan.json"))? == *plan
                && io::read_json::<Assignment>(&output.join("assignment.json"))? == *assignment,
            "immutable resume plan or assignment differs"
        );
        status(&output)?
    } else {
        io::write_json_atomic(&output.join("plan.json"), plan)?;
        io::write_json_atomic(&output.join("assignment.json"), assignment)?;
        for dir in ["payloads", "packages", "invocations"] {
            fs::create_dir(output.join(dir))?;
        }
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
            invocations: vec![],
            payloads: BTreeMap::new(),
            packages: BTreeMap::new(),
            error: None,
        }
    };
    ensure!(
        receipt.plan_id == plan.id
            && receipt.assignment_id == assignment.id
            && receipt.engine_source_id == plan.engine_source_id,
        "receipt binding differs"
    );
    let (mut payloads, packages) = scan(plan, assignment, &output)?;
    ensure!(
        receipt
            .payloads
            .iter()
            .all(|(i, id)| payloads.get(i).is_some_and(|r| &r.id == id))
            && receipt
                .packages
                .iter()
                .all(|(i, id)| packages.get(i).is_some_and(|r| &r.id == id)),
        "previous checkpoint missing or changed"
    );
    receipt.payloads = payloads.iter().map(|(i, r)| (*i, r.id.clone())).collect();
    receipt.packages = packages.iter().map(|(i, r)| (*i, r.id.clone())).collect();
    crate::cohort::run::interrupt_invocations(
        &mut receipt.invocations,
        receipt.updated_at_ms,
        "previous invocation interrupted",
        "previous invocation interrupted",
    );
    let view = runtime_view(plan)?;
    let unsafe_builds = assignment
        .units
        .iter()
        .filter(|i| {
            !payloads.contains_key(i)
                && has_hooks(plan, **i)
                && previously_started(&view, &receipt, **i)
                && !assignment.retry_safe_units.contains(i)
                && !allow_retry.contains(i)
        })
        .copied()
        .collect::<Vec<_>>();
    if !unsafe_builds.is_empty() {
        receipt.status = "needs-decision".into();
        receipt.error = Some(format!(
            "incomplete builds with hooks need explicit --allow-retry: {unsafe_builds:?}"
        ));
        receipt.finished_at_ms = Some(io::now_ms().max(receipt.updated_at_ms));
        save(&output, &mut receipt)?;
        bail!(receipt.error.unwrap_or_default());
    }
    let needed = assignment
        .units
        .iter()
        .flat_map(|build| tasks_for(&view, *build))
        .filter(|t| matches!(t.action, Action::Probe { .. }))
        .map(|t| t.id)
        .collect::<BTreeSet<_>>();
    let tasks = view
        .tasks
        .iter()
        .filter(|t| {
            needed.contains(&t.id)
                || v2::run::task_unit(t)
                    .is_some_and(|b| assignment.units.contains(&b) && !payloads.contains_key(&b))
        })
        .cloned()
        .collect::<Vec<_>>();
    let invocation_id = io::random_id()?;
    let invocation = output.join("invocations").join(&invocation_id);
    fs::create_dir(&invocation)?;
    let mut execution = execution(plan, &tasks);
    receipt.status = "running".into();
    receipt.error = None;
    receipt.finished_at_ms = None;
    receipt.invocations.push(Invocation {
        id: invocation_id.clone(),
        status: "running".into(),
        started_at_ms: crate::cohort::run::journal_time(
            receipt.started_at_ms,
            receipt.updated_at_ms,
            None,
            &receipt.invocations,
        ),
        finished_at_ms: None,
        tasks: execution.tasks.clone(),
        toolchain: BTreeMap::new(),
        error: None,
    });
    save(&output, &mut receipt)?;
    let result = (|| -> Result<()> {
        let checkout = crate::cohort::run::clone_source_at(
            &root,
            &plan.source.commit,
            plan.config.timeout_seconds,
            &invocation,
        )?;
        plan::validate_saved(&checkout, plan)?;
        execution
            .toolchain
            .extend(compiler_files(&checkout, &tasks)?);
        for dir in ["work", "staging"] {
            fs::create_dir(invocation.join(dir))?;
        }
        for build in &assignment.units {
            if !payloads.contains_key(build) {
                for prefix in ["generated", "build"] {
                    fs::create_dir(invocation.join("work").join(format!("{prefix}-{build}")))?;
                }
            }
        }
        let mut staged = BTreeMap::new();
        for (i, t) in tasks
            .iter()
            .enumerate()
            .filter(|(_, t)| matches!(t.action, Action::Probe { .. }))
        {
            task(
                &checkout,
                &view,
                &output,
                &invocation,
                t,
                i,
                assignment.skip_runtime,
                &mut execution,
                &mut receipt,
                &mut staged,
            )?;
        }
        validate_probe_outputs(&execution.toolchain)?;
        for record in payloads.values() {
            ensure!(
                record.toolchain == build_tools(&view, record.build, &execution.toolchain)?,
                "compiler or engine tool identity changed; completed payload cannot be reused"
            );
        }
        let terminal = assignment
            .units
            .iter()
            .filter(|b| !payloads.contains_key(b))
            .map(|b| {
                Ok((
                    *b,
                    tasks
                        .iter()
                        .rev()
                        .find(|t| v2::run::task_unit(t) == Some(*b))
                        .context("build task chain absent")?
                        .id
                        .clone(),
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        for (i, t) in tasks
            .iter()
            .enumerate()
            .filter(|(_, t)| !matches!(t.action, Action::Probe { .. }))
        {
            task(
                &checkout,
                &view,
                &output,
                &invocation,
                t,
                i,
                assignment.skip_runtime,
                &mut execution,
                &mut receipt,
                &mut staged,
            )?;
            if let Some(build) = v2::run::task_unit(t)
                && terminal.get(&build) == Some(&t.id)
            {
                ensure!(
                    compiler_files(&checkout, &tasks)?
                        .iter()
                        .all(|(key, value)| execution.toolchain.get(key) == Some(value)),
                    "compiler executable changed during build"
                );
                let record = commit_payload(
                    plan,
                    assignment,
                    &output,
                    &invocation,
                    &invocation_id,
                    build,
                    &execution,
                    staged
                        .remove(&build)
                        .context("frozen payload manifest missing")?,
                    signer,
                )?;
                receipt.payloads.insert(build, record.id.clone());
                payloads.insert(build, record);
                save(&output, &mut receipt)?;
            }
        }
        let native_needed = selected_packages(plan, assignment)
            .iter()
            .any(|i| plan.packages[*i].format.is_native());
        let resolved_tool = if native_needed {
            (|| -> Result<Option<native::NativeTool>> {
                let requested = if let Some(expected) = expected_tool {
                    ensure!(
                        source::file_digest(&expected.path)? == expected.sha256,
                        "native backend differs from preflight-pinned tool identity"
                    );
                    Some(expected.path.as_path())
                } else {
                    nfpm_path
                };
                native::resolve_nfpm(requested).map(Some)
            })()
        } else {
            Ok(None)
        };
        if let Some(expected) = expected_tool {
            let actual = resolved_tool
                .as_ref()
                .map_err(|error| anyhow::anyhow!("{error:#}"))?
                .as_ref()
                .context("preflight-pinned backend is absent")?;
            ensure!(
                actual.version == expected.version && actual.sha256 == expected.sha256,
                "native backend differs from preflight-pinned tool identity"
            );
        }
        if let Ok(Some(tool)) = &resolved_tool {
            let identity = backend(Some(tool))?;
            let pin = safe_join(&output, "packager.json")?;
            match fs::symlink_metadata(&pin) {
                Ok(_) => ensure!(
                    io::read_json::<BTreeMap<String, String>>(&pin)? == identity,
                    "packaging tool identity changed since first package attempt"
                ),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    io::write_json_atomic(&pin, &identity)?
                }
                Err(error) => return Err(error.into()),
            }
        }
        for (index, record) in &packages {
            let tool = if plan.packages[*index].format.is_native() {
                resolved_tool
                    .as_ref()
                    .map_err(|error| anyhow::anyhow!("{error:#}"))?
                    .as_ref()
            } else {
                None
            };
            ensure!(
                record.toolchain == backend(tool)?,
                "packaging tool identity changed; package checkpoint cannot be reused"
            );
        }
        // Each package has its own durable boundary. Failures do not discard a
        // validated payload or prevent independent formats from completing.
        let mut failures = Vec::new();
        for index in selected_packages(plan, assignment) {
            if packages.contains_key(&index) {
                continue;
            }
            let tool = if plan.packages[index].format.is_native() {
                match &resolved_tool {
                    Ok(tool) => tool.as_ref(),
                    Err(error) => {
                        failures.push(format!("{}: {error:#}", plan.packages[index].id));
                        continue;
                    }
                }
            } else {
                None
            };
            match commit_package(
                plan,
                assignment,
                &output,
                index,
                &payloads[&plan.packages[index].build],
                tool,
                signer,
            ) {
                Ok(record) => {
                    receipt.packages.insert(index, record.id);
                    save(&output, &mut receipt)?;
                }
                Err(error) => failures.push(format!("{}: {error:#}", plan.packages[index].id)),
            }
        }
        ensure!(
            failures.is_empty(),
            "package failures: {}",
            failures.join("; ")
        );
        Ok(())
    })();
    sync(&mut receipt, &execution);
    let finished = io::now_ms().max(receipt.updated_at_ms);
    let last = receipt
        .invocations
        .last_mut()
        .context("missing invocation")?;
    last.finished_at_ms = Some(finished);
    match &result {
        Ok(()) => {
            receipt.status = completion(assignment).into();
            last.status = receipt.status.clone();
        }
        Err(error) => {
            receipt.status = "failed".into();
            receipt.error = Some(format!("{error:#}"));
            last.status = "failed".into();
            last.error = receipt.error.clone();
            for t in &mut last.tasks {
                if matches!(t.state, TaskState::Pending | TaskState::Running) {
                    t.state = TaskState::Blocked;
                    t.error = Some("invocation failed".into());
                }
            }
        }
    }
    receipt.finished_at_ms = Some(finished);
    save(&output, &mut receipt)?;
    result?;
    Ok(receipt)
}
/// Freeze the exact build output before runtime hooks, without a temporary archive.
/// The historical task action remains unchanged in saved plans and journals.
pub(crate) fn stage_payload(
    root: &Path,
    view: &v2::model::Plan,
    invocation: &Path,
    build: usize,
) -> Result<PayloadManifest> {
    let contents = v2::run::collect(root, view, invocation, build)?;
    let files = manifest(&contents);
    let directory = safe_join(invocation, &format!("work/run-{build}"))?;
    archive::extract(&contents, &directory)?;
    validate_payload_files(&directory, &files)?;
    Ok(files)
}
pub(crate) fn manifest(contents: &BTreeMap<String, archive::Content>) -> PayloadManifest {
    contents
        .iter()
        .map(|(path, c)| {
            (
                path.clone(),
                PayloadEntry {
                    size: c.bytes.len() as u64,
                    sha256: source::digest(&c.bytes),
                    mode: if c.executable { 0o755 } else { 0o644 },
                },
            )
        })
        .collect()
}
pub(crate) fn payload_names(plan: &Plan, build: usize) -> Result<BTreeSet<String>> {
    let planned = plan.builds.get(build).context("unknown payload build")?;
    let product = &plan.config.products[planned.product];
    let target = &plan.config.targets[planned.target];
    let names = product
        .binaries
        .iter()
        .map(|name| target.binary_name(name))
        .chain(product.assets.iter().map(|a| a.path.clone()))
        .collect::<BTreeSet<_>>();
    ensure!(
        names.len() == product.binaries.len() + product.assets.len(),
        "payload contract collides"
    );
    Ok(names)
}
fn validate_payload_contract(plan: &Plan, record: &PayloadRecord) -> Result<()> {
    ensure!(
        record.files.keys().cloned().collect::<BTreeSet<_>>() == payload_names(plan, record.build)?,
        "payload has missing or extra contract members"
    );
    let build = &plan.builds[record.build];
    let product = &plan.config.products[build.product];
    let target = &plan.config.targets[build.target];
    for name in &product.binaries {
        ensure!(
            record.files[&target.binary_name(name)].mode == 0o755,
            "payload binary mode differs"
        );
    }
    for asset in &product.assets {
        let entry = &record.files[&asset.path];
        ensure!(entry.mode == 0o644, "payload asset mode differs");
        if !asset.source.starts_with("{generated}/") {
            ensure!(
                plan.source.files.get(&asset.source) == Some(&entry.sha256),
                "payload asset differs from frozen source"
            );
        }
    }
    Ok(())
}
pub(crate) fn payload_directory(output: &Path, build: usize) -> Result<PathBuf> {
    safe_join(output, &format!("payloads/{build}"))
}
pub(crate) fn package_directory(output: &Path, package: usize) -> Result<PathBuf> {
    safe_join(output, &format!("packages/{package}"))
}
pub(crate) fn pending(output: &Path, kind: &str) -> Result<PathBuf> {
    let path = safe_join(output, &format!("{kind}/.pending-{}", io::random_id()?))?;
    fs::create_dir(&path)?;
    Ok(path)
}
pub(crate) fn install_pending(temporary: &Path, dest: &Path) -> Result<()> {
    ensure!(
        matches!(fs::symlink_metadata(dest),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
        "checkpoint already exists"
    );
    fn sync_tree(directory: &Path) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                !metadata.file_type().is_symlink(),
                "checkpoint staging symlink"
            );
            if metadata.is_dir() {
                sync_tree(&path)?;
            } else {
                ensure!(metadata.is_file(), "checkpoint contains a nonregular file");
                fs::OpenOptions::new().write(true).open(&path)?.sync_all()?;
            }
        }
        io::sync_directory(directory)
    }
    sync_tree(temporary)?;
    fs::rename(temporary, dest)?;
    io::sync_directory(dest.parent().context("checkpoint parent missing")?)
}
#[allow(clippy::too_many_arguments)]
fn commit_payload(
    plan: &Plan,
    assignment: &Assignment,
    output: &Path,
    invocation: &Path,
    invocation_id: &str,
    build: usize,
    execution: &v2::model::Receipt,
    files: PayloadManifest,
    signer: Option<&SigningKey>,
) -> Result<PayloadRecord> {
    let view = runtime_view(plan)?;
    // Hooks run the staged bytes. Compare against the pre-hook manifest before
    // signing or persisting the payload used by every package format.
    validate_payload_files(
        &invocation.join("work").join(format!("run-{build}")),
        &files,
    )?;
    let tasks = tasks_for(&view, build)
        .iter()
        .map(|task| {
            execution
                .tasks
                .iter()
                .find(|r| r.id == task.id)
                .cloned()
                .context("completed build task missing")
        })
        .collect::<Result<Vec<_>>>()?;
    let mut record = PayloadRecord {
        schema: SCHEMA,
        id: String::new(),
        plan_id: plan.id.clone(),
        assignment_id: assignment.id.clone(),
        engine_source_id: plan.engine_source_id.clone(),
        build,
        invocation: invocation_id.into(),
        status: completion(assignment).into(),
        toolchain: build_tools(&view, build, &execution.toolchain)?,
        tasks,
        files,
        proof: None,
    };
    proof::seal_payload(&mut record, signer)?;
    let temporary = pending(output, "payloads")?;
    fs::create_dir(temporary.join("files"))?;
    for (name, entry) in &record.files {
        let dest = safe_join(&temporary.join("files"), name)?;
        io::copy_file_checked(
            &safe_join(&invocation.join("work").join(format!("run-{build}")), name)?,
            &dest,
            &FileEntry {
                size: entry.size,
                sha256: entry.sha256.clone(),
            },
        )?;
        set_mode(&dest, entry.mode)?;
    }
    io::write_json_atomic(&temporary.join("payload.json"), &record)?;
    validate_payload(plan, assignment, &temporary, build, &record)?;
    install_pending(&temporary, &payload_directory(output, build)?)?;
    Ok(record)
}
pub(crate) fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}
pub(crate) fn validate_payload_files(directory: &Path, files: &PayloadManifest) -> Result<()> {
    let expected = files.keys().cloned().collect();
    let inventory = crate::cohort::bundle::exact_inventory(directory, &expected)?;
    for (name, entry) in files {
        ensure!(
            is_digest(&entry.sha256) && matches!(entry.mode, 0o644 | 0o755),
            "invalid payload entry"
        );
        ensure!(
            inventory.get(name)
                == Some(&FileEntry {
                    size: entry.size,
                    sha256: entry.sha256.clone()
                }),
            "payload bytes or size changed: {name}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                fs::metadata(safe_join(directory, name)?)?
                    .permissions()
                    .mode()
                    & 0o7777
                    == entry.mode,
                "payload mode changed: {name}"
            );
        }
    }
    Ok(())
}
fn validate_payload(
    plan: &Plan,
    assignment: &Assignment,
    directory: &Path,
    build: usize,
    record: &PayloadRecord,
) -> Result<()> {
    ensure!(
        assignment.units.contains(&build)
            && record.schema == SCHEMA
            && record.build == build
            && record.plan_id == plan.id
            && record.assignment_id == assignment.id
            && record.engine_source_id == plan.engine_source_id
            && record.status == completion(assignment),
        "payload record binding differs"
    );
    ensure!(
        record.invocation.len() == 32
            && record
                .invocation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid payload invocation"
    );
    proof::verify_payload(record, assignment.trusted_key.as_deref())?;
    validate_payload_contract(plan, record)?;
    let view = runtime_view(plan)?;
    let tasks = tasks_for(&view, build);
    ensure!(
        record.tasks.len() == tasks.len(),
        "payload task closure differs"
    );
    for (observed, task) in record.tasks.iter().zip(&tasks) {
        ensure!(observed.id == task.id, "payload task missing or reordered");
        if assignment.skip_runtime && task.runtime {
            ensure!(
                observed.state == TaskState::Skipped
                    && observed.log.is_none()
                    && observed.error.as_deref() == Some(SKIP_REASON),
                "runtime skip evidence differs"
            );
        } else {
            ensure!(
                observed.state == TaskState::Succeeded
                    && observed.error.is_none()
                    && observed.log == v2::run::command(task).map(|_| format!("logs/{}", task.id)),
                "payload task incomplete or log differs"
            );
        }
    }
    let mut expected_keys = BTreeSet::from(["engine_sha256".to_string()]);
    for task in &tasks {
        if let Action::Probe { key, .. } = &task.action {
            expected_keys.insert(key.clone());
            expected_keys.insert(format!("executable:{key}"));
            expected_keys.insert(format!("launcher:{key}"));
        }
    }
    ensure!(
        record.toolchain.keys().cloned().collect::<BTreeSet<_>>() == expected_keys
            && record.toolchain.values().all(|v| !v.trim().is_empty()),
        "payload compiler identity set differs"
    );
    validate_probe_outputs(&record.toolchain)?;
    for (key, value) in &record.toolchain {
        if key == "engine_sha256" || key.starts_with("executable:") || key.starts_with("launcher:")
        {
            ensure!(is_digest(value), "invalid executable digest");
        }
    }
    if !assignment.skip_runtime {
        let spec = &plan.builds[build];
        ensure!(
            v2::builder::can_run(
                &plan.config.targets[spec.target],
                &spec.recipe,
                &record.toolchain
            ),
            "saved tools cannot support claimed runtime verification"
        );
    }
    let mut expected = BTreeSet::from(["payload.json".to_string()]);
    expected.extend(record.files.keys().map(|name| format!("files/{name}")));
    crate::cohort::bundle::exact_inventory(directory, &expected)?;
    validate_payload_files(&directory.join("files"), &record.files)
}
#[allow(clippy::too_many_arguments)]
fn commit_package(
    plan: &Plan,
    assignment: &Assignment,
    output: &Path,
    index: usize,
    payload: &PayloadRecord,
    tool: Option<&native::NativeTool>,
    signer: Option<&SigningKey>,
) -> Result<PackageRecord> {
    let spec = &plan.packages[index];
    let temporary = pending(output, "packages")?;
    let artifact = safe_join(&temporary, &spec.filename)?;
    let payload_root = payload_directory(output, spec.build)?.join("files");
    validate_payload_files(&payload_root, &payload.files)?;
    let observed = if spec.format.is_native() {
        native::package(
            spec,
            &payload_root,
            &payload.files,
            tool.context("nFPM unavailable")?,
            &artifact,
        )?
    } else {
        native::package_archive(spec, &payload_root, &payload.files, &artifact)?
    };
    let sha256 = source::file_digest(&artifact)?;
    let size = fs::symlink_metadata(&artifact)?.len();
    let mut record = PackageRecord {
        schema: SCHEMA,
        id: String::new(),
        plan_id: plan.id.clone(),
        assignment_id: assignment.id.clone(),
        engine_source_id: plan.engine_source_id.clone(),
        package: index,
        payload_id: payload.id.clone(),
        status: completion(assignment).into(),
        toolchain: backend(if spec.format.is_native() { tool } else { None })?,
        filename: spec.filename.clone(),
        sha256: sha256.clone(),
        size,
        files: observed.files,
        metadata: observed.metadata,
        native_fields: observed.native_fields,
        candidate_match: assignment
            .candidate
            .as_ref()
            .and_then(|c| c.digests.get(&index))
            .map(|expected| expected == &sha256),
        proof: None,
    };
    proof::seal_package(&mut record, signer)?;
    io::write_json_atomic(&temporary.join("package.json"), &record)?;
    validate_package(plan, assignment, &temporary, index, payload, &record)?;
    install_pending(&temporary, &package_directory(output, index)?)?;
    Ok(record)
}
fn validate_package(
    plan: &Plan,
    assignment: &Assignment,
    directory: &Path,
    index: usize,
    payload: &PayloadRecord,
    record: &PackageRecord,
) -> Result<()> {
    let spec = plan
        .packages
        .get(index)
        .context("unknown checkpoint package")?;
    ensure!(
        assignment.units.contains(&spec.build)
            && record.schema == SCHEMA
            && record.package == index
            && record.plan_id == plan.id
            && record.assignment_id == assignment.id
            && record.engine_source_id == plan.engine_source_id
            && record.payload_id == payload.id
            && record.status == completion(assignment),
        "package checkpoint binding differs"
    );
    proof::verify_package(record, assignment.trusted_key.as_deref())?;
    ensure!(
        record.filename == spec.filename && is_digest(&record.sha256),
        "package filename or digest invalid"
    );
    ensure!(
        record.candidate_match
            == assignment
                .candidate
                .as_ref()
                .and_then(|c| c.digests.get(&index))
                .map(|expected| expected == &record.sha256),
        "candidate comparison differs from rebuilt bytes"
    );
    if spec.format.is_native() {
        ensure!(
            record
                .toolchain
                .keys()
                .map(String::as_str)
                .eq(["backend", "sha256", "version"])
                && record.toolchain["backend"] == "nfpm"
                && record.toolchain["version"] == NFPM_VERSION
                && is_digest(&record.toolchain["sha256"]),
            "native backend identity differs"
        );
    } else {
        ensure!(
            record
                .toolchain
                .keys()
                .map(String::as_str)
                .eq(["backend", "engine_sha256"])
                && record.toolchain["backend"] == "builtin-archive"
                && is_digest(&record.toolchain["engine_sha256"]),
            "archive backend identity differs"
        );
    }
    let expected = BTreeSet::from(["package.json".to_string(), spec.filename.clone()]);
    let actual = crate::cohort::bundle::exact_inventory(directory, &expected)?;
    ensure!(
        actual[&spec.filename]
            == FileEntry {
                size: record.size,
                sha256: record.sha256.clone()
            },
        "package bytes or size changed"
    );
    let observed = inspect::inspect(spec, &safe_join(directory, &spec.filename)?, &payload.files)?;
    ensure!(
        record.files == observed.files
            && record.metadata == observed.metadata
            && record.native_fields == observed.native_fields,
        "package inspection differs from saved result"
    );
    Ok(())
}
pub fn read_payload(
    plan: &Plan,
    assignment: &Assignment,
    output: &Path,
    build: usize,
) -> Result<PayloadRecord> {
    let directory = payload_directory(output, build)?;
    let record = io::read_json(&safe_join(&directory, "payload.json")?)?;
    validate_payload(plan, assignment, &directory, build, &record)?;
    Ok(record)
}
pub fn read_package(
    plan: &Plan,
    assignment: &Assignment,
    output: &Path,
    index: usize,
) -> Result<PackageRecord> {
    let spec = plan.packages.get(index).context("unknown package")?;
    let payload = read_payload(plan, assignment, output, spec.build)?;
    read_package_with_payload(plan, assignment, output, index, &payload)
}
/// Reuse a payload validated within this operation; callers still verify every
/// package and revalidate copied snapshots at persistence boundaries.
pub(crate) fn read_package_with_payload(
    plan: &Plan,
    assignment: &Assignment,
    output: &Path,
    index: usize,
    payload: &PayloadRecord,
) -> Result<PackageRecord> {
    ensure!(
        plan.packages
            .get(index)
            .is_some_and(|spec| spec.build == payload.build),
        "package references a different payload build"
    );
    let directory = package_directory(output, index)?;
    let record = io::read_json(&safe_join(&directory, "package.json")?)?;
    validate_package(plan, assignment, &directory, index, payload, &record)?;
    Ok(record)
}
fn scan_kind(output: &Path, kind: &str, allowed: &[usize]) -> Result<Vec<usize>> {
    let base = safe_join(output, kind)?;
    let meta = fs::symlink_metadata(&base)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "checkpoint root is not a directory"
    );
    let mut found = Vec::new();
    for entry in fs::read_dir(base)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF8 checkpoint"))?;
        let meta = fs::symlink_metadata(entry.path())?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "checkpoint is not a directory"
        );
        if let Some(id) = name.strip_prefix(".pending-") {
            ensure!(
                id.len() == 32
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
                "invalid temporary checkpoint"
            );
            continue;
        }
        let index = name.parse::<usize>().context("unexpected checkpoint")?;
        ensure!(
            name == index.to_string() && allowed.contains(&index),
            "checkpoint outside assignment"
        );
        found.push(index);
    }
    Ok(found)
}
fn scan(
    plan: &Plan,
    assignment: &Assignment,
    output: &Path,
) -> Result<(
    BTreeMap<usize, PayloadRecord>,
    BTreeMap<usize, PackageRecord>,
)> {
    let payloads: BTreeMap<usize, PayloadRecord> =
        scan_kind(output, "payloads", &assignment.units)?
            .into_iter()
            .map(|i| Ok((i, read_payload(plan, assignment, output, i)?)))
            .collect::<Result<_>>()?;
    let packages = scan_kind(output, "packages", &selected_packages(plan, assignment))?
        .into_iter()
        .map(|i| {
            let payload = payloads
                .get(&plan.packages[i].build)
                .context("package checkpoint has no payload")?;
            Ok((
                i,
                read_package_with_payload(plan, assignment, output, i, payload)?,
            ))
        })
        .collect::<Result<_>>()?;
    Ok((payloads, packages))
}
/// Read the persisted snapshot. A running receipt does not claim liveness.
pub fn status(output: &Path) -> Result<RunReceipt> {
    let meta = fs::symlink_metadata(output)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "attempt is not a directory"
    );
    let receipt: RunReceipt = io::read_json(&safe_join(output, "receipt.json")?)?;
    ensure!(
        receipt.schema == SCHEMA
            && is_digest(&receipt.plan_id)
            && is_digest(&receipt.assignment_id)
            && is_digest(&receipt.engine_source_id),
        "invalid receipt identity"
    );
    crate::cohort::run::validate_invocation_journal(
        &receipt.status,
        receipt.started_at_ms,
        receipt.updated_at_ms,
        receipt.finished_at_ms,
        &receipt.error,
        &receipt.invocations,
    )?;
    ensure!(
        receipt
            .payloads
            .values()
            .chain(receipt.packages.values())
            .all(|id| is_digest(id)),
        "invalid checkpoint references"
    );
    Ok(receipt)
}
pub fn verify_run(root: &Path, output: &Path) -> Result<RunReceipt> {
    let plan: Plan = io::read_json(&safe_join(output, "plan.json")?)?;
    plan::validate_saved(root, &plan)?;
    let assignment: Assignment = io::read_json(&safe_join(output, "assignment.json")?)?;
    validate_assignment(&plan, &assignment)?;
    let receipt = status(output)?;
    ensure!(
        receipt.plan_id == plan.id
            && receipt.assignment_id == assignment.id
            && receipt.engine_source_id == plan.engine_source_id,
        "receipt binding differs"
    );
    let (payloads, packages) = scan(&plan, &assignment, output)?;
    ensure!(
        receipt
            .payloads
            .iter()
            .all(|(i, id)| payloads.get(i).is_some_and(|r| &r.id == id))
            && receipt
                .packages
                .iter()
                .all(|(i, id)| packages.get(i).is_some_and(|r| &r.id == id)),
        "receipt references missing checkpoint"
    );
    if matches!(receipt.status.as_str(), "complete" | "build-only") {
        ensure!(
            payloads.len() == assignment.units.len()
                && packages.len() == selected_packages(&plan, &assignment).len()
                && receipt.payloads.len() == payloads.len()
                && receipt.packages.len() == packages.len()
                && receipt.status == completion(&assignment)
                && receipt.error.is_none(),
            "successful receipt has incomplete checkpoints"
        );
    }
    Ok(receipt)
}
