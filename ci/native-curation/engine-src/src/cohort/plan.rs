use super::{io, model::*};
use crate::{
    model::IMPLEMENTATION,
    source,
    v2::{
        self,
        model::{Action, Task},
    },
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub fn id(p: &Plan) -> Result<String> {
    let mut p = p.clone();
    p.id.clear();
    let mut b = b"cli-release-kit/cohort-plan/v1\0".to_vec();
    b.extend(serde_json::to_vec(&p)?);
    Ok(source::digest(&b))
}
fn upgrade(old: v2::model::Plan) -> Result<Plan> {
    let mut tasks = old.tasks;
    let probes: BTreeMap<String, String> = tasks
        .iter()
        .filter_map(|t| match &t.action {
            Action::Probe { key, .. } => Some((t.id.clone(), key.clone())),
            _ => None,
        })
        .collect();
    tasks.retain(|t| !matches!(t.action, Action::Seal));
    for task in &mut tasks {
        if let Some(unit) = v2::run::task_unit(task) {
            let product = &old.config.products[old.units[unit].product];
            let needed: BTreeSet<_> = v2::builder::probes(std::slice::from_ref(product))
                .into_iter()
                .map(|(k, _)| k)
                .collect();
            task.depends_on
                .retain(|id| probes.get(id).is_none_or(|key| needed.contains(key)));
        }
    }
    let mut outputs = BTreeSet::new();
    for unit in &old.units {
        ensure!(
            outputs.insert(unit.filename.to_ascii_lowercase()),
            "planned artifact names collide (case insensitive)"
        );
    }
    let mut p = Plan {
        schema: SCHEMA,
        id: String::new(),
        implementation: IMPLEMENTATION.into(),
        engine_source_id: ENGINE_SOURCE_ID.into(),
        source: old.source,
        config: old.config,
        resolved: old.resolved,
        units: old.units,
        tasks,
    };
    p.id = id(&p)?;
    Ok(p)
}
pub fn create(root: &Path) -> Result<Plan> {
    upgrade(v2::plan::create(root)?)
}
pub fn load(path: &Path) -> Result<Plan> {
    io::read_json(path)
}
pub fn validate(root: &Path, p: &Plan) -> Result<()> {
    ensure!(
        p.schema == SCHEMA && p.implementation == IMPLEMENTATION && is_digest(&p.engine_source_id),
        "unsupported plan protocol or engine source identity"
    );
    ensure!(p.id == id(p)?, "plan identity mismatch");
    ensure!(
        v2::contract::load(root)? == p.config,
        "consumer configuration changed"
    );
    ensure!(
        source::snapshot_plain(root)? == p.source,
        "source identity changed"
    );
    v2::contract::validate_source(root, &p.config, &p.source)?;
    ensure!(
        p.config.products.len() == p.resolved.len(),
        "resolved product set differs"
    );
    for (product, resolved) in p.config.products.iter().zip(&p.resolved) {
        v2::builder::validate_offline_source(root, product, resolved, &p.source.files, false)?;
    }
    let old = v2::plan::assemble(p.config.clone(), p.source.clone(), p.resolved.clone())?;
    let expected = upgrade(old)?;
    ensure!(
        expected.units == p.units && expected.tasks == p.tasks,
        "canonical task graph or recipes differ from source contract"
    );
    Ok(())
}
pub fn assignment_id(a: &Assignment) -> Result<String> {
    let mut a = a.clone();
    a.id.clear();
    let mut b = b"cli-release-kit/assignment/v1\0".to_vec();
    b.extend(serde_json::to_vec(&a)?);
    Ok(source::digest(&b))
}
pub fn assignment(
    p: &Plan,
    units: Vec<usize>,
    retry_safe_units: Vec<usize>,
    skip_runtime: bool,
    trusted_key: Option<String>,
    candidate: Option<CandidateRef>,
) -> Result<Assignment> {
    let mut units = units;
    units.sort();
    let mut retry_safe_units = retry_safe_units;
    retry_safe_units.sort();
    let mut a = Assignment {
        schema: SCHEMA,
        id: String::new(),
        plan_id: p.id.clone(),
        units,
        retry_safe_units,
        skip_runtime,
        trusted_key,
        candidate,
    };
    a.id = assignment_id(&a)?;
    validate_assignment(p, &a)?;
    Ok(a)
}
pub fn validate_assignment(p: &Plan, a: &Assignment) -> Result<()> {
    ensure!(
        a.schema == SCHEMA && a.plan_id == p.id && a.id == assignment_id(a)?,
        "assignment identity or plan mismatch"
    );
    ensure!(
        !a.units.is_empty()
            && a.units.iter().all(|i| *i < p.units.len())
            && a.units.windows(2).all(|w| w[0] < w[1]),
        "assignment unit set must be nonempty, unique and canonical"
    );
    ensure!(
        a.retry_safe_units.iter().all(|i| a.units.contains(i))
            && a.retry_safe_units.windows(2).all(|w| w[0] < w[1]),
        "retry-safe declarations must select unique assigned units"
    );
    if let Some(key) = &a.trusted_key {
        ensure!(is_digest(key), "invalid trusted public key");
    }
    if let Some(c) = &a.candidate {
        ensure!(
            is_digest(&c.bundle_id)
                && c.digests.keys().copied().eq(a.units.iter().copied())
                && c.digests.values().all(|h| is_digest(h)),
            "candidate reference must bind each assigned artifact digest"
        );
    }
    Ok(())
}
pub fn is_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
pub fn select(p: &Plan, names: &[String]) -> Result<Vec<usize>> {
    if names.is_empty() {
        return Ok((0..p.units.len()).collect());
    }
    let mut units = Vec::new();
    for name in names {
        let idx = p
            .units
            .iter()
            .position(|u| u.id == *name)
            .with_context(|| format!("unknown unit: {name}"))?;
        ensure!(!units.contains(&idx), "duplicate unit selection");
        units.push(idx);
    }
    units.sort();
    Ok(units)
}
pub fn task_ids_for_unit(p: &Plan, unit: usize) -> Result<Vec<String>> {
    ensure!(unit < p.units.len(), "unknown unit");
    let mut ids: BTreeSet<String> = p
        .tasks
        .iter()
        .filter(|t| v2::run::task_unit(t) == Some(unit))
        .map(|t| t.id.clone())
        .collect();
    loop {
        let before = ids.len();
        for task in &p.tasks {
            if ids.contains(&task.id) {
                ids.extend(task.depends_on.iter().cloned());
            }
        }
        if ids.len() == before {
            break;
        }
    }
    ensure!(
        !ids.is_empty() && ids.iter().all(|id| p.tasks.iter().any(|t| &t.id == id)),
        "unit task closure is incomplete"
    );
    Ok(p.tasks
        .iter()
        .filter(|t| ids.contains(&t.id))
        .map(|t| t.id.clone())
        .collect())
}
pub fn tasks_for_units(p: &Plan, units: &[usize]) -> Result<Vec<Task>> {
    let mut ids = BTreeSet::new();
    for unit in units {
        ids.extend(task_ids_for_unit(p, *unit)?);
    }
    Ok(p.tasks
        .iter()
        .filter(|t| ids.contains(&t.id))
        .cloned()
        .collect())
}
/// Command helpers share this in-memory view; it is never serialized as legacy evidence.
pub fn as_v2(p: &Plan) -> v2::model::Plan {
    v2::model::Plan {
        schema: 2,
        id: p.id.clone(),
        implementation: p.implementation.clone(),
        source: p.source.clone(),
        config: p.config.clone(),
        resolved: p.resolved.clone(),
        units: p.units.clone(),
        tasks: p.tasks.clone(),
    }
}
