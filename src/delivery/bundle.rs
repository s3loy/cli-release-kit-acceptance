//! Data-only protocol 4 transfer and independently verified collections.
use super::{
    model::{Plan, SCHEMA},
    plan, proof,
    run::{self, Assignment, CandidateRef, PackageRecord, PayloadRecord},
};
use crate::{
    cohort::{
        crypto, io,
        model::{FileEntry, Policy},
    },
    config::safe_join,
    source,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub schema: u32,
    pub id: String,
    pub plan_id: String,
    pub engine_source_id: String,
    pub assignment: Assignment,
    pub builds: Vec<usize>,
    pub packages: Vec<usize>,
    pub files: BTreeMap<String, FileEntry>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub package: usize,
    pub build: usize,
    pub bundle_id: String,
    pub record_id: String,
    pub filename: String,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Collection {
    pub schema: u32,
    pub id: String,
    pub plan_id: String,
    pub engine_source_id: String,
    pub policy_id: String,
    pub status: String,
    pub publication_ready: bool,
    pub selections: Vec<Selection>,
    pub bundles: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    schema: u32,
    status: String,
    plan_id: String,
    bundle_id: String,
}
struct Snapshot {
    directory: PathBuf,
    bundle: Bundle,
    payloads: BTreeMap<usize, PayloadRecord>,
    packages: BTreeMap<usize, PackageRecord>,
    files: BTreeMap<String, FileEntry>,
}
pub fn bundle_id(value: &Bundle) -> Result<String> {
    let mut copy = value.clone();
    copy.id.clear();
    proof::content_id(b"cli-release-kit/delivery-bundle/v1\0", &copy)
}
pub fn collection_id(value: &Collection) -> Result<String> {
    let mut copy = value.clone();
    copy.id.clear();
    proof::content_id(b"cli-release-kit/delivery-collection/v1\0", &copy)
}
fn expected_files(plan: &Plan, assignment: &Assignment) -> Result<BTreeSet<String>> {
    let mut expected = BTreeSet::from(["plan.json".to_string()]);
    for &build in &assignment.units {
        expected.insert(format!("payloads/{build}/payload.json"));
        for name in run::payload_names(plan, build)? {
            expected.insert(format!("payloads/{build}/files/{name}"));
        }
    }
    for package in run::selected_packages(plan, assignment) {
        expected.insert(format!("packages/{package}/package.json"));
        ensure!(
            expected.insert(format!(
                "packages/{package}/{}",
                plan.packages[package].filename
            )),
            "package output path collision"
        );
    }
    ensure!(expected.len() <= 10000, "bundle has too many members");
    Ok(expected)
}
fn load(plan: &Plan, directory: &Path) -> Result<Snapshot> {
    let bundle: Bundle = io::read_json(&safe_join(directory, "bundle.json")?)?;
    ensure!(
        bundle.schema == SCHEMA
            && bundle.id == bundle_id(&bundle)?
            && bundle.plan_id == plan.id
            && bundle.engine_source_id == plan.engine_source_id,
        "bundle identity or plan binding differs"
    );
    run::validate_assignment(plan, &bundle.assignment)?;
    ensure!(
        bundle.builds == bundle.assignment.units
            && bundle.packages == run::selected_packages(plan, &bundle.assignment),
        "bundle does not cover its complete build and package assignment"
    );
    let expected = expected_files(plan, &bundle.assignment)?;
    ensure!(
        bundle.files.keys().cloned().collect::<BTreeSet<_>>() == expected,
        "bundle manifest differs from planned files"
    );
    let mut all = expected;
    all.insert("bundle.json".into());
    let files = crate::cohort::bundle::exact_inventory(directory, &all)?;
    ensure!(
        bundle
            .files
            .iter()
            .all(|(name, file)| files.get(name) == Some(file)),
        "bundle file digest or size differs"
    );
    ensure!(
        io::read_json::<Plan>(&safe_join(directory, "plan.json")?)? == *plan,
        "bundle immutable plan differs"
    );
    let payloads = bundle
        .builds
        .iter()
        .map(|i| {
            Ok((
                *i,
                run::read_payload(plan, &bundle.assignment, directory, *i)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let packages = bundle
        .packages
        .iter()
        .map(|i| {
            Ok((
                *i,
                run::read_package_with_payload(
                    plan,
                    &bundle.assignment,
                    directory,
                    *i,
                    &payloads[&plan.packages[*i].build],
                )?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    Ok(Snapshot {
        directory: directory.to_path_buf(),
        bundle,
        payloads,
        packages,
        files,
    })
}
fn load_input(plan: &Plan, input: &Path) -> Result<Snapshot> {
    let marker = safe_join(input, "candidate.json")?;
    match fs::symlink_metadata(marker) {
        Ok(_) => {
            let marker: Candidate = io::read_json(&input.join("candidate.json"))?;
            let snapshot = load(plan, &safe_join(input, "bundle")?)?;
            ensure!(
                marker.schema == SCHEMA
                    && marker.status == "candidate"
                    && marker.plan_id == plan.id
                    && marker.bundle_id == snapshot.bundle.id,
                "candidate marker binding differs"
            );
            let expected = std::iter::once("candidate.json".to_string())
                .chain(snapshot.files.keys().map(|name| format!("bundle/{name}")))
                .collect();
            crate::cohort::bundle::exact_inventory(input, &expected)?;
            Ok(snapshot)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => load(plan, input),
        Err(error) => Err(error.into()),
    }
}
fn copy_files(
    input: &Path,
    output: &Path,
    files: &BTreeMap<String, FileEntry>,
    payloads: &BTreeMap<usize, PayloadRecord>,
) -> Result<()> {
    for (name, file) in files {
        io::copy_file_checked(&safe_join(input, name)?, &safe_join(output, name)?, file)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for (build, record) in payloads {
            for (name, entry) in &record.files {
                fs::set_permissions(
                    safe_join(output, &format!("payloads/{build}/files/{name}"))?,
                    fs::Permissions::from_mode(entry.mode),
                )?;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = payloads;
    Ok(())
}
fn copy_snapshot(snapshot: &Snapshot, output: &Path) -> Result<()> {
    copy_files(
        &snapshot.directory,
        output,
        &snapshot.files,
        &snapshot.payloads,
    )
}
pub fn validate(root: &Path, plan: &Plan, input: &Path) -> Result<Bundle> {
    plan::validate_saved(root, plan)?;
    Ok(load_input(plan, input)?.bundle)
}
pub fn candidate_ref(root: &Path, plan: &Plan, input: &Path) -> Result<CandidateRef> {
    plan::validate_saved(root, plan)?;
    let snapshot = load_input(plan, input)?;
    Ok(CandidateRef {
        bundle_id: snapshot.bundle.id,
        digests: snapshot
            .packages
            .into_iter()
            .map(|(i, r)| (i, r.sha256))
            .collect(),
    })
}
pub fn candidate(root: &Path, input: &Path) -> Result<(Plan, CandidateRef)> {
    let path = if input.join("candidate.json").exists() {
        input.join("bundle/plan.json")
    } else {
        input.join("plan.json")
    };
    let plan: Plan = io::read_json(&path)?;
    let reference = candidate_ref(root, &plan, input)?;
    Ok((plan, reference))
}
pub fn export_run(root: &Path, attempt: &Path, output: &Path) -> Result<Bundle> {
    let receipt = run::verify_run(root, attempt)?;
    ensure!(
        matches!(receipt.status.as_str(), "complete" | "build-only"),
        "only a completed assignment can be exported"
    );
    let plan: Plan = io::read_json(&safe_join(attempt, "plan.json")?)?;
    let assignment: Assignment = io::read_json(&safe_join(attempt, "assignment.json")?)?;
    let mut files = BTreeMap::new();
    for name in expected_files(&plan, &assignment)? {
        let path = safe_join(attempt, &name)?;
        let meta = fs::symlink_metadata(&path)?;
        ensure!(
            meta.is_file() && !meta.file_type().is_symlink(),
            "export input must be regular"
        );
        files.insert(
            name,
            FileEntry {
                size: meta.len(),
                sha256: source::file_digest(&path)?,
            },
        );
    }
    let payloads = assignment
        .units
        .iter()
        .map(|i| Ok((*i, run::read_payload(&plan, &assignment, attempt, *i)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut bundle = Bundle {
        schema: SCHEMA,
        id: String::new(),
        plan_id: plan.id.clone(),
        engine_source_id: plan.engine_source_id.clone(),
        builds: assignment.units.clone(),
        packages: run::selected_packages(&plan, &assignment),
        assignment,
        files,
    };
    bundle.id = bundle_id(&bundle)?;
    let out = io::guard_output(root, output)?;
    let attempt = attempt.canonicalize()?;
    ensure!(
        out == attempt.join("result") || (!out.starts_with(&attempt) && !attempt.starts_with(&out)),
        "export overlaps attempt outside result directory"
    );
    crate::cohort::bundle::prepare_collection(root, &out, &[], |staging| {
        copy_files(&attempt, staging, &bundle.files, &payloads)?;
        io::write_json_atomic(&staging.join("bundle.json"), &bundle)?;
        Ok(load(&plan, staging)?.bundle)
    })
}
pub fn export(root: &Path, attempt: &Path, output: &Path) -> Result<Bundle> {
    export_run(root, attempt, output)
}
pub fn import_candidate(root: &Path, plan: &Plan, input: &Path, output: &Path) -> Result<Bundle> {
    plan::validate_saved(root, plan)?;
    let snapshot = load_input(plan, input)?;
    crate::cohort::bundle::prepare_collection(root, output, &[input], |staging| {
        let directory = staging.join("bundle");
        fs::create_dir(&directory)?;
        copy_snapshot(&snapshot, &directory)?;
        let copied = load(plan, &directory)?;
        ensure!(
            copied.bundle == snapshot.bundle,
            "candidate changed during import"
        );
        io::write_json_atomic(
            &staging.join("candidate.json"),
            &Candidate {
                schema: SCHEMA,
                status: "candidate".into(),
                plan_id: plan.id.clone(),
                bundle_id: copied.bundle.id,
            },
        )?;
        Ok(load_input(plan, staging)?.bundle)
    })
}
pub fn import(root: &Path, input: &Path, output: &Path) -> Result<Bundle> {
    let (plan, _) = candidate(root, input)?;
    import_candidate(root, &plan, input, output)
}
fn select(
    plan: &Plan,
    snapshots: &BTreeMap<String, Snapshot>,
    policy: &Policy,
) -> Result<Vec<Selection>> {
    let mut builds = BTreeSet::new();
    let mut selected = BTreeMap::new();
    for (id, snapshot) in snapshots {
        for build in &snapshot.bundle.builds {
            ensure!(
                builds.insert(*build),
                "duplicate full build result across worker bundles: {build}"
            );
        }
        for (&package, record) in &snapshot.packages {
            let build = plan.packages[package].build;
            let payload = &snapshot.payloads[&build];
            proof::authorize(plan, &snapshot.bundle.assignment, payload, record, policy)?;
            ensure!(
                selected
                    .insert(
                        package,
                        Selection {
                            package,
                            build,
                            bundle_id: id.clone(),
                            record_id: record.id.clone(),
                            filename: record.filename.clone(),
                            sha256: record.sha256.clone()
                        }
                    )
                    .is_none(),
                "duplicate package across bundles"
            );
        }
    }
    ensure!(
        builds.into_iter().eq(0..plan.builds.len()),
        "worker results must cover every planned build exactly once"
    );
    ensure!(
        selected.keys().copied().eq(0..plan.packages.len()),
        "worker results must cover every planned package exactly once"
    );
    Ok(selected.into_values().collect())
}
fn sums(selections: &[Selection]) -> String {
    let mut rows = selections
        .iter()
        .map(|s| (&s.filename, &s.sha256))
        .collect::<Vec<_>>();
    rows.sort();
    rows.into_iter()
        .map(|(name, digest)| format!("{digest}  {name}\n"))
        .collect()
}
pub fn merge(
    root: &Path,
    plan: &Plan,
    results: &[PathBuf],
    policy: &Policy,
    output: &Path,
) -> Result<Collection> {
    plan::validate_saved(root, plan)?;
    crypto::validate_policy(policy)?;
    ensure!(
        !results.is_empty() && results.len() <= plan.builds.len(),
        "invalid bundle count"
    );
    let mut snapshots = BTreeMap::new();
    for input in results {
        let snapshot = load_input(plan, input)?;
        ensure!(
            snapshots
                .insert(snapshot.bundle.id.clone(), snapshot)
                .is_none(),
            "duplicate worker bundle"
        );
    }
    let selections = select(plan, &snapshots, policy)?;
    let mut collection = Collection {
        schema: SCHEMA,
        id: String::new(),
        plan_id: plan.id.clone(),
        engine_source_id: plan.engine_source_id.clone(),
        policy_id: crypto::policy_id(policy)?,
        status: "prepared".into(),
        publication_ready: false,
        selections,
        bundles: snapshots.keys().cloned().collect(),
    };
    collection.id = collection_id(&collection)?;
    let inputs = results.iter().map(PathBuf::as_path).collect::<Vec<_>>();
    crate::cohort::bundle::prepare_collection(root, output, &inputs, |staging| {
        fs::create_dir(staging.join("results"))?;
        fs::create_dir(staging.join("verified"))?;
        io::write_json_atomic(&staging.join("plan.json"), plan)?;
        io::write_json_atomic(&staging.join("policy.json"), policy)?;
        for (id, snapshot) in &snapshots {
            let directory = safe_join(staging, &format!("results/{id}"))?;
            fs::create_dir(&directory)?;
            copy_snapshot(snapshot, &directory)?;
        }
        for selection in &collection.selections {
            let snapshot = &snapshots[&selection.bundle_id];
            let name = format!("packages/{}/{}", selection.package, selection.filename);
            io::copy_file_checked(
                &safe_join(&snapshot.directory, &name)?,
                &safe_join(staging, &format!("verified/{}", selection.filename))?,
                &snapshot.files[&name],
            )?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(staging.join("verified/SHA256SUMS"))?;
        file.write_all(sums(&collection.selections).as_bytes())?;
        file.sync_all()?;
        io::write_json_atomic(&staging.join("collection.json"), &collection)?;
        verify_collection(root, staging, policy)
    })
}
pub fn verify_collection(root: &Path, output: &Path, policy: &Policy) -> Result<Collection> {
    crypto::validate_policy(policy)?;
    let collection: Collection = io::read_json(&safe_join(output, "collection.json")?)?;
    let plan: Plan = io::read_json(&safe_join(output, "plan.json")?)?;
    plan::validate_saved(root, &plan)?;
    ensure!(
        collection.schema == SCHEMA
            && collection.id == collection_id(&collection)?
            && collection.plan_id == plan.id
            && collection.engine_source_id == plan.engine_source_id,
        "collection identity differs"
    );
    ensure!(
        collection.status == "prepared" && !collection.publication_ready,
        "collection falsely claims publication readiness"
    );
    let saved_policy: Policy = io::read_json(&safe_join(output, "policy.json")?)?;
    crypto::validate_policy(&saved_policy)?;
    ensure!(
        collection.policy_id == crypto::policy_id(policy)?
            && collection.policy_id == crypto::policy_id(&saved_policy)?,
        "collection differs from explicitly supplied trust policy"
    );
    ensure!(
        !collection.bundles.is_empty()
            && collection.bundles.len() <= plan.builds.len()
            && collection.bundles.windows(2).all(|p| p[0] < p[1]),
        "invalid collection bundle set"
    );
    let mut expected = BTreeSet::from([
        "collection.json".to_string(),
        "plan.json".into(),
        "policy.json".into(),
        "verified/SHA256SUMS".into(),
    ]);
    let mut snapshots = BTreeMap::new();
    for id in &collection.bundles {
        ensure!(run::is_digest(id), "invalid bundle identity");
        let snapshot = load(&plan, &safe_join(output, &format!("results/{id}"))?)?;
        ensure!(&snapshot.bundle.id == id, "witness bundle identity differs");
        expected.extend(
            snapshot
                .files
                .keys()
                .map(|name| format!("results/{id}/{name}")),
        );
        snapshots.insert(id.clone(), snapshot);
    }
    let selections = select(&plan, &snapshots, policy)?;
    ensure!(
        collection.selections == selections,
        "collection selection differs from independent trust and exact coverage checks"
    );
    for selection in &selections {
        let name = format!("verified/{}", selection.filename);
        ensure!(expected.insert(name.clone()), "duplicate verified filename");
        let actual = source::file_digest(&safe_join(output, &name)?)?;
        ensure!(
            actual == selection.sha256,
            "verified package digest changed"
        );
        let record = &snapshots[&selection.bundle_id].packages[&selection.package];
        ensure!(
            fs::symlink_metadata(safe_join(output, &name)?)?.len() == record.size,
            "verified package size changed"
        );
        // Re-inspect the selected delivery bytes instead of trusting the witness
        // record or a checksum alone.
        super::inspect::inspect(
            &plan.packages[selection.package],
            &safe_join(output, &name)?,
            &snapshots[&selection.bundle_id].payloads[&selection.build].files,
        )?;
    }
    crate::cohort::bundle::exact_inventory(output, &expected)?;
    ensure!(
        fs::read_to_string(safe_join(output, "verified/SHA256SUMS")?)? == sums(&selections),
        "checksum inventory differs from all planned packages"
    );
    Ok(collection)
}
