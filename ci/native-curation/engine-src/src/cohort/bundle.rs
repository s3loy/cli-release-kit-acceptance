use super::{crypto, io, model::*, plan, run};
use crate::{config, execute::checksum_text, source};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

const MEMBER_LIMIT: usize = 10_000;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidate {
    schema: u32,
    status: String,
    plan_id: String,
    bundle_id: String,
}

struct Validated {
    directory: PathBuf,
    bundle: Bundle,
    records: BTreeMap<usize, UnitRecord>,
    files: BTreeMap<String, FileEntry>,
}

pub fn bundle_id(bundle: &Bundle) -> Result<String> {
    let mut value = bundle.clone();
    value.id.clear();
    let mut bytes = b"cli-release-kit/bundle/v1\0".to_vec();
    bytes.extend(serde_json::to_vec(&value)?);
    Ok(source::digest(&bytes))
}

pub fn collection_id(collection: &Collection) -> Result<String> {
    let mut value = collection.clone();
    value.id.clear();
    let mut bytes = b"cli-release-kit/collection/v1\0".to_vec();
    bytes.extend(serde_json::to_vec(&value)?);
    Ok(source::digest(&bytes))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn expected_bundle_files(plan: &Plan, units: &[usize]) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::from(["plan.json".into()]);
    ensure!(!units.is_empty(), "bundle has no units");
    ensure!(units.len() <= MEMBER_LIMIT / 2, "too many bundled units");
    for &index in units {
        let unit = plan.units.get(index).context("unknown bundled unit")?;
        ensure!(
            names.insert(format!("units/{index}/unit.json"))
                && names.insert(format!("units/{index}/{}", unit.filename)),
            "duplicate bundled unit or filename"
        );
    }
    Ok(names)
}

// Check the directory shape before recursive inventory so unknown empty directories,
// deep directory trees, and case aliases cannot hide outside the file manifest.
pub(crate) fn exact_inventory(
    directory: &Path,
    expected: &BTreeSet<String>,
) -> Result<BTreeMap<String, FileEntry>> {
    ensure!(expected.len() <= MEMBER_LIMIT, "too many snapshot members");
    let metadata = fs::symlink_metadata(directory)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "snapshot root must be a regular directory"
    );
    let mut directories = BTreeSet::new();
    let mut portable = BTreeSet::new();
    for name in expected {
        config::relative(name)?;
        ensure!(name.len() <= 4096, "snapshot path exceeds size limit");
        let mut prefix = String::new();
        let components: Vec<_> = name.split('/').collect();
        ensure!(components.len() <= 32, "snapshot path exceeds depth limit");
        for (index, component) in components.iter().enumerate() {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(component);
            if index + 1 < components.len() {
                directories.insert(prefix.clone());
            }
        }
    }
    for name in expected.iter().chain(directories.iter()) {
        ensure!(
            portable.insert(name.to_ascii_lowercase()),
            "case-colliding snapshot path"
        );
    }
    fn walk(
        base: &Path,
        directory: &Path,
        expected: &BTreeSet<String>,
        directories: &BTreeSet<String>,
        count: &mut usize,
    ) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            *count += 1;
            ensure!(*count <= MEMBER_LIMIT * 2, "too many snapshot entries");
            let path = entry.path();
            let name = path
                .strip_prefix(base)?
                .components()
                .map(|component| {
                    component
                        .as_os_str()
                        .to_str()
                        .context("non-UTF8 snapshot member")
                })
                .collect::<Result<Vec<_>>>()?
                .join("/");
            config::relative(&name)?;
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                !metadata.file_type().is_symlink(),
                "snapshot symlink: {name}"
            );
            if metadata.is_dir() {
                ensure!(directories.contains(&name), "unexpected directory: {name}");
                walk(base, &path, expected, directories, count)?;
            } else {
                ensure!(
                    metadata.is_file() && expected.contains(&name),
                    "unexpected or non-regular snapshot member: {name}"
                );
            }
        }
        Ok(())
    }
    walk(directory, directory, expected, &directories, &mut 0)?;
    let files = io::inventory(directory)?;
    ensure!(
        files.keys().cloned().collect::<BTreeSet<_>>() == *expected,
        "snapshot has missing or extra files"
    );
    Ok(files)
}

fn load_bundle(root: &Path, plan: &Plan, directory: &Path) -> Result<Validated> {
    let bundle: Bundle = io::read_json(&config::safe_join(directory, "bundle.json")?)?;
    ensure!(bundle.schema == SCHEMA, "unsupported bundle schema");
    ensure!(
        bundle.id == bundle_id(&bundle)?,
        "bundle content identity mismatch"
    );
    ensure!(
        bundle.plan_id == plan.id && bundle.engine_source_id == plan.engine_source_id,
        "bundle belongs to another plan or engine"
    );
    plan::validate_assignment(plan, &bundle.assignment)?;
    ensure!(
        bundle.units == bundle.assignment.units,
        "bundle does not cover its complete worker assignment"
    );
    let expected = expected_bundle_files(plan, &bundle.units)?;
    ensure!(
        bundle.files.keys().cloned().collect::<BTreeSet<_>>() == expected,
        "bundle manifest differs from the planned worker files"
    );
    let mut total = 0u64;
    for file in bundle.files.values() {
        ensure!(
            is_digest(&file.sha256) && file.size <= io::FILE_LIMIT,
            "invalid bundle manifest entry"
        );
        total = total
            .checked_add(file.size)
            .context("bundle size overflow")?;
        ensure!(total <= io::BUNDLE_LIMIT, "bundle exceeds total size limit");
    }
    let mut with_manifest = expected;
    with_manifest.insert("bundle.json".into());
    let files = exact_inventory(directory, &with_manifest)?;
    ensure!(
        bundle
            .files
            .iter()
            .all(|(name, expected)| files.get(name) == Some(expected)),
        "bundle manifest size or digest mismatch"
    );
    let saved: Plan = io::read_json(&config::safe_join(directory, "plan.json")?)?;
    ensure!(
        &saved == plan,
        "bundle immutable plan differs from requested plan"
    );
    let mut records = BTreeMap::new();
    for &unit in &bundle.units {
        let record = run::read_unit(root, plan, &bundle.assignment, directory, unit)?;
        records.insert(unit, record);
    }
    Ok(Validated {
        directory: directory.to_path_buf(),
        bundle,
        records,
        files,
    })
}

pub fn validate(root: &Path, plan: &Plan, bundle_dir: &Path) -> Result<Bundle> {
    plan::validate(root, plan)?;
    Ok(load_bundle(root, plan, bundle_dir)?.bundle)
}

fn load_input(root: &Path, plan: &Plan, input: &Path) -> Result<Validated> {
    let marker_path = config::safe_join(input, "candidate.json")?;
    match fs::symlink_metadata(&marker_path) {
        Ok(_) => {
            let marker: Candidate = io::read_json(&marker_path)?;
            ensure!(
                marker.schema == SCHEMA && marker.status == "candidate",
                "invalid external candidate marker"
            );
            let directory = config::safe_join(input, "bundle")?;
            let snapshot = load_bundle(root, plan, &directory)?;
            ensure!(
                marker.plan_id == plan.id && marker.bundle_id == snapshot.bundle.id,
                "candidate marker does not bind its immutable bundle"
            );
            let expected = std::iter::once("candidate.json".into())
                .chain(snapshot.files.keys().map(|name| format!("bundle/{name}")))
                .collect();
            exact_inventory(input, &expected)?;
            Ok(snapshot)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            load_bundle(root, plan, input)
        }
        Err(error) => Err(error.into()),
    }
}

pub fn candidate_ref(root: &Path, plan: &Plan, dir: &Path) -> Result<CandidateRef> {
    plan::validate(root, plan)?;
    let snapshot = load_input(root, plan, dir)?;
    Ok(CandidateRef {
        bundle_id: snapshot.bundle.id,
        digests: snapshot
            .records
            .into_iter()
            .map(|(index, record)| (index, record.artifact.sha256))
            .collect(),
    })
}

fn output_outside_inputs(root: &Path, output: &Path, inputs: &[&Path]) -> Result<PathBuf> {
    let output = io::guard_output(root, output)?;
    for input in inputs {
        let input = input.canonicalize()?;
        ensure!(
            !output.starts_with(&input) && !input.starts_with(&output),
            "output overlaps an input snapshot"
        );
    }
    Ok(output)
}

fn export_output(root: &Path, attempt: &Path, output: &Path) -> Result<PathBuf> {
    let output = io::guard_output(root, output)?;
    let attempt = attempt.canonicalize()?;
    ensure!(
        output == attempt.join("result")
            || (!output.starts_with(&attempt) && !attempt.starts_with(&output)),
        "export output overlaps attempt inputs outside its result directory"
    );
    Ok(output)
}

fn file_entry(path: &Path) -> Result<FileEntry> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "snapshot input is not a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(metadata.nlink() == 1, "hardlinked snapshot input");
    }
    ensure!(
        metadata.len() <= io::FILE_LIMIT,
        "snapshot file exceeds limit"
    );
    Ok(FileEntry {
        sha256: source::file_digest(path)?,
        size: metadata.len(),
    })
}

fn copy_snapshot(snapshot: &Validated, output: &Path) -> Result<()> {
    for (name, entry) in &snapshot.files {
        io::copy_file_checked(
            &config::safe_join(&snapshot.directory, name)?,
            &config::safe_join(output, name)?,
            entry,
        )?;
    }
    io::sync_directory(output)?;
    Ok(())
}

pub fn export_run(root: &Path, attempt: &Path, output: &Path) -> Result<Bundle> {
    run::verify_run(root, attempt)?;
    let plan: Plan = io::read_json(&config::safe_join(attempt, "plan.json")?)?;
    let assignment: Assignment = io::read_json(&config::safe_join(attempt, "assignment.json")?)?;
    let names = expected_bundle_files(&plan, &assignment.units)?;
    let mut files = BTreeMap::new();
    let mut total = 0u64;
    for name in names {
        let entry = file_entry(&config::safe_join(attempt, &name)?)?;
        total = total
            .checked_add(entry.size)
            .context("bundle size overflow")?;
        ensure!(total <= io::BUNDLE_LIMIT, "bundle exceeds total size limit");
        files.insert(name, entry);
    }
    let mut bundle = Bundle {
        schema: SCHEMA,
        id: String::new(),
        plan_id: plan.id.clone(),
        engine_source_id: plan.engine_source_id.clone(),
        units: assignment.units.clone(),
        assignment,
        files,
    };
    bundle.id = bundle_id(&bundle)?;
    let output = export_output(root, attempt, output)?;
    let output = io::fresh_directory(&output)?;
    for (name, entry) in &bundle.files {
        io::copy_file_checked(
            &config::safe_join(attempt, name)?,
            &config::safe_join(&output, name)?,
            entry,
        )?;
    }
    io::write_json_atomic(&output.join("bundle.json"), &bundle)?;
    validate(root, &plan, &output)
}

pub fn import_candidate(root: &Path, plan: &Plan, input: &Path, output: &Path) -> Result<Bundle> {
    plan::validate(root, plan)?;
    let snapshot = load_input(root, plan, input)?;
    let output = output_outside_inputs(root, output, &[input])?;
    let output = io::fresh_directory(&output)?;
    let directory = config::safe_join(&output, "bundle")?;
    fs::create_dir(&directory)?;
    copy_snapshot(&snapshot, &directory)?;
    let copied = load_bundle(root, plan, &directory)?;
    ensure!(
        copied.bundle == snapshot.bundle,
        "candidate snapshot changed during import"
    );
    io::write_json_atomic(
        &output.join("candidate.json"),
        &Candidate {
            schema: SCHEMA,
            status: "candidate".into(),
            plan_id: plan.id.clone(),
            bundle_id: copied.bundle.id.clone(),
        },
    )?;
    Ok(load_input(root, plan, &output)?.bundle)
}

fn select(
    plan: &Plan,
    snapshots: &BTreeMap<String, Validated>,
    policy: &Policy,
) -> Result<Vec<Selection>> {
    let mut selected = BTreeMap::new();
    for (bundle_id, snapshot) in snapshots {
        for (&unit, record) in &snapshot.records {
            ensure!(
                !selected.contains_key(&unit),
                "duplicate unit {unit} across worker results"
            );
            crypto::authorize(plan, &snapshot.bundle.assignment, record, policy)?;
            selected.insert(
                unit,
                Selection {
                    unit,
                    bundle_id: bundle_id.clone(),
                    record_id: record.id.clone(),
                    filename: record.artifact.filename.clone(),
                    sha256: record.artifact.sha256.clone(),
                },
            );
        }
    }
    ensure!(
        selected.keys().copied().eq(0..plan.units.len()),
        "worker results do not cover every planned unit exactly once"
    );
    Ok(selected.into_values().collect())
}

fn artifacts(
    selections: &[Selection],
    snapshots: &BTreeMap<String, Validated>,
) -> Vec<crate::model::Artifact> {
    selections
        .iter()
        .map(|selection| {
            snapshots[&selection.bundle_id].records[&selection.unit]
                .artifact
                .clone()
        })
        .collect()
}

fn rename_directory_exclusive(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let source = CString::new(source.as_os_str().as_bytes())?;
        let destination = CString::new(destination.as_os_str().as_bytes())?;
        // Both C strings remain alive through the call. Exclusive rename preserves
        // a destination created after the initial fresh-output check.
        #[cfg(target_os = "linux")]
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        let result =
            unsafe { libc::renamex_np(source.as_ptr(), destination.as_ptr(), libc::RENAME_EXCL) };
        ensure!(
            result == 0,
            "atomic collection rename: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
    #[cfg(windows)]
    {
        // Windows directory rename fails if the destination already exists.
        fs::rename(source, destination).context("atomic collection rename")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (source, destination);
        anyhow::bail!("exclusive atomic collection rename is unavailable on this host")
    }
}

fn sync_snapshot_directories(directory: &Path) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "staged collection symlink"
        );
        if metadata.is_dir() {
            sync_snapshot_directories(&path)?;
        }
    }
    io::sync_directory(directory)
}

pub(crate) fn prepare_collection<T>(
    root: &Path,
    output: &Path,
    inputs: &[&Path],
    prepare: impl FnOnce(&Path) -> Result<T>,
) -> Result<T> {
    let output = output_outside_inputs(root, output, inputs)?;
    let parent = output.parent().context("collection output has no parent")?;
    let staging = config::safe_join(parent, &format!(".kit-collection-{}", io::random_id()?))?;
    let staging = io::guard_output(root, &staging)?;
    let staging = io::fresh_directory(&staging)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
    }
    let prepared = (|| -> Result<T> {
        let prepared = prepare(&staging)?;
        sync_snapshot_directories(&staging)?;
        io::sync_directory(parent)?;
        Ok(prepared)
    })()
    .with_context(|| {
        format!(
            "collection was not installed; staging retained at {}",
            staging.display()
        )
    })?;
    rename_directory_exclusive(&staging, &output)
        .with_context(|| format!("collection staging retained at {}", staging.display()))?;
    if let Err(error) = io::sync_directory(parent) {
        rename_directory_exclusive(&output, &staging).with_context(|| {
            format!(
                "collection installed at {} but parent sync failed ({error:#}); withdrawal failed",
                output.display()
            )
        })?;
        return Err(error).with_context(|| {
            format!(
                "collection installation withdrawn; staging retained at {}",
                staging.display()
            )
        });
    }
    Ok(prepared)
}

pub fn merge(
    root: &Path,
    plan: &Plan,
    results: &[PathBuf],
    policy: &Policy,
    output: &Path,
) -> Result<Collection> {
    plan::validate(root, plan)?;
    crypto::validate_policy(policy)?;
    ensure!(
        !results.is_empty() && results.len() <= plan.units.len(),
        "invalid worker result count"
    );
    let mut snapshots = BTreeMap::new();
    let mut total = 0u64;
    for result in results {
        let snapshot = load_input(root, plan, result)?;
        for entry in snapshot.files.values() {
            total = total
                .checked_add(entry.size)
                .context("collection size overflow")?;
            ensure!(
                total <= io::BUNDLE_LIMIT,
                "collection exceeds total size limit"
            );
        }
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
    let sums = checksum_text(&artifacts(&collection.selections, &snapshots));
    let member_count = snapshots
        .values()
        .try_fold(4 + collection.selections.len(), |count, snapshot| {
            count.checked_add(snapshot.files.len())
        })
        .context("collection member count overflow")?;
    ensure!(member_count <= MEMBER_LIMIT, "too many collection members");
    for selection in &collection.selections {
        let name = format!("units/{}/{}", selection.unit, selection.filename);
        total = total
            .checked_add(snapshots[&selection.bundle_id].files[&name].size)
            .context("collection size overflow")?;
    }
    for size in [
        serde_json::to_vec_pretty(plan)?.len() + 1,
        serde_json::to_vec_pretty(policy)?.len() + 1,
        serde_json::to_vec_pretty(&collection)?.len() + 1,
        sums.len(),
    ] {
        total = total
            .checked_add(size as u64)
            .context("collection size overflow")?;
    }
    ensure!(
        total <= io::BUNDLE_LIMIT,
        "collection exceeds total size limit"
    );
    let inputs: Vec<_> = results.iter().map(PathBuf::as_path).collect();
    prepare_collection(root, output, &inputs, |output| {
        fs::create_dir(output.join("results"))?;
        fs::create_dir(output.join("verified"))?;
        io::write_json_atomic(&output.join("plan.json"), plan)?;
        io::write_json_atomic(&output.join("policy.json"), policy)?;
        for (id, snapshot) in &snapshots {
            let directory = config::safe_join(output, &format!("results/{id}"))?;
            fs::create_dir(&directory)?;
            copy_snapshot(snapshot, &directory)?;
        }
        for selection in &collection.selections {
            let name = format!("units/{}/{}", selection.unit, selection.filename);
            let snapshot = &snapshots[&selection.bundle_id];
            io::copy_file_checked(
                &config::safe_join(output, &format!("results/{}/{name}", selection.bundle_id))?,
                &config::safe_join(output, &format!("verified/{}", selection.filename))?,
                &snapshot.files[&name],
            )?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output.join("verified/SHA256SUMS"))?;
        file.write_all(sums.as_bytes())?;
        file.sync_all()?;
        drop(file);
        io::write_json_atomic(&output.join("collection.json"), &collection)?;
        verify_collection(root, output, policy)
    })
}

pub fn verify_collection(root: &Path, output: &Path, policy: &Policy) -> Result<Collection> {
    crypto::validate_policy(policy)?;
    let collection: Collection = io::read_json(&config::safe_join(output, "collection.json")?)?;
    let plan: Plan = io::read_json(&config::safe_join(output, "plan.json")?)?;
    plan::validate(root, &plan)?;
    ensure!(collection.schema == SCHEMA, "unsupported collection schema");
    ensure!(
        collection.id == collection_id(&collection)?,
        "collection content identity mismatch"
    );
    ensure!(
        collection.plan_id == plan.id && collection.engine_source_id == plan.engine_source_id,
        "collection belongs to another plan or engine"
    );
    ensure!(
        collection.status == "prepared" && !collection.publication_ready,
        "collection falsely claims publication readiness"
    );
    let saved_policy: Policy = io::read_json(&config::safe_join(output, "policy.json")?)?;
    crypto::validate_policy(&saved_policy)?;
    ensure!(
        collection.policy_id == crypto::policy_id(policy)?
            && collection.policy_id == crypto::policy_id(&saved_policy)?,
        "collection policy differs from the explicitly supplied trust policy"
    );
    ensure!(
        !collection.bundles.is_empty() && collection.bundles.len() <= plan.units.len(),
        "invalid collection bundle count"
    );
    let mut snapshots = BTreeMap::new();
    let mut expected = BTreeSet::from([
        "collection.json".into(),
        "plan.json".into(),
        "policy.json".into(),
        "verified/SHA256SUMS".into(),
    ]);
    let mut total = 0u64;
    for id in &collection.bundles {
        ensure!(is_digest(id), "invalid collection bundle identity");
        let directory = config::safe_join(output, &format!("results/{id}"))?;
        let snapshot = load_bundle(root, &plan, &directory)?;
        ensure!(&snapshot.bundle.id == id, "witness bundle identity changed");
        for (name, entry) in &snapshot.files {
            expected.insert(format!("results/{id}/{name}"));
            total = total
                .checked_add(entry.size)
                .context("collection size overflow")?;
            ensure!(
                total <= io::BUNDLE_LIMIT,
                "collection exceeds total size limit"
            );
        }
        ensure!(
            snapshots.insert(id.clone(), snapshot).is_none(),
            "duplicate collection witness"
        );
    }
    ensure!(
        collection.bundles == snapshots.keys().cloned().collect::<Vec<_>>(),
        "collection witnesses must have canonical order"
    );
    let selections = select(&plan, &snapshots, policy)?;
    ensure!(
        collection.selections == selections,
        "collection selection differs from trusted witnesses"
    );
    for selection in &selections {
        expected.insert(format!("verified/{}", selection.filename));
    }
    let inventory = exact_inventory(output, &expected)?;
    for selection in &selections {
        let snapshot = &snapshots[&selection.bundle_id];
        let name = format!("units/{}/{}", selection.unit, selection.filename);
        ensure!(
            inventory.get(&format!("verified/{}", selection.filename)) == snapshot.files.get(&name),
            "verified artifact bytes differ from their trusted witness"
        );
    }
    let sums = checksum_text(&artifacts(&selections, &snapshots));
    ensure!(
        inventory.get("verified/SHA256SUMS")
            == Some(&FileEntry {
                sha256: source::digest(sums.as_bytes()),
                size: sums.len() as u64,
            }),
        "verified checksum coverage, order or bytes differ"
    );
    Ok(collection)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("kit-cohort-bundle-")
            .tempdir_in("/tmp")
            .unwrap()
    }

    #[test]
    fn snapshot_rejects_unknown_empty_directories_and_missing_files() {
        let directory = temporary();
        let expected = BTreeSet::from(["plan.json".into()]);
        assert!(exact_inventory(directory.path(), &expected).is_err());
        fs::write(directory.path().join("plan.json"), b"{}").unwrap();
        assert!(exact_inventory(directory.path(), &expected).is_ok());
        fs::create_dir(directory.path().join("extra")).unwrap();
        assert!(exact_inventory(directory.path(), &expected).is_err());
    }

    #[test]
    fn snapshot_rejects_case_conflicts_across_directories() {
        let directory = temporary();
        let expected = BTreeSet::from(["Units/0/unit.json".into(), "units/1/unit.json".into()]);
        assert!(exact_inventory(directory.path(), &expected).is_err());
    }

    #[test]
    fn export_allows_only_the_fresh_result_directory_inside_an_attempt() {
        let directory = temporary();
        let root = directory.path().join("source");
        let attempt = directory.path().join("attempt");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&attempt).unwrap();
        for name in ["units", "invocations", "metadata"] {
            fs::create_dir(attempt.join(name)).unwrap();
            assert!(export_output(&root, &attempt, &attempt.join(name).join("result")).is_err());
        }
        assert!(export_output(&root, &attempt, &attempt.join("other")).is_err());
        assert!(export_output(&root, &attempt, &attempt.join("result")).is_ok());
        assert!(export_output(&root, &attempt, &directory.path().join("external")).is_ok());
        assert!(output_outside_inputs(&root, &attempt.join("result"), &[&attempt]).is_err());
        fs::create_dir(attempt.join("result")).unwrap();
        assert!(export_output(&root, &attempt, &attempt.join("result")).is_err());
    }

    #[test]
    fn failed_collection_preparation_keeps_requested_output_absent() {
        let directory = temporary();
        let root = directory.path().join("source");
        let output = directory.path().join("collection");
        fs::create_dir(&root).unwrap();
        let result = prepare_collection::<()>(&root, &output, &[], |staging| {
            fs::create_dir(staging.join("verified"))?;
            fs::write(staging.join("collection.json"), b"prepared")?;
            assert!(!output.exists());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(fs::metadata(staging)?.permissions().mode() & 0o777, 0o700);
            }
            anyhow::bail!("late collection verification failed")
        });
        assert!(result.is_err());
        assert!(!output.exists());
        let retained: Vec<_> = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".kit-collection-")
            })
            .collect();
        assert_eq!(retained.len(), 1);
        assert!(retained[0].join("verified").is_dir());
        assert!(retained[0].join("collection.json").is_file());
    }

    #[test]
    fn successful_collection_preparation_installs_the_whole_directory() {
        let directory = temporary();
        let root = directory.path().join("source");
        let output = directory.path().join("collection");
        fs::create_dir(&root).unwrap();
        let result = prepare_collection(&root, &output, &[], |staging| {
            fs::create_dir(staging.join("verified"))?;
            fs::write(staging.join("verified/archive"), b"artifact")?;
            fs::write(staging.join("collection.json"), b"prepared")?;
            assert!(!output.exists());
            Ok("prepared")
        })
        .unwrap();
        assert_eq!(result, "prepared");
        assert_eq!(
            fs::read(output.join("verified/archive")).unwrap(),
            b"artifact"
        );
        assert_eq!(
            fs::read(output.join("collection.json")).unwrap(),
            b"prepared"
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    }

    #[test]
    fn collection_installation_does_not_replace_an_existing_directory() {
        let directory = temporary();
        let staging = directory.path().join("staging");
        let output = directory.path().join("collection");
        fs::create_dir(&staging).unwrap();
        fs::create_dir(&output).unwrap();
        fs::write(staging.join("collection.json"), b"new").unwrap();
        assert!(rename_directory_exclusive(&staging, &output).is_err());
        assert!(staging.join("collection.json").is_file());
        assert_eq!(fs::read_dir(&output).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_rejects_symlinks_and_hardlinks() {
        let directory = temporary();
        let external = temporary();
        let source = external.path().join("original");
        fs::write(&source, b"{}").unwrap();
        let member = directory.path().join("plan.json");
        let expected = BTreeSet::from(["plan.json".into()]);
        std::os::unix::fs::symlink(&source, &member).unwrap();
        assert!(exact_inventory(directory.path(), &expected).is_err());
        fs::remove_file(&member).unwrap();
        fs::hard_link(&source, &member).unwrap();
        assert!(exact_inventory(directory.path(), &expected).is_err());
    }
}
