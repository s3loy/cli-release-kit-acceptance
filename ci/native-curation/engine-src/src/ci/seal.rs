//! Data-only sealing after credential-free builds have finished.
//!
//! GitHub's REST artifact metadata binds an immutable archive to a run and SHA.
//! It does not attest the producing job. We additionally require a successful
//! expected job in the exact attempt and a unique reviewed artifact name; this
//! is a workflow control binding, not a cryptographic producer-job attestation.
use crate::{
    cohort::{
        crypto,
        model::{FileEntry, Proof},
    },
    source,
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Cursor, Read, Write},
    path::{Component, Path, PathBuf},
};

const DOMAIN: &[u8] = b"cli-release-kit/qualified-seal/v1\0";
const MAX_ARCHIVE: u64 = 512 * 1024 * 1024;
const MAX_EXPANDED: u64 = 2 * 1024 * 1024 * 1024;
pub const WORKFLOW: &str = ".github/workflows/relship-release.yml";
pub const PLAN_JOB_NAME: &str = "relship canonical qualified plan";
const PLAN_BINDING: &str = "plan:input";
pub fn input_artifact_name(run: u64, attempt: u64) -> String {
    format!("relship-qualified-input-{run}-{attempt}")
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Candidate,
    Rebuild,
}
impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Rebuild => "rebuild",
        }
    }
}
pub fn job_name(role: Role, profile: &str) -> String {
    format!("relship {} {profile}", role.name())
}
pub fn artifact_name(role: Role, profile: &str, run: u64, attempt: u64) -> String {
    format!(
        "relship-qualified-{}-{profile}-{run}-{attempt}",
        role.name()
    )
}

/// Expectations originate in the pinned engine, canonical plan, reviewed CI
/// configuration and workflow context, rather than in an uploaded result.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Expected {
    pub repository: String,
    pub branch: String,
    pub run_id: u64,
    pub run_attempt: u64,
    pub source_commit: String,
    pub engine_source_id: String,
    pub config_id: String,
    pub plan_id: String,
    pub schedule_id: String,
    /// Profile -> package ID -> canonical package filename.
    pub profiles: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub filename: String,
    pub size: u64,
    pub sha256: String,
    /// Identity of the statically verified complete validation record.
    pub validation_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub source_commit: String,
    pub engine_source_id: String,
    pub config_id: String,
    pub plan_id: String,
    pub schedule_id: String,
    pub profile: String,
    pub role: Role,
    pub packages: BTreeMap<String, Package>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Repository {
    pub id: u64,
    pub full_name: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowRun {
    pub id: u64,
    pub run_attempt: u64,
    pub head_sha: String,
    pub head_branch: String,
    pub event: String,
    pub path: String,
    pub repository: Repository,
    pub head_repository: Repository,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Job {
    pub id: u64,
    pub run_id: u64,
    pub run_attempt: u64,
    pub head_sha: String,
    pub name: String,
    pub status: String,
    pub conclusion: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactRun {
    pub id: u64,
    pub repository_id: u64,
    pub head_repository_id: u64,
    pub head_branch: String,
    pub head_sha: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Artifact {
    pub id: u64,
    pub name: String,
    pub size_in_bytes: u64,
    pub digest: Option<String>,
    pub expired: bool,
    pub workflow_run: ArtifactRun,
}

/// Production implementations must obtain these values from authenticated
/// control-plane requests. Uploaded JSON is never an implementation of this API.
pub trait ControlApi {
    fn workflow_run(&mut self, repository: &str, run: u64) -> Result<WorkflowRun>;
    fn jobs(&mut self, repository: &str, run: u64, attempt: u64) -> Result<Vec<Job>>;
    fn artifacts(&mut self, repository: &str, run: u64) -> Result<Vec<Artifact>>;
    fn download(&mut self, repository: &str, artifact: u64, limit: u64) -> Result<Vec<u8>>;
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub job: Job,
    pub artifact: Artifact,
}
/// Private fields prevent deserializing a bundle claim as trusted API capture.
#[derive(Clone, Debug, Serialize)]
pub struct ControlEvidence {
    run: WorkflowRun,
    bindings: BTreeMap<String, Binding>,
}
fn binding_key(role: Role, profile: &str) -> String {
    format!("{}:{profile}", role.name())
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn digest(value: &str) -> bool {
    crate::cohort::plan::is_digest(value)
}
fn commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn data_path(value: &str) -> bool {
    value.len() <= 4096
        && crate::config::relative(value).is_ok()
        && value.split('/').all(|component| component.len() <= 240)
}
fn consistent_path_case(value: &str, paths: &mut BTreeMap<String, String>) -> bool {
    let mut prefix = String::new();
    for component in value.split('/') {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);
        if let Some(previous) = paths.insert(prefix.to_ascii_lowercase(), prefix.clone())
            && previous != prefix
        {
            return false;
        }
    }
    true
}
pub fn validate_expected(value: &Expected) -> Result<()> {
    let segments = value.repository.split('/').collect::<Vec<_>>();
    ensure!(
        segments.len() == 2
            && segments
                .iter()
                .all(|s| super::config::safe_member(s) && !s.contains('/')),
        "invalid sealing repository"
    );
    ensure!(
        value.run_id != 0 && value.run_attempt != 0 && commit(&value.source_commit),
        "invalid expected run, attempt or source SHA"
    );
    ensure!(
        !value.branch.is_empty() && !value.branch.contains(['\n', '\r']),
        "invalid sealing branch"
    );
    for id in [
        &value.engine_source_id,
        &value.config_id,
        &value.plan_id,
        &value.schedule_id,
    ] {
        ensure!(digest(id), "invalid expected sealing identity");
    }
    ensure!(
        !value.profiles.is_empty() && value.profiles.len() <= 64,
        "sealing requires a bounded complete profile set"
    );
    let mut packages = BTreeSet::new();
    let mut names = BTreeSet::new();
    for (profile, expected) in &value.profiles {
        ensure!(
            identifier(profile) && !expected.is_empty(),
            "invalid or empty sealing profile"
        );
        for (id, filename) in expected {
            ensure!(
                digest(id) && packages.insert(id),
                "invalid or multiply assigned package identity"
            );
            ensure!(
                data_path(filename)
                    && !filename.contains('/')
                    && names.insert(filename.to_ascii_lowercase()),
                "unsafe or colliding sealing package filename"
            );
        }
    }
    ensure!(
        packages.len() <= 10000,
        "sealing package inventory exceeds bounds"
    );
    Ok(())
}

pub fn capture(api: &mut impl ControlApi, expected: &Expected) -> Result<ControlEvidence> {
    validate_expected(expected)?;
    let run = api.workflow_run(&expected.repository, expected.run_id)?;
    ensure!(
        run.id == expected.run_id
            && run.run_attempt == expected.run_attempt
            && run.head_sha == expected.source_commit
            && run.head_branch == expected.branch
            && run.event == "workflow_dispatch"
            && run.path == WORKFLOW
            && run.repository.id != 0
            && run.repository == run.head_repository
            && run.repository.full_name == expected.repository,
        "GitHub workflow run differs from approved repository, dispatch, branch, SHA, workflow or attempt"
    );
    let jobs = api.jobs(&expected.repository, expected.run_id, expected.run_attempt)?;
    let artifacts = api.artifacts(&expected.repository, expected.run_id)?;
    ensure!(
        jobs.len() <= 10000 && artifacts.len() <= 10000,
        "GitHub control evidence exceeds bounds"
    );
    let mut job_ids = BTreeSet::new();
    ensure!(
        jobs.iter().all(|j| j.id != 0 && job_ids.insert(j.id)),
        "GitHub returned duplicate job IDs"
    );
    let mut artifact_ids = BTreeSet::new();
    ensure!(
        artifacts
            .iter()
            .all(|a| a.id != 0 && artifact_ids.insert(a.id)),
        "GitHub returned duplicate artifact IDs"
    );
    let mut bindings = BTreeMap::new();
    let specs = std::iter::once((
        PLAN_BINDING.to_string(),
        PLAN_JOB_NAME.to_string(),
        input_artifact_name(expected.run_id, expected.run_attempt),
    ))
    .chain(expected.profiles.keys().flat_map(|profile| {
        [Role::Candidate, Role::Rebuild]
            .into_iter()
            .map(move |role| {
                (
                    binding_key(role, profile),
                    job_name(role, profile),
                    artifact_name(role, profile, expected.run_id, expected.run_attempt),
                )
            })
    }));
    for (key, name, artifact_name) in specs {
        let matches = jobs.iter().filter(|j| j.name == name).collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "expected successful job is missing or duplicated: {name}"
        );
        let job = matches[0];
        ensure!(
            job.run_id == expected.run_id
                && job.run_attempt == expected.run_attempt
                && job.head_sha == expected.source_commit
                && job.status == "completed"
                && job.conclusion.as_deref() == Some("success"),
            "expected job did not complete successfully at the approved run, attempt and SHA: {name}"
        );
        let name = artifact_name;
        let matches = artifacts
            .iter()
            .filter(|a| a.name == name)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "expected artifact is missing or duplicated: {name}"
        );
        let artifact = matches[0];
        let origin = &artifact.workflow_run;
        ensure!(
            !artifact.expired
                && artifact.size_in_bytes > 0
                && artifact.size_in_bytes <= MAX_ARCHIVE
                && origin.id == expected.run_id
                && origin.repository_id == run.repository.id
                && origin.head_repository_id == run.repository.id
                && origin.head_sha == expected.source_commit
                && origin.head_branch == expected.branch,
            "artifact origin differs from approved run/repository/source or artifact is expired/oversized"
        );
        ensure!(
            artifact
                .digest
                .as_deref()
                .and_then(|v| v.strip_prefix("sha256:"))
                .is_some_and(digest),
            "GitHub artifact has no canonical SHA-256 digest"
        );
        bindings.insert(
            key,
            Binding {
                job: job.clone(),
                artifact: artifact.clone(),
            },
        );
    }
    Ok(ControlEvidence { run, bindings })
}

fn validate_control(expected: &Expected, evidence: &ControlEvidence) -> Result<()> {
    struct Snapshot<'a>(&'a ControlEvidence);
    impl ControlApi for Snapshot<'_> {
        fn workflow_run(&mut self, _: &str, _: u64) -> Result<WorkflowRun> {
            Ok(self.0.run.clone())
        }
        fn jobs(&mut self, _: &str, _: u64, _: u64) -> Result<Vec<Job>> {
            Ok(self.0.bindings.values().map(|b| b.job.clone()).collect())
        }
        fn artifacts(&mut self, _: &str, _: u64) -> Result<Vec<Artifact>> {
            Ok(self
                .0
                .bindings
                .values()
                .map(|b| b.artifact.clone())
                .collect())
        }
        fn download(&mut self, _: &str, _: u64, _: u64) -> Result<Vec<u8>> {
            anyhow::bail!("control snapshot cannot download artifacts")
        }
    }
    let checked = capture(&mut Snapshot(evidence), expected)?;
    ensure!(
        checked.bindings == evidence.bindings,
        "control binding set differs from the exact expected profile roles"
    );
    Ok(())
}

pub fn download(
    api: &mut impl ControlApi,
    expected: &Expected,
    evidence: &ControlEvidence,
    role: Role,
    profile: &str,
    output: &Path,
) -> Result<()> {
    download_binding(api, expected, evidence, &binding_key(role, profile), output)
}
fn download_binding(
    api: &mut impl ControlApi,
    expected: &Expected,
    evidence: &ControlEvidence,
    key: &str,
    output: &Path,
) -> Result<()> {
    validate_control(expected, evidence)?;
    let binding = evidence
        .bindings
        .get(key)
        .context("missing artifact binding")?;
    let bytes = api.download(&expected.repository, binding.artifact.id, MAX_ARCHIVE)?;
    ensure!(
        bytes.len() as u64 == binding.artifact.size_in_bytes
            && binding.artifact.digest.as_deref()
                == Some(&format!("sha256:{}", source::digest(&bytes))),
        "downloaded artifact archive differs from GitHub size or digest"
    );
    extract(&bytes, output)
}

/// Extract only bounded regular data. No checkout, hooks, built programs or
/// consumer supplied archive utilities are involved in the sealing process.
pub fn extract(bytes: &[u8], output: &Path) -> Result<()> {
    ensure!(
        !output.exists() && bytes.len() as u64 <= MAX_ARCHIVE,
        "artifact destination exists or archive is oversized"
    );
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).context("invalid artifact ZIP")?;
    ensure!(
        !zip.is_empty() && zip.len() <= 10000,
        "artifact ZIP member count is invalid"
    );
    let mut names = BTreeSet::new();
    let mut path_cases = BTreeMap::new();
    let mut total = 0u64;
    // Validate every entry before writing the first file.
    for index in 0..zip.len() {
        let entry = zip.by_index(index)?;
        let name = entry.name().strip_suffix('/').unwrap_or(entry.name());
        ensure!(
            data_path(name)
                && names.insert(name.to_ascii_lowercase())
                && consistent_path_case(name, &mut path_cases),
            "unsafe or colliding artifact ZIP member"
        );
        ensure!(
            entry.unix_mode().is_none_or(|mode| mode & 0o170000 == 0
                || mode & 0o170000 == if entry.is_dir() { 0o040000 } else { 0o100000 }),
            "artifact ZIP contains a link or special file"
        );
        total = total
            .checked_add(entry.size())
            .context("artifact ZIP size overflow")?;
        ensure!(
            entry.size() <= MAX_ARCHIVE && total <= MAX_EXPANDED,
            "artifact ZIP expansion exceeds bounds"
        );
    }
    fs::create_dir_all(output)?;
    let result = (|| -> Result<()> {
        for index in 0..zip.len() {
            let mut entry = zip.by_index(index)?;
            let name = entry.name().strip_suffix('/').unwrap_or(entry.name());
            let path = crate::config::safe_join(output, name)?;
            if entry.is_dir() {
                fs::create_dir_all(path)?;
                continue;
            }
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?;
            let count = std::io::copy(&mut entry.by_ref().take(MAX_ARCHIVE + 1), &mut file)?;
            ensure!(
                count == entry.size() && count <= MAX_ARCHIVE,
                "artifact ZIP member exceeds declared size"
            );
            file.flush()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(output);
    }
    result
}

pub fn validate_manifest(
    expected: &Expected,
    role: Role,
    profile: &str,
    manifest: &Manifest,
) -> Result<()> {
    validate_expected(expected)?;
    let packages = expected
        .profiles
        .get(profile)
        .context("unknown sealing profile")?;
    ensure!(
        manifest.schema == 1
            && manifest.role == role
            && manifest.profile == profile
            && manifest.source_commit == expected.source_commit
            && manifest.engine_source_id == expected.engine_source_id
            && manifest.config_id == expected.config_id
            && manifest.plan_id == expected.plan_id
            && manifest.schedule_id == expected.schedule_id,
        "result manifest differs from approved source, plan, schedule, engine, role or profile"
    );
    ensure!(
        manifest.packages.keys().eq(packages.keys()),
        "result must cover exactly the complete expected profile package set"
    );
    for (id, package) in &manifest.packages {
        ensure!(
            package.filename == packages[id]
                && package.size > 0
                && package.size <= MAX_ARCHIVE
                && digest(&package.sha256)
                && digest(&package.validation_id),
            "invalid package bytes, validation identity or canonical filename"
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    pub schema: u32,
    pub id: String,
    pub expected: Expected,
    pub run: WorkflowRun,
    pub bindings: BTreeMap<String, Binding>,
    pub manifests: Vec<Manifest>,
    pub candidate_matches: BTreeMap<String, BTreeMap<String, bool>>,
    pub evidence_inventory: BTreeMap<String, FileEntry>,
    pub proof: Option<Proof>,
}

/// A comparison is an observation about these two executions. A mismatch
/// preserves the policy of sealing the complete controlled fresh rebuild.
fn compare_candidates(
    expected: &Expected,
    manifests: &[Manifest],
) -> Result<BTreeMap<String, BTreeMap<String, bool>>> {
    ensure!(
        manifests.len() == expected.profiles.len() * 2,
        "candidate comparison requires both profile roles"
    );
    let mut matches = BTreeMap::new();
    for (profile, packages) in &expected.profiles {
        let candidates = manifests
            .iter()
            .filter(|m| m.profile == *profile && m.role == Role::Candidate)
            .collect::<Vec<_>>();
        let rebuilds = manifests
            .iter()
            .filter(|m| m.profile == *profile && m.role == Role::Rebuild)
            .collect::<Vec<_>>();
        ensure!(
            candidates.len() == 1 && rebuilds.len() == 1,
            "candidate comparison requires one candidate and one rebuild per profile"
        );
        validate_manifest(expected, Role::Candidate, profile, candidates[0])?;
        validate_manifest(expected, Role::Rebuild, profile, rebuilds[0])?;
        matches.insert(
            profile.clone(),
            packages
                .keys()
                .map(|id| {
                    let candidate = &candidates[0].packages[id];
                    let rebuilt = &rebuilds[0].packages[id];
                    (
                        id.clone(),
                        candidate.size == rebuilt.size && candidate.sha256 == rebuilt.sha256,
                    )
                })
                .collect(),
        );
    }
    Ok(matches)
}
fn record_id(record: &Sealed) -> Result<String> {
    let mut canonical = record.clone();
    canonical.id.clear();
    canonical.proof = None;
    crypto::content_id(DOMAIN, &canonical)
}
pub fn seal(
    expected: &Expected,
    evidence: &ControlEvidence,
    manifests: &[Manifest],
    key: &SigningKey,
) -> Result<Sealed> {
    seal_with_inventory(expected, evidence, manifests, BTreeMap::new(), key)
}

pub fn seal_with_inventory(
    expected: &Expected,
    evidence: &ControlEvidence,
    manifests: &[Manifest],
    evidence_inventory: BTreeMap<String, FileEntry>,
    key: &SigningKey,
) -> Result<Sealed> {
    validate_control(expected, evidence)?;
    validate_evidence_inventory(expected, &evidence_inventory, false)?;
    ensure!(
        manifests.len() == expected.profiles.len() * 2,
        "sealing requires both candidate and fresh rebuild for every profile"
    );
    let mut seen = BTreeSet::new();
    let mut canonical = manifests.to_vec();
    canonical.sort_by(|a, b| (&a.profile, a.role).cmp(&(&b.profile, b.role)));
    for manifest in &canonical {
        validate_manifest(expected, manifest.role, &manifest.profile, manifest)?;
        let binding = binding_key(manifest.role, &manifest.profile);
        ensure!(
            seen.insert(binding.clone()) && evidence.bindings.contains_key(&binding),
            "duplicate result or result without GitHub control binding"
        );
    }
    let mut record = Sealed {
        schema: 1,
        id: String::new(),
        expected: expected.clone(),
        run: evidence.run.clone(),
        bindings: evidence.bindings.clone(),
        manifests: canonical,
        candidate_matches: compare_candidates(expected, manifests)?,
        evidence_inventory,
        proof: None,
    };
    record.id = record_id(&record)?;
    record.proof = Some(crypto::seal_record(&record.id, DOMAIN, key));
    Ok(record)
}
pub fn verify(record: &Sealed, public_key: &str) -> Result<()> {
    ensure!(
        record.schema == 1 && record.id == record_id(record)?,
        "sealed collection identity differs"
    );
    validate_expected(&record.expected)?;
    validate_evidence_inventory(&record.expected, &record.evidence_inventory, false)?;
    validate_control(
        &record.expected,
        &ControlEvidence {
            run: record.run.clone(),
            bindings: record.bindings.clone(),
        },
    )?;
    ensure!(
        record.manifests.len() == record.expected.profiles.len() * 2,
        "sealed collection is incomplete"
    );
    let mut seen = BTreeSet::new();
    for manifest in &record.manifests {
        validate_manifest(&record.expected, manifest.role, &manifest.profile, manifest)?;
        ensure!(
            seen.insert(binding_key(manifest.role, &manifest.profile)),
            "duplicate sealed profile role"
        );
    }
    ensure!(
        record.candidate_matches == compare_candidates(&record.expected, &record.manifests)?,
        "candidate comparison flags differ from the complete candidate and fresh rebuild package bytes"
    );
    crypto::verify_record(&record.id, DOMAIN, record.proof.as_ref(), Some(public_key))
}

fn comparison_summary(
    expected: &Expected,
    matches: &BTreeMap<String, BTreeMap<String, bool>>,
) -> String {
    let mut text = String::from(
        "\nCandidate and fresh rebuild comparison for this execution:\n\n| Profile | Package | Size and SHA-256 |\n| --- | --- | --- |\n",
    );
    for (profile, packages) in matches {
        for (id, same) in packages {
            text.push_str(&format!(
                "| `{profile}` | `{}` | {} |\n",
                expected.profiles[profile][id],
                if *same { "match" } else { "different" }
            ));
        }
    }
    text.push_str("\nThe sealed collection contains the verified fresh rebuild packages, including when candidate bytes differ. Each comparison records only these two executions.\n");
    text
}

pub fn verify_collection(output: &Path, public_key: &str) -> Result<Sealed> {
    let metadata = fs::symlink_metadata(output)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "sealed collection must be a regular directory"
    );
    let record: Sealed =
        crate::cohort::io::read_json(&crate::config::safe_join(output, "collection.json")?)?;
    verify(&record, public_key)?;
    validate_evidence_inventory(&record.expected, &record.evidence_inventory, true)?;
    let artifacts = crate::config::safe_join(output, "artifacts")?;
    let expected = collection_files(&record.manifests, &record.evidence_inventory)?;
    let mut entries = crate::cohort::io::inventory(output)?;
    ensure!(
        entries.remove("collection.json").is_some(),
        "sealed collection record is missing"
    );
    ensure!(
        entries == expected,
        "sealed file inventory differs from signed rebuilt packages and evidence"
    );
    reject_unlisted_directories(output, output, &expected)?;
    verify_preserved_records(
        &record.expected,
        &record.manifests,
        &record.evidence_inventory,
        output,
        &artifacts,
    )?;
    Ok(record)
}

fn collection_files(
    manifests: &[Manifest],
    inventory: &BTreeMap<String, FileEntry>,
) -> Result<BTreeMap<String, FileEntry>> {
    let mut files = inventory.clone();
    for manifest in manifests.iter().filter(|m| m.role == Role::Rebuild) {
        for package in manifest.packages.values() {
            ensure!(
                files
                    .insert(
                        format!("artifacts/{}", package.filename),
                        FileEntry {
                            size: package.size,
                            sha256: package.sha256.clone()
                        }
                    )
                    .is_none(),
                "duplicate sealed artifact filename"
            );
        }
    }
    Ok(files)
}

fn validate_evidence_inventory(
    expected: &Expected,
    inventory: &BTreeMap<String, FileEntry>,
    require_complete: bool,
) -> Result<()> {
    ensure!(
        inventory.len() <= 10000,
        "sealed evidence inventory exceeds bounds"
    );
    let mut total = 0u64;
    let mut names = BTreeSet::new();
    let mut path_cases = BTreeMap::new();
    for (name, file) in inventory {
        ensure!(
            data_path(name)
                && names.insert(name.to_ascii_lowercase())
                && consistent_path_case(name, &mut path_cases),
            "unsafe or case-colliding sealed evidence path"
        );
        let mut parts = name.splitn(3, '/');
        ensure!(
            parts.next() == Some("records"),
            "sealed evidence must be under records/<profile>"
        );
        let profile = parts.next().context("sealed evidence profile is missing")?;
        let relative = parts.next().context("sealed evidence member is missing")?;
        ensure!(
            expected.profiles.contains_key(profile)
                && (relative == "plan.json"
                    || relative == "receipt.json"
                    || relative.starts_with("evidence/")
                    || relative.starts_with("validations/")),
            "sealed evidence contains an unknown profile or a member outside the data-only closure"
        );
        ensure!(
            digest(&file.sha256) && file.size <= crate::cohort::io::FILE_LIMIT,
            "invalid sealed evidence file identity"
        );
        total = total
            .checked_add(file.size)
            .context("sealed evidence size overflow")?;
        ensure!(
            total <= crate::cohort::io::BUNDLE_LIMIT,
            "sealed evidence exceeds total size bound"
        );
    }
    if require_complete {
        for profile in expected.profiles.keys() {
            ensure!(
                inventory.contains_key(&format!("records/{profile}/plan.json"))
                    && inventory.contains_key(&format!("records/{profile}/receipt.json")),
                "sealed collection lacks complete preserved rebuild evidence"
            );
        }
    }
    Ok(())
}

fn reject_unlisted_directories(
    root: &Path,
    at: &Path,
    expected: &BTreeMap<String, FileEntry>,
) -> Result<()> {
    for entry in fs::read_dir(at)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let path = entry.path();
            let name = path
                .strip_prefix(root)?
                .to_str()
                .context("non-UTF8 sealed directory")?
                .replace('\\', "/");
            ensure!(
                expected
                    .keys()
                    .any(|file| file.starts_with(&format!("{name}/"))),
                "sealed collection contains an unlisted directory"
            );
            reject_unlisted_directories(root, &path, expected)?;
        }
    }
    Ok(())
}

fn verify_preserved_records(
    expected: &Expected,
    manifests: &[Manifest],
    inventory: &BTreeMap<String, FileEntry>,
    output: &Path,
    artifacts: &Path,
) -> Result<()> {
    validate_evidence_inventory(expected, inventory, true)?;
    let records = crate::config::safe_join(output, "records")?;
    let actual = crate::cohort::io::inventory(&records)?
        .into_iter()
        .map(|(name, file)| (format!("records/{name}"), file))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        &actual == inventory,
        "preserved rebuild evidence differs from signed inventory"
    );
    for profile in expected.profiles.keys() {
        let root = crate::config::safe_join(&records, profile)?;
        let plan = crate::qualified::plan::load(&root.join("plan.json"))?;
        let text = plan
            .ci_config
            .as_deref()
            .context("preserved plan lacks reviewed CI configuration")?;
        let cfg: super::model::Config = toml::from_str(text)
            .map_err(|_| anyhow::anyhow!("invalid preserved reviewed CI configuration"))?;
        let derived = super::qualified::expected(
            &cfg,
            &plan,
            &expected.repository,
            &expected.source_commit,
            expected.run_id,
            expected.run_attempt,
        )?;
        ensure!(
            &derived == expected,
            "preserved rebuild plan differs from signed source, engine, CI configuration or schedule"
        );
        let receipt = crate::qualified::run::verify_with_artifacts(&root, true, artifacts)?;
        let manifest = super::qualified::manifest(&cfg, &plan, &receipt, profile, Role::Rebuild)?;
        let signed = manifests
            .iter()
            .find(|m| m.profile == *profile && m.role == Role::Rebuild)
            .context("missing signed rebuild manifest")?;
        ensure!(
            &manifest == signed,
            "preserved rebuild evidence differs from signed package and validation manifest"
        );
    }
    Ok(())
}

/// The entry point intentionally requires no consumer checkout. All inputs are
/// parsed as bounded data, the API supplies transport provenance, and the only
/// signing-key read happens after the complete static verification succeeds.
#[allow(clippy::too_many_arguments)]
pub fn execute(
    cfg: &super::model::Config,
    plan: &crate::qualified::model::Plan,
    expected_source: &str,
    run_id: u64,
    run_attempt: u64,
    results: &Path,
    output: &Path,
    key: &Path,
) -> Result<Sealed> {
    let repository = std::env::var("GITHUB_REPOSITORY")
        .context("independent sealing requires GITHUB_REPOSITORY from workflow context")?;
    let mut api = crate::github::api::Client::from_env()?;
    execute_with_api(
        &mut api,
        cfg,
        plan,
        &repository,
        expected_source,
        run_id,
        run_attempt,
        results,
        output,
        key,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execute_with_api(
    api: &mut impl ControlApi,
    cfg: &super::model::Config,
    plan: &crate::qualified::model::Plan,
    repository: &str,
    expected_source: &str,
    run_id: u64,
    run_attempt: u64,
    results: &Path,
    output: &Path,
    key: &Path,
) -> Result<Sealed> {
    let expected =
        super::qualified::expected(cfg, plan, repository, expected_source, run_id, run_attempt)?;
    let evidence = capture(api, &expected)?;
    let results = new_data_directory(results)?;
    let output = new_data_directory(output)?;
    ensure!(
        !results.starts_with(&output) && !output.starts_with(&results),
        "sealing result inputs and collection output overlap"
    );
    ensure!(
        !key.starts_with(&results) && !key.starts_with(&output),
        "sealing key overlaps result or collection output"
    );
    fs::create_dir(&results)?;
    let input = results.join("input");
    download_binding(api, &expected, &evidence, PLAN_BINDING, &input)?;
    let supplied: crate::qualified::model::Plan =
        crate::cohort::io::read_json(&input.join("plan.json"))?;
    ensure!(
        &supplied == plan,
        "API-bound input plan differs from approved canonical plan"
    );
    let mut manifests = Vec::new();
    let mut rebuild_paths = BTreeMap::new();
    for profile in expected.profiles.keys() {
        for role in [Role::Candidate, Role::Rebuild] {
            let directory = results.join(format!("{}-{profile}", role.name()));
            download(api, &expected, &evidence, role, profile, &directory)?;
            let embedded: crate::qualified::model::Plan =
                crate::cohort::io::read_json(&directory.join("plan.json"))?;
            ensure!(
                &embedded == plan,
                "transport plan differs from the approved canonical plan"
            );
            let receipt = crate::qualified::run::verify(&directory, true)?;
            let manifest = super::qualified::manifest(cfg, plan, &receipt, profile, role)?;
            validate_manifest(&expected, role, profile, &manifest)?;
            if role == Role::Rebuild {
                rebuild_paths.insert(profile.clone(), directory);
            }
            manifests.push(manifest);
        }
    }
    // Derive all candidate comparisons before opening any signing material.
    // A false comparison records the differing fresh rebuild; it is not a gate.
    let candidate_matches = compare_candidates(&expected, &manifests)?;
    let summary = comparison_summary(&expected, &candidate_matches);
    // Copy only the verified rebuilt deliverables into the sealed collection.
    // Diagnostics, SDKs, source trees and executables used during builds remain
    // outside this deliverable directory.
    fs::create_dir(&output)?;
    let artifacts = output.join("artifacts");
    fs::create_dir(&artifacts)?;
    let mut evidence_inventory = BTreeMap::new();
    for (profile, directory) in &rebuild_paths {
        let manifest = manifests
            .iter()
            .find(|m| m.profile == *profile && m.role == Role::Rebuild)
            .context("missing rebuilt manifest")?;
        for (id, package) in &manifest.packages {
            let index = plan
                .packages
                .iter()
                .position(|p| &p.id == id)
                .context("unknown rebuilt package")?;
            let relative = format!("packages/{index}/{}", package.filename);
            let input = crate::config::safe_join(directory, &relative)?;
            let metadata = fs::symlink_metadata(&input)?;
            ensure!(
                metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.len() == package.size,
                "rebuilt package is not the verified regular file"
            );
            let target = crate::config::safe_join(&artifacts, &package.filename)?;
            let mut source = fs::File::open(&input)?;
            let mut destination = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)?;
            let copied = std::io::copy(
                &mut Read::by_ref(&mut source).take(package.size + 1),
                &mut destination,
            )?;
            destination.sync_all()?;
            ensure!(
                copied == package.size && crate::source::file_digest(&target)? == package.sha256,
                "rebuilt package changed while copying sealed collection"
            );
        }
        let records = output.join("records").join(profile);
        fs::create_dir_all(&records)?;
        for (name, file) in crate::cohort::io::inventory(directory)? {
            if name == "plan.json"
                || name == "receipt.json"
                || name.starts_with("evidence/")
                || name.starts_with("validations/")
            {
                let target = crate::config::safe_join(&records, &name)?;
                fs::create_dir_all(target.parent().context("preserved record has no parent")?)?;
                crate::cohort::io::copy_file_checked(&directory.join(&name), &target, &file)?;
                ensure!(
                    evidence_inventory
                        .insert(format!("records/{profile}/{name}"), file)
                        .is_none(),
                    "duplicate preserved rebuild evidence"
                );
            }
        }
    }
    let expected_files = collection_files(&manifests, &evidence_inventory)?;
    ensure!(
        crate::cohort::io::inventory(&output)? == expected_files,
        "prepared collection differs from complete rebuilt package and evidence inventory"
    );
    reject_unlisted_directories(&output, &output, &expected_files)?;
    verify_preserved_records(
        &expected,
        &manifests,
        &evidence_inventory,
        &output,
        &artifacts,
    )?;
    // The key is opened only after all candidate/rebuild control, preserved
    // evidence, final package and comparison checks have completed.
    let signer = crypto::load_key(key)?;
    let record = seal_with_inventory(
        &expected,
        &evidence,
        &manifests,
        evidence_inventory,
        &signer,
    )?;
    verify(&record, &crypto::public_key(&signer))?;
    crate::cohort::io::write_json_atomic(&output.join("collection.json"), &record)?;
    verify_collection(&output, &crypto::public_key(&signer))?;
    if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        file.write_all(summary.as_bytes())?;
    }
    Ok(record)
}

fn new_data_directory(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        ensure!(
            !matches!(component, Component::ParentDir),
            "sealing paths cannot contain parent traversal"
        );
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "sealing output ancestry must contain regular directories"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    ensure!(
        !absolute.exists(),
        "sealing directory already exists; use a fresh attempt"
    );
    let parent = absolute
        .parent()
        .context("sealing directory has no parent")?;
    ensure!(parent.is_dir(), "sealing directory parent must exist");
    Ok(absolute)
}

impl ControlApi for crate::github::api::Client {
    fn workflow_run(&mut self, repository: &str, run: u64) -> Result<WorkflowRun> {
        self.actions_json(repository, &format!("runs/{run}"))
    }
    fn jobs(&mut self, repository: &str, run: u64, attempt: u64) -> Result<Vec<Job>> {
        #[derive(Deserialize)]
        struct Page {
            total_count: usize,
            jobs: Vec<Job>,
        }
        let mut all = Vec::new();
        for page in 1..=100 {
            let batch: Page = self.actions_json(
                repository,
                &format!("runs/{run}/attempts/{attempt}/jobs?per_page=100&page={page}"),
            )?;
            ensure!(
                batch.jobs.len() <= 100 && batch.total_count <= 10000,
                "GitHub job pagination exceeds bounds"
            );
            let complete = batch.jobs.len() < 100;
            all.extend(batch.jobs);
            if complete {
                ensure!(
                    all.len() == batch.total_count,
                    "GitHub job pagination was incomplete"
                );
                return Ok(all);
            }
        }
        anyhow::bail!("GitHub job pagination limit reached")
    }
    fn artifacts(&mut self, repository: &str, run: u64) -> Result<Vec<Artifact>> {
        #[derive(Deserialize)]
        struct Page {
            total_count: usize,
            artifacts: Vec<Artifact>,
        }
        let mut all = Vec::new();
        for page in 1..=100 {
            let batch: Page = self.actions_json(
                repository,
                &format!("runs/{run}/artifacts?per_page=100&page={page}"),
            )?;
            ensure!(
                batch.artifacts.len() <= 100 && batch.total_count <= 10000,
                "GitHub artifact pagination exceeds bounds"
            );
            let complete = batch.artifacts.len() < 100;
            all.extend(batch.artifacts);
            if complete {
                ensure!(
                    all.len() == batch.total_count,
                    "GitHub artifact pagination was incomplete"
                );
                return Ok(all);
            }
        }
        anyhow::bail!("GitHub artifact pagination limit reached")
    }
    fn download(&mut self, repository: &str, artifact: u64, limit: u64) -> Result<Vec<u8>> {
        self.actions_artifact(repository, artifact, limit)
    }
}
