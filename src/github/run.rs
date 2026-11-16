use super::{model::*, plan};
use crate::{
    cohort::{
        io,
        model::{FileEntry, Policy},
    },
    config::safe_join,
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
};

const EVENT_LIMIT: usize = 10_000;
const CREATE_LOOKUPS: usize = 3;

pub fn draft_body(plan: &Plan, correlation: &str) -> String {
    format!(
        "{}\n\n<!-- cli-release-kit draft-plan:{} collection:{} correlation:{} -->",
        plan.notes, plan.id, plan.collection_id, correlation
    )
}

enum CollectionPolicy<'a> {
    Legacy(&'a Policy),
    V5(&'a crate::v5::proof::Policy),
}
impl CollectionPolicy<'_> {
    fn validate(&self, root: &Path, collection: &Path, plan: &Plan, execute: bool) -> Result<()> {
        match self {
            Self::Legacy(policy) => plan::validate(root, collection, policy, plan, execute),
            Self::V5(policy) => plan::validate_v5(root, collection, policy, plan, execute),
        }
    }
}

pub fn stage(
    root: &Path,
    collection: &Path,
    policy: &Policy,
    plan: &Plan,
    output: &Path,
    api: &mut dyn Api,
) -> Result<Receipt> {
    stage_with_policy(
        root,
        collection,
        CollectionPolicy::Legacy(policy),
        plan,
        output,
        api,
    )
}

pub fn stage_v5(
    root: &Path,
    collection: &Path,
    policy: &crate::v5::proof::Policy,
    plan: &Plan,
    output: &Path,
    api: &mut dyn Api,
) -> Result<Receipt> {
    stage_with_policy(
        root,
        collection,
        CollectionPolicy::V5(policy),
        plan,
        output,
        api,
    )
}

fn stage_with_policy(
    root: &Path,
    collection: &Path,
    policy: CollectionPolicy<'_>,
    plan: &Plan,
    output: &Path,
    api: &mut dyn Api,
) -> Result<Receipt> {
    policy.validate(root, collection, plan, true)?;
    let output = io::guard_output(root, output)?;
    collection_overlap(collection, &output)?;
    create_private_directory(&output)?;
    let _writer = writer_lock(&output)?;
    io::write_json_atomic(&output.join("plan.json"), plan)?;
    let mut receipt = new_receipt(plan)?;
    save(&output, &mut receipt)?;
    let result = (|| {
        snapshot(collection, &output, plan)?;
        execute_remote(plan, &output, &mut receipt, api, false, false)
    })();
    finish(&output, &mut receipt, result)
}

pub fn resume(
    root: &Path,
    collection: &Path,
    policy: &Policy,
    output: &Path,
    api: &mut dyn Api,
    retry_create_draft: bool,
) -> Result<Receipt> {
    run_existing(
        root,
        collection,
        CollectionPolicy::Legacy(policy),
        output,
        api,
        false,
        retry_create_draft,
    )
}

pub fn verify(
    root: &Path,
    collection: &Path,
    policy: &Policy,
    output: &Path,
    api: &mut dyn Api,
) -> Result<Receipt> {
    run_existing(
        root,
        collection,
        CollectionPolicy::Legacy(policy),
        output,
        api,
        true,
        false,
    )
}

pub fn resume_v5(
    root: &Path,
    collection: &Path,
    policy: &crate::v5::proof::Policy,
    output: &Path,
    api: &mut dyn Api,
    retry_create_draft: bool,
) -> Result<Receipt> {
    run_existing(
        root,
        collection,
        CollectionPolicy::V5(policy),
        output,
        api,
        false,
        retry_create_draft,
    )
}

pub fn verify_v5(
    root: &Path,
    collection: &Path,
    policy: &crate::v5::proof::Policy,
    output: &Path,
    api: &mut dyn Api,
) -> Result<Receipt> {
    run_existing(
        root,
        collection,
        CollectionPolicy::V5(policy),
        output,
        api,
        true,
        false,
    )
}

fn run_existing(
    root: &Path,
    collection: &Path,
    policy: CollectionPolicy<'_>,
    output: &Path,
    api: &mut dyn Api,
    read_only: bool,
    retry_create_draft: bool,
) -> Result<Receipt> {
    let output = existing_output(root, collection, output)?;
    let _writer = writer_lock(&output)?;
    let local_plan = plan::load(&safe_join(&output, "plan.json")?)?;
    let mut receipt = status(&output)?;
    let result = (|| {
        policy.validate(root, collection, &local_plan, !read_only)?;
        ensure_snapshot(collection, &output, &local_plan, &receipt)?;
        execute_remote(
            &local_plan,
            &output,
            &mut receipt,
            api,
            read_only,
            retry_create_draft,
        )
    })();
    finish(&output, &mut receipt, result)
}

fn create_private_directory(output: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(output)?;
    io::sync_directory(output.parent().context("output has no parent")?)?;
    Ok(())
}

fn collection_overlap(collection: &Path, output: &Path) -> Result<()> {
    let collection = collection.canonicalize()?;
    ensure!(
        !output.starts_with(&collection) && !collection.starts_with(output),
        "draft output overlaps immutable collection"
    );
    Ok(())
}

fn existing_output(root: &Path, collection: &Path, output: &Path) -> Result<PathBuf> {
    regular_directory(output)?;
    let output = output.canonicalize()?;
    collection_overlap(collection, &output)?;
    let root = root.canonicalize()?;
    ensure!(
        !root.starts_with(&output),
        "draft output overlaps source root"
    );
    if output.starts_with(&root) {
        ensure!(
            output.starts_with(root.join("target")) && output != root.join("target"),
            "source-tree draft outputs must be beneath ignored target/"
        );
        let relative = output
            .strip_prefix(&root)?
            .to_str()
            .context("non-UTF8 draft output")?;
        crate::process::capture(
            &root,
            &[
                "git".into(),
                "check-ignore".into(),
                "--quiet".into(),
                "--".into(),
                relative.into(),
            ],
            30,
        )
        .context("draft output must be ignored")?;
        ensure!(
            crate::source::git(&root, &["ls-files", "--", relative])?.is_empty(),
            "draft output overlaps tracked inputs"
        );
    }
    Ok(output)
}

fn regular_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "draft output must be a regular directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "draft output must be private (mode 0700)"
        );
    }
    Ok(())
}

fn regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "draft member must be a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(metadata.nlink() == 1, "draft member must not be hardlinked");
    }
    Ok(())
}

fn writer_lock(output: &Path) -> Result<io::WriterLock> {
    let path = safe_join(output, ".writer.lock")?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    regular_file(&path)?;
    io::WriterLock::acquire(file)
        .context("draft attempt already has a writer or cannot acquire its advisory lock")
}

fn expected_snapshot(plan: &Plan) -> BTreeMap<String, FileEntry> {
    plan.assets
        .iter()
        .map(|asset| {
            (
                asset.name.clone(),
                FileEntry {
                    size: asset.size,
                    sha256: asset.sha256.clone(),
                },
            )
        })
        .collect()
}

fn snapshot(collection: &Path, output: &Path, plan: &Plan) -> Result<()> {
    let destination = safe_join(output, "snapshot")?;
    ensure!(
        matches!(fs::symlink_metadata(&destination), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
        "snapshot already exists or cannot be inspected"
    );
    // A crash leaves an isolated preparation directory, never a partly committed
    // snapshot. Keep such directories as evidence and use a fresh random name.
    let directory = safe_join(output, &format!(".snapshot-{}", io::random_id()?))?;
    create_private_directory(&directory)?;
    for asset in &plan.assets {
        let expected = FileEntry {
            size: asset.size,
            sha256: asset.sha256.clone(),
        };
        io::copy_file_checked(
            &safe_join(&collection.join("verified"), &asset.name)?,
            &safe_join(&directory, &asset.name)?,
            &expected,
        )?;
    }
    ensure!(
        io::inventory(&directory)? == expected_snapshot(plan),
        "prepared snapshot differs from plan"
    );
    io::sync_directory(&directory)?;
    fs::rename(&directory, &destination)?;
    io::sync_directory(output)?;
    validate_snapshot(output, plan)
}

fn ensure_snapshot(collection: &Path, output: &Path, plan: &Plan, receipt: &Receipt) -> Result<()> {
    match fs::symlink_metadata(safe_join(output, "snapshot")?) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            ensure!(
                receipt.release_id.is_none()
                    && receipt.pending.is_none()
                    && receipt.confirmed_assets.is_empty()
                    && !receipt.events.iter().any(|event| event.outcome == "intent"),
                "snapshot is missing after a remote intent; preserve the attempt for inspection"
            );
            snapshot(collection, output, plan)
        }
        Err(error) => Err(error.into()),
        Ok(_) => validate_snapshot(output, plan),
    }
}

fn validate_snapshot(output: &Path, plan: &Plan) -> Result<()> {
    ensure!(
        io::inventory(&safe_join(output, "snapshot")?)? == expected_snapshot(plan),
        "draft snapshot contains changed, missing or extra bytes"
    );
    Ok(())
}

fn new_receipt(plan: &Plan) -> Result<Receipt> {
    Ok(Receipt {
        schema: 1,
        plan_id: plan.id.clone(),
        correlation: io::random_id()?,
        status: "running".into(),
        release_id: None,
        pending: None,
        confirmed_assets: BTreeMap::new(),
        events: Vec::new(),
        updated_at_ms: io::now_ms(),
        error: None,
    })
}

fn save(output: &Path, receipt: &mut Receipt) -> Result<()> {
    receipt.updated_at_ms = io::now_ms().max(receipt.updated_at_ms);
    io::write_json_atomic(&safe_join(output, "receipt.json")?, receipt)
}

fn event(receipt: &mut Receipt, operation: &str, outcome: &str) {
    let at_ms = io::now_ms().max(receipt.updated_at_ms);
    receipt.updated_at_ms = at_ms;
    if receipt.events.len() >= EVENT_LIMIT {
        receipt
            .events
            .drain(..receipt.events.len() + 1 - EVENT_LIMIT);
    }
    receipt.events.push(Event {
        at_ms,
        operation: operation.into(),
        outcome: outcome.into(),
    });
}

fn intent(
    output: &Path,
    receipt: &mut Receipt,
    operation: &str,
    asset: Option<&str>,
) -> Result<()> {
    receipt.pending = Some(Intent {
        operation: operation.into(),
        asset: asset.map(str::to_owned),
    });
    receipt.status = "running".into();
    receipt.error = None;
    event(receipt, operation, "intent");
    // Both the file and containing directory are synced before the remote write.
    save(output, receipt)
}

fn confirmed(output: &Path, receipt: &mut Receipt, operation: &str) -> Result<()> {
    receipt.pending = None;
    event(receipt, operation, "confirmed");
    save(output, receipt)
}

fn finish(output: &Path, receipt: &mut Receipt, result: Result<()>) -> Result<Receipt> {
    if let Err(error) = result {
        let message = format!("{error:#}");
        receipt.status = error
            .downcast_ref::<DraftFailure>()
            .map_or("failed", DraftFailure::status)
            .into();
        receipt.error = Some(message.chars().take(4096).collect());
        event(receipt, "check", "failed");
        save(output, receipt).context("failed to persist draft failure receipt")?;
        return Err(error);
    }
    save(output, receipt)?;
    Ok(receipt.clone())
}

fn check_repository(plan: &Plan, api: &mut dyn Api) -> Result<()> {
    let actual = api.repository(&plan.repository.full_name)?;
    ensure!(
        actual.id == plan.repository.id
            && actual
                .full_name
                .eq_ignore_ascii_case(&plan.repository.full_name),
        DraftFailure::Conflict("repository was renamed, transferred or replaced".into())
    );
    Ok(())
}

fn check_release(plan: &Plan, receipt: &Receipt, release: &Release) -> Result<()> {
    ensure!(
        release.id != 0
            && release.tag_name == plan.tag
            && release.prerelease == plan.prerelease
            && release.name.as_deref() == Some(plan.title.as_str())
            && release.body.as_deref() == Some(draft_body(plan, &receipt.correlation).as_str()),
        DraftFailure::Conflict(
            "same-tag release is foreign or its planned metadata changed".into()
        )
    );
    ensure!(
        receipt.release_id.is_none_or(|id| id == release.id),
        DraftFailure::Conflict("receipt release ID differs from same-tag release".into())
    );
    Ok(())
}

fn find_release(plan: &Plan, receipt: &Receipt, api: &mut dyn Api) -> Result<Option<Release>> {
    let matches: Vec<_> = api
        .releases(&plan.repository.full_name)?
        .into_iter()
        .filter(|release| release.tag_name == plan.tag)
        .collect();
    ensure!(
        matches.len() <= 1,
        DraftFailure::Conflict("multiple releases exist for the planned tag".into())
    );
    let Some(listed) = matches.into_iter().next() else {
        return Ok(None);
    };
    check_release(plan, receipt, &listed)?;
    let current = api.release(&plan.repository.full_name, listed.id)?;
    ensure!(
        current.id == listed.id,
        DraftFailure::Conflict("release lookup returned a different ID".into())
    );
    check_release(plan, receipt, &current)?;
    Ok(Some(current))
}

fn check_tag(plan: &Plan, api: &mut dyn Api) -> Result<()> {
    ensure!(
        api.tag(&plan.repository.full_name, &plan.tag)?.as_deref()
            == Some(plan.source_commit.as_str()),
        DraftFailure::Conflict("remote tag is missing or points to another commit".into())
    );
    Ok(())
}

fn guard_remote(plan: &Plan, receipt: &Receipt, api: &mut dyn Api, draft: bool) -> Result<Release> {
    check_repository(plan, api)?;
    check_tag(plan, api)?;
    let release = find_release(plan, receipt, api)?
        .context(DraftFailure::Conflict("planned release disappeared".into()))?;
    if draft {
        ensure!(
            release.draft,
            DraftFailure::Conflict(
                "owned release was published while staging; resume can observe it without writes"
                    .into()
            )
        );
    }
    Ok(release)
}

fn ensure_tag(
    plan: &Plan,
    output: &Path,
    receipt: &mut Receipt,
    api: &mut dyn Api,
    read_only: bool,
) -> Result<()> {
    match api.tag(&plan.repository.full_name, &plan.tag)? {
        Some(commit) => {
            ensure!(
                commit == plan.source_commit,
                DraftFailure::Conflict("remote tag points to another commit".into())
            );
            if receipt
                .pending
                .as_ref()
                .is_some_and(|i| i.operation == "create_tag")
            {
                confirmed(output, receipt, "create_tag")?;
            }
        }
        None => {
            ensure!(
                receipt.release_id.is_none()
                    && receipt
                        .pending
                        .as_ref()
                        .is_none_or(|i| i.operation == "create_tag"),
                DraftFailure::Conflict(
                    "tag disappeared after an earlier draft or upload intent".into()
                )
            );
            ensure!(!read_only, "remote tag is missing");
            ensure!(
                plan.create_tag_if_missing,
                "remote tag is missing and tag creation was not approved in the plan"
            );
            intent(output, receipt, "create_tag", None)?;
            let response =
                api.create_tag(&plan.repository.full_name, &plan.tag, &plan.source_commit);
            match api.tag(&plan.repository.full_name, &plan.tag)? {
                Some(commit) => {
                    ensure!(
                        commit == plan.source_commit,
                        DraftFailure::Conflict("tag creation resolved to another commit".into())
                    );
                    confirmed(output, receipt, "create_tag")?;
                }
                None => {
                    if let Err(error) = response {
                        return Err(error).context("tag creation outcome is unconfirmed; resume will recheck its exact ref");
                    }
                    bail!("tag creation is not observable; resume will recheck its exact ref");
                }
            }
        }
    }
    Ok(())
}

fn create_release(
    plan: &Plan,
    output: &Path,
    receipt: &mut Receipt,
    api: &mut dyn Api,
    retry: bool,
) -> Result<Release> {
    ensure!(
        receipt.release_id.is_none(),
        DraftFailure::Conflict("previously recorded release disappeared".into())
    );
    let uncertain = receipt
        .pending
        .as_ref()
        .is_some_and(|intent| intent.operation == "create_draft");
    ensure!(
        !uncertain || retry,
        DraftFailure::NeedsDecision("an earlier create-draft intent has no observable release; inspect GitHub and explicitly use --retry-create-draft to authorize another POST".into())
    );
    // A missing result is never enough to authorize a repeated create POST.
    check_repository(plan, api)?;
    check_tag(plan, api)?;
    if let Some(release) = find_release(plan, receipt, api)? {
        receipt.release_id = Some(release.id);
        confirmed(output, receipt, "create_draft")?;
        return Ok(release);
    }
    intent(output, receipt, "create_draft", None)?;
    let response = api.create_draft(plan, &draft_body(plan, &receipt.correlation));
    if let Ok(release) = &response {
        check_release(plan, receipt, release)?;
        ensure!(
            release.draft,
            DraftFailure::Conflict("create-draft response was already published".into())
        );
        receipt.release_id = Some(release.id);
        save(output, receipt)?;
    }
    for _ in 0..CREATE_LOOKUPS {
        check_repository(plan, api)?;
        check_tag(plan, api)?;
        if let Some(release) = find_release(plan, receipt, api)? {
            receipt.release_id = Some(release.id);
            confirmed(output, receipt, "create_draft")?;
            return Ok(release);
        }
    }
    let detail = response
        .err()
        .map(|error| format!(": {error:#}"))
        .unwrap_or_default();
    bail!(DraftFailure::NeedsDecision(format!(
        "create-draft outcome remains uncertain after bounded read-only lookup{detail}; no second POST was sent"
    )))
}

fn observed_assets(plan: &Plan, release: u64, api: &mut dyn Api) -> Result<BTreeMap<String, u64>> {
    let remote = api.assets(&plan.repository.full_name, release)?;
    ensure!(
        remote.len() <= plan.assets.len(),
        DraftFailure::Conflict("release has extra or duplicate assets".into())
    );
    let mut names = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut confirmed = BTreeMap::new();
    for actual in remote {
        ensure!(
            actual.id != 0 && names.insert(actual.name.clone()) && ids.insert(actual.id),
            DraftFailure::Conflict("release has invalid or duplicate asset identities".into())
        );
        let expected =
            plan.assets
                .iter()
                .find(|a| a.name == actual.name)
                .context(DraftFailure::Conflict(
                    "release contains an extra asset".into(),
                ))?;
        ensure!(
            actual.state == "uploaded",
            DraftFailure::Conflict(
                "release asset is not in uploaded state (including starter assets)".into()
            )
        );
        ensure!(
            actual.size == expected.size,
            DraftFailure::Conflict("release asset has different size".into())
        );
        match actual
            .digest
            .as_deref()
            .and_then(|digest| digest.strip_prefix("sha256:"))
            .filter(|digest| crate::cohort::plan::is_digest(digest))
        {
            Some(digest) => ensure!(
                digest == expected.sha256,
                DraftFailure::Conflict("release asset digest differs from the plan".into())
            ),
            None => {
                let bytes =
                    api.download_digest(&plan.repository.full_name, actual.id, expected.size)?;
                ensure!(
                    bytes.size == expected.size && bytes.sha256 == expected.sha256,
                    DraftFailure::Conflict("downloaded release asset differs from the plan".into())
                );
            }
        }
        confirmed.insert(actual.name, actual.id);
    }
    Ok(confirmed)
}

fn execute_remote(
    plan: &Plan,
    output: &Path,
    receipt: &mut Receipt,
    api: &mut dyn Api,
    read_only: bool,
    retry_create: bool,
) -> Result<()> {
    receipt.status = "running".into();
    receipt.error = None;
    event(receipt, "check", "started");
    save(output, receipt)?;
    check_repository(plan, api)?;
    api.commit_exists(&plan.repository.full_name, &plan.source_commit)?;
    // Detect every same-tag collision before even creating a missing tag.
    let existing = find_release(plan, receipt, api)?;
    if existing.is_none() && receipt.release_id.is_some() {
        bail!(DraftFailure::Conflict(
            "previously recorded release is missing from the exact tag lookup".into()
        ));
    }
    let published = existing.as_ref().is_some_and(|release| !release.draft);
    ensure_tag(plan, output, receipt, api, read_only || published)?;
    let release = match existing {
        Some(release) => {
            receipt.release_id = Some(release.id);
            if receipt
                .pending
                .as_ref()
                .is_some_and(|i| i.operation == "create_draft")
            {
                confirmed(output, receipt, "create_draft")?;
            } else {
                save(output, receipt)?;
            }
            release
        }
        None => {
            ensure!(!read_only, "no owned release exists for the planned tag");
            create_release(plan, output, receipt, api, retry_create)?
        }
    };
    let observed = guard_remote(plan, receipt, api, false)?;
    let no_writes = read_only || !release.draft || !observed.draft;
    receipt.confirmed_assets = observed_assets(plan, release.id, api)?;
    if receipt.pending.as_ref().is_some_and(|i| {
        i.operation == "upload"
            && i.asset
                .as_ref()
                .is_some_and(|name| receipt.confirmed_assets.contains_key(name))
    }) {
        confirmed(output, receipt, "upload")?;
    } else {
        save(output, receipt)?;
    }
    for asset in &plan.assets {
        if receipt.confirmed_assets.contains_key(&asset.name) {
            continue;
        }
        ensure!(
            !no_writes,
            "owned release is missing planned assets; read-only verification cannot upload them"
        );
        guard_remote(plan, receipt, api, true)?;
        // Recheck the asset set immediately before each write, including partial
        // uploads observed from a previous response loss.
        receipt.confirmed_assets = observed_assets(plan, release.id, api)?;
        if receipt.confirmed_assets.contains_key(&asset.name) {
            save(output, receipt)?;
            continue;
        }
        let path = safe_join(&safe_join(output, "snapshot")?, &asset.name)?;
        regular_file(&path)?;
        ensure!(
            fs::symlink_metadata(&path)?.len() == asset.size
                && crate::source::file_digest(&path)? == asset.sha256,
            "snapshot asset changed before upload"
        );
        guard_remote(plan, receipt, api, true)?;
        intent(output, receipt, "upload", Some(&asset.name))?;
        let response = api.upload(&plan.repository.full_name, release.id, asset, &path);
        guard_remote(plan, receipt, api, true)?;
        receipt.confirmed_assets = observed_assets(plan, release.id, api)?;
        if !receipt.confirmed_assets.contains_key(&asset.name) {
            if let Err(error) = response {
                return Err(error).context("upload outcome unconfirmed; resume will inspect the exact asset name before retry");
            }
            bail!(
                "uploaded asset is not observable; resume will inspect its exact name before retry"
            );
        }
        confirmed(output, receipt, "upload")?;
    }
    let release = guard_remote(plan, receipt, api, false)?;
    receipt.confirmed_assets = observed_assets(plan, release.id, api)?;
    ensure!(
        receipt.confirmed_assets.len() == plan.assets.len(),
        "release asset coverage is incomplete"
    );
    let final_release = guard_remote(plan, receipt, api, false)?;
    receipt.pending = None;
    receipt.error = None;
    receipt.status = if final_release.draft {
        "draft_complete"
    } else {
        "published_observed"
    }
    .into();
    event(receipt, "verify", "confirmed");
    Ok(())
}

/// Return a persisted snapshot. A running intent does not prove process liveness.
/// The content hash and receipt linkage are checked without source or tools.
pub fn status(output: &Path) -> Result<Receipt> {
    regular_directory(output)?;
    let plan_path = safe_join(output, "plan.json")?;
    let receipt_path = safe_join(output, "receipt.json")?;
    regular_file(&plan_path)?;
    regular_file(&receipt_path)?;
    let local_plan = plan::load(&plan_path)?;
    let receipt: Receipt = io::read_json(&receipt_path)?;
    validate_receipt(&local_plan, &receipt)?;
    Ok(receipt)
}

fn validate_receipt(plan: &Plan, receipt: &Receipt) -> Result<()> {
    ensure!(
        receipt.schema == 1 && receipt.plan_id == plan.id,
        "receipt schema or plan linkage differs"
    );
    ensure!(
        receipt.correlation.len() == 32
            && receipt
                .correlation
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid receipt correlation"
    );
    ensure!(
        matches!(
            receipt.status.as_str(),
            "running"
                | "draft_complete"
                | "published_observed"
                | "failed"
                | "conflict"
                | "needs-decision"
        ),
        "unknown draft receipt status"
    );
    ensure!(receipt.release_id != Some(0), "invalid release identity");
    ensure!(
        receipt.confirmed_assets.is_empty() || receipt.release_id.is_some(),
        "confirmed assets lack a release identity"
    );
    let mut ids = BTreeSet::new();
    for (name, id) in &receipt.confirmed_assets {
        ensure!(
            *id != 0 && ids.insert(id) && plan.assets.iter().any(|a| a.name == *name),
            "receipt contains invalid, duplicate or unplanned asset identity"
        );
    }
    let failed = matches!(
        receipt.status.as_str(),
        "failed" | "conflict" | "needs-decision"
    );
    ensure!(
        if failed {
            receipt.error.as_ref().is_some_and(|e| !e.is_empty())
        } else {
            receipt.error.is_none()
        },
        "receipt error differs from its status"
    );
    if let Some(pending) = &receipt.pending {
        match pending.operation.as_str() {
            "create_tag" | "create_draft" => ensure!(
                pending.asset.is_none(),
                "tag/draft intent must not name an asset"
            ),
            "upload" => ensure!(
                receipt.release_id.is_some()
                    && pending
                        .asset
                        .as_ref()
                        .is_some_and(|name| plan.assets.iter().any(|a| &a.name == name)),
                "upload intent lacks a planned asset or release"
            ),
            _ => bail!("unknown remote write intent"),
        }
    }
    if matches!(
        receipt.status.as_str(),
        "draft_complete" | "published_observed"
    ) {
        ensure!(
            receipt.release_id.is_some()
                && receipt.pending.is_none()
                && receipt.confirmed_assets.len() == plan.assets.len(),
            "completed receipt has incomplete release coverage or pending intent"
        );
    }
    ensure!(
        receipt.events.len() <= EVENT_LIMIT,
        "draft audit exceeds event limit"
    );
    let mut last = 0;
    for event in &receipt.events {
        ensure!(
            event.at_ms >= last
                && event.at_ms <= receipt.updated_at_ms
                && matches!(
                    event.operation.as_str(),
                    "check" | "create_tag" | "create_draft" | "upload" | "verify"
                )
                && matches!(
                    event.outcome.as_str(),
                    "started" | "intent" | "confirmed" | "failed"
                ),
            "invalid draft audit event"
        );
        last = event.at_ms;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Default)]
    enum DraftResponse {
        #[default]
        Normal,
        LostWithRelease,
        LostWithoutRelease,
        LostWithDuplicate,
    }

    struct Fake {
        repository: Repository,
        commit: String,
        tag: Option<String>,
        releases: Vec<Release>,
        assets: Vec<RemoteAsset>,
        bytes: BTreeMap<u64, Vec<u8>>,
        output: PathBuf,
        tag_posts: usize,
        draft_posts: usize,
        upload_posts: usize,
        download_calls: usize,
        draft_response: DraftResponse,
        lose_tag_response: bool,
        lose_upload_response: bool,
        absent_upload_once: bool,
        asset_queries: usize,
        mutate_tag_at_query: Option<usize>,
        publish_at_query: Option<usize>,
    }

    impl Fake {
        fn new(plan: &Plan, output: &Path) -> Self {
            Self {
                repository: plan.repository.clone(),
                commit: plan.source_commit.clone(),
                tag: Some(plan.source_commit.clone()),
                releases: Vec::new(),
                assets: Vec::new(),
                bytes: BTreeMap::new(),
                output: output.into(),
                tag_posts: 0,
                draft_posts: 0,
                upload_posts: 0,
                download_calls: 0,
                draft_response: DraftResponse::Normal,
                lose_tag_response: false,
                lose_upload_response: false,
                absent_upload_once: false,
                asset_queries: 0,
                mutate_tag_at_query: None,
                publish_at_query: None,
            }
        }
        fn require_intent(&self, operation: &str, asset: Option<&str>) {
            let saved: Receipt = io::read_json(&self.output.join("receipt.json")).unwrap();
            let intent = saved.pending.unwrap();
            assert_eq!(intent.operation, operation);
            assert_eq!(intent.asset.as_deref(), asset);
            assert_eq!(saved.events.last().unwrap().outcome, "intent");
        }
        fn add_owned_release(&mut self, plan: &Plan, receipt: &Receipt) {
            self.releases.push(Release {
                id: 91,
                tag_name: plan.tag.clone(),
                draft: true,
                prerelease: plan.prerelease,
                name: Some(plan.title.clone()),
                body: Some(draft_body(plan, &receipt.correlation)),
            });
        }
        fn write_count(&self) -> usize {
            self.tag_posts + self.draft_posts + self.upload_posts
        }
    }

    impl Api for Fake {
        fn repository(&mut self, _: &str) -> Result<Repository> {
            Ok(self.repository.clone())
        }
        fn commit_exists(&mut self, _: &str, commit: &str) -> Result<()> {
            ensure!(commit == self.commit, "missing commit");
            Ok(())
        }
        fn tag(&mut self, _: &str, _: &str) -> Result<Option<String>> {
            Ok(self.tag.clone())
        }
        fn create_tag(&mut self, _: &str, _: &str, commit: &str) -> Result<()> {
            self.require_intent("create_tag", None);
            self.tag_posts += 1;
            self.tag = Some(commit.into());
            ensure!(!self.lose_tag_response, "tag response lost");
            Ok(())
        }
        fn releases(&mut self, _: &str) -> Result<Vec<Release>> {
            Ok(self.releases.clone())
        }
        fn release(&mut self, _: &str, id: u64) -> Result<Release> {
            self.releases
                .iter()
                .find(|release| release.id == id)
                .cloned()
                .context("release missing")
        }
        fn create_draft(&mut self, plan: &Plan, body: &str) -> Result<Release> {
            self.require_intent("create_draft", None);
            self.draft_posts += 1;
            if matches!(self.draft_response, DraftResponse::LostWithoutRelease) {
                bail!("create response lost without an observable release");
            }
            let release = Release {
                id: 91,
                tag_name: plan.tag.clone(),
                draft: true,
                prerelease: plan.prerelease,
                name: Some(plan.title.clone()),
                body: Some(body.into()),
            };
            self.releases.push(release.clone());
            if matches!(self.draft_response, DraftResponse::LostWithDuplicate) {
                let mut duplicate = release.clone();
                duplicate.id = 92;
                self.releases.push(duplicate);
            }
            ensure!(
                matches!(self.draft_response, DraftResponse::Normal),
                "draft response lost"
            );
            Ok(release)
        }
        fn assets(&mut self, _: &str, _: u64) -> Result<Vec<RemoteAsset>> {
            self.asset_queries += 1;
            if self.mutate_tag_at_query == Some(self.asset_queries) {
                self.tag = Some("f".repeat(40));
            }
            if self.publish_at_query == Some(self.asset_queries) {
                self.releases[0].draft = false;
            }
            Ok(self.assets.clone())
        }
        fn upload(&mut self, _: &str, _: u64, asset: &Asset, path: &Path) -> Result<RemoteAsset> {
            self.require_intent("upload", Some(&asset.name));
            self.upload_posts += 1;
            if self.absent_upload_once {
                self.absent_upload_once = false;
                bail!("upload response lost without stored bytes");
            }
            let bytes = fs::read(path)?;
            assert_eq!(bytes.len() as u64, asset.size);
            assert_eq!(crate::source::digest(&bytes), asset.sha256);
            let remote = RemoteAsset {
                id: 100 + self.assets.len() as u64,
                name: asset.name.clone(),
                state: "uploaded".into(),
                size: asset.size,
                digest: Some(format!("sha256:{}", asset.sha256)),
            };
            self.assets.push(remote.clone());
            self.bytes.insert(remote.id, bytes);
            ensure!(!self.lose_upload_response, "upload response lost");
            Ok(remote)
        }
        fn download_digest(&mut self, _: &str, asset: u64, _: u64) -> Result<FileEntry> {
            self.download_calls += 1;
            let bytes = self.bytes.get(&asset).context("asset bytes missing")?;
            Ok(FileEntry {
                size: bytes.len() as u64,
                sha256: crate::source::digest(bytes),
            })
        }
    }

    fn fixture() -> (tempfile::TempDir, Plan, Receipt, Fake) {
        let output = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(output.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::create_dir(output.path().join("snapshot")).unwrap();
        let mut assets = Vec::new();
        for (name, bytes) in [
            ("SHA256SUMS", b"original sums\n".as_slice()),
            ("tool.tar.gz", b"original archive".as_slice()),
        ] {
            fs::write(output.path().join("snapshot").join(name), bytes).unwrap();
            assets.push(Asset {
                name: name.into(),
                size: bytes.len() as u64,
                sha256: crate::source::digest(bytes),
            });
        }
        let mut plan = Plan {
            schema: 1,
            id: String::new(),
            implementation: crate::model::IMPLEMENTATION.into(),
            engine_source_id: crate::cohort::model::ENGINE_SOURCE_ID.into(),
            collection_id: "b".repeat(64),
            policy_id: "c".repeat(64),
            source_commit: "d".repeat(40),
            repository: Repository {
                id: 7,
                full_name: "owner/repo".into(),
            },
            tag: "v1.0.0".into(),
            create_tag_if_missing: true,
            title: "Version 1".into(),
            notes: "Original notes\nwith trailing newline\n".into(),
            prerelease: true,
            assets,
        };
        plan.id = plan::id(&plan).unwrap();
        plan::shape(&plan).unwrap();
        let mut receipt = new_receipt(&plan).unwrap();
        io::write_json_atomic(&output.path().join("plan.json"), &plan).unwrap();
        save(output.path(), &mut receipt).unwrap();
        let api = Fake::new(&plan, output.path());
        (output, plan, receipt, api)
    }

    fn run(
        plan: &Plan,
        output: &Path,
        receipt: &mut Receipt,
        api: &mut Fake,
        read_only: bool,
        retry: bool,
    ) -> Result<Receipt> {
        let result = execute_remote(plan, output, receipt, api, read_only, retry);
        finish(output, receipt, result)
    }

    #[test]
    fn failure_receipts_use_typed_reasons_through_error_contexts() {
        for (failure, expected) in [
            (DraftFailure::Conflict("release changed".into()), "conflict"),
            (
                DraftFailure::NeedsDecision("outcome is uncertain".into()),
                "needs-decision",
            ),
        ] {
            let (output, _, mut receipt, _) = fixture();
            let error = anyhow::Error::new(failure).context("rechecking saved attempt");
            let message = format!("{error:#}");
            assert!(finish(output.path(), &mut receipt, Err(error)).is_err());
            let saved = status(output.path()).unwrap();
            assert_eq!(saved.status, expected);
            assert_eq!(saved.error.as_deref(), Some(message.as_str()));
            assert!(saved.pending.is_none());
            assert_eq!(saved.events.last().unwrap().outcome, "failed");
        }
    }

    #[test]
    fn untyped_errors_cannot_select_operator_status_by_their_wording() {
        for message in [
            "conflict: upstream transport error",
            "needs-decision: upstream transport error",
        ] {
            let (output, _, mut receipt, _) = fixture();
            assert!(finish(output.path(), &mut receipt, Err(anyhow::anyhow!(message))).is_err());
            let saved = status(output.path()).unwrap();
            assert_eq!(saved.status, "failed");
            assert_eq!(saved.error.as_deref(), Some(message));
        }
    }

    #[test]
    fn dropped_write_responses_reconcile_once_and_preserve_original_bytes() {
        let (output, plan, mut receipt, mut api) = fixture();
        api.tag = None;
        api.lose_tag_response = true;
        api.draft_response = DraftResponse::LostWithRelease;
        api.lose_upload_response = true;
        let complete = run(&plan, output.path(), &mut receipt, &mut api, false, false).unwrap();
        assert_eq!(complete.status, "draft_complete");
        assert!(complete.pending.is_none());
        assert_eq!(
            (api.tag_posts, api.draft_posts, api.upload_posts),
            (1, 1, 2)
        );
        assert_eq!(
            api.releases[0].body.as_deref(),
            Some(draft_body(&plan, &complete.correlation).as_str())
        );
        assert!(
            draft_body(&plan, &complete.correlation)
                .starts_with(&format!("{}\n\n<!--", plan.notes))
        );
        validate_snapshot(output.path(), &plan).unwrap();
        assert_eq!(status(output.path()).unwrap().status, "draft_complete");
        let before = api.write_count();
        run(&plan, output.path(), &mut receipt, &mut api, false, false).unwrap();
        assert_eq!(api.write_count(), before);
    }

    #[test]
    fn zero_create_outcomes_need_an_explicit_retry_and_never_auto_post_again() {
        let (output, plan, mut receipt, mut api) = fixture();
        api.draft_response = DraftResponse::LostWithoutRelease;
        assert!(run(&plan, output.path(), &mut receipt, &mut api, false, false).is_err());
        assert_eq!(receipt.status, "needs-decision");
        assert_eq!(receipt.pending.as_ref().unwrap().operation, "create_draft");
        assert_eq!(api.draft_posts, 1);
        api.draft_response = DraftResponse::Normal;
        for _ in 0..2 {
            assert!(run(&plan, output.path(), &mut receipt, &mut api, false, false).is_err());
            assert_eq!(receipt.status, "needs-decision");
            assert_eq!(api.draft_posts, 1);
        }
        run(&plan, output.path(), &mut receipt, &mut api, false, true).unwrap();
        assert_eq!(api.draft_posts, 2);
    }

    #[test]
    fn before_send_create_intent_is_equally_uncertain_and_one_match_is_adopted() {
        let (output, plan, mut receipt, mut api) = fixture();
        intent(output.path(), &mut receipt, "create_draft", None).unwrap();
        assert!(run(&plan, output.path(), &mut receipt, &mut api, false, false).is_err());
        assert_eq!(api.draft_posts, 0);
        api.add_owned_release(&plan, &receipt);
        run(&plan, output.path(), &mut receipt, &mut api, false, false).unwrap();
        assert_eq!(api.draft_posts, 0);
        assert_eq!(receipt.release_id, Some(91));
    }

    #[test]
    fn multiple_create_outcomes_conflict_without_asset_writes() {
        let (output, plan, mut receipt, mut api) = fixture();
        api.draft_response = DraftResponse::LostWithDuplicate;
        assert!(run(&plan, output.path(), &mut receipt, &mut api, false, false).is_err());
        assert_eq!(receipt.status, "conflict");
        assert_eq!(api.draft_posts, 1);
        assert_eq!(api.upload_posts, 0);
        assert_eq!(receipt.pending.as_ref().unwrap().operation, "create_draft");
    }

    #[test]
    fn foreign_same_tag_release_conflicts_before_missing_tag_creation() {
        for published in [false, true] {
            let (output, plan, mut receipt, mut api) = fixture();
            api.tag = None;
            api.add_owned_release(&plan, &receipt);
            api.releases[0].body = Some("foreign body".into());
            api.releases[0].draft = !published;
            assert!(run(&plan, output.path(), &mut receipt, &mut api, false, false).is_err());
            assert_eq!(receipt.status, "conflict");
            assert_eq!(api.write_count(), 0);
        }
    }

    #[test]
    fn known_release_id_never_adopts_a_different_matching_release() {
        let (output, plan, mut receipt, mut api) = fixture();
        api.add_owned_release(&plan, &receipt);
        receipt.release_id = Some(1234);
        assert!(run(&plan, output.path(), &mut receipt, &mut api, false, false).is_err());
        assert_eq!(receipt.status, "conflict");
        assert_eq!(receipt.release_id, Some(1234));
        assert_eq!(api.write_count(), 0);
    }

    #[test]
    fn absent_upload_is_retried_only_after_resume_observes_no_same_name_asset() {
        let (output, plan, mut receipt, mut api) = fixture();
        api.absent_upload_once = true;
        assert!(run(&plan, output.path(), &mut receipt, &mut api, false, false).is_err());
        assert_eq!(receipt.status, "failed");
        assert_eq!(receipt.pending.as_ref().unwrap().operation, "upload");
        assert_eq!(api.upload_posts, 1);
        run(&plan, output.path(), &mut receipt, &mut api, false, false).unwrap();
        assert_eq!(api.upload_posts, 3);
        assert_eq!(api.assets.len(), 2);
        assert_eq!(api.draft_posts, 1);
    }

    #[test]
    fn mutation_between_asset_query_and_upload_is_detected_without_uploading() {
        for publish in [false, true] {
            let (output, plan, mut receipt, mut api) = fixture();
            if publish {
                api.publish_at_query = Some(2);
            } else {
                api.mutate_tag_at_query = Some(2);
            }
            assert!(run(&plan, output.path(), &mut receipt, &mut api, false, false).is_err());
            assert_eq!(receipt.status, "conflict");
            assert_eq!(api.upload_posts, 0);
        }
    }

    #[test]
    fn unknown_digests_download_and_published_owned_releases_are_read_only() {
        let (output, plan, mut receipt, mut api) = fixture();
        run(&plan, output.path(), &mut receipt, &mut api, false, false).unwrap();
        let writes = api.write_count();
        api.releases[0].draft = false;
        for asset in &mut api.assets {
            asset.digest = None;
        }
        run(&plan, output.path(), &mut receipt, &mut api, false, false).unwrap();
        assert_eq!(receipt.status, "published_observed");
        assert!(api.download_calls >= 2);
        assert_eq!(api.write_count(), writes);
        run(&plan, output.path(), &mut receipt, &mut api, true, false).unwrap();
        assert_eq!(api.write_count(), writes);
        api.assets.pop();
        assert!(run(&plan, output.path(), &mut receipt, &mut api, false, false).is_err());
        assert_eq!(api.write_count(), writes);
    }

    #[test]
    fn unexpected_remote_assets_never_trigger_delete_replace_or_upload() {
        for mutation in 0..6 {
            let (output, plan, mut receipt, mut api) = fixture();
            run(&plan, output.path(), &mut receipt, &mut api, false, false).unwrap();
            let before = api.write_count();
            match mutation {
                0 => api.assets[0].size += 1,
                1 => api.assets[0].digest = Some(format!("sha256:{}", "0".repeat(64))),
                2 => api.assets[0].state = "starter".into(),
                3 => api.assets[0].name = "unexpected.txt".into(),
                4 => api.assets.push(api.assets[0].clone()),
                _ => {
                    api.assets[0].digest = None;
                    api.bytes.get_mut(&api.assets[0].id).unwrap()[0] ^= 1;
                }
            }
            assert!(
                run(&plan, output.path(), &mut receipt, &mut api, false, false).is_err(),
                "mutation {mutation}"
            );
            assert_eq!(receipt.status, "conflict");
            assert_eq!(api.write_count(), before);
        }
    }

    #[test]
    fn snapshot_must_be_exact_and_regular_and_writer_lock_is_exclusive() {
        let (output, plan, _, _) = fixture();
        validate_snapshot(output.path(), &plan).unwrap();
        let first = writer_lock(output.path()).unwrap();
        assert!(writer_lock(output.path()).is_err());
        drop(first);
        writer_lock(output.path()).unwrap();
        fs::write(output.path().join("snapshot/extra"), b"extra").unwrap();
        assert!(validate_snapshot(output.path(), &plan).is_err());
        fs::remove_file(output.path().join("snapshot/extra")).unwrap();
        fs::write(output.path().join("snapshot/tool.tar.gz"), b"changed").unwrap();
        assert!(validate_snapshot(output.path(), &plan).is_err());
    }

    #[test]
    fn source_free_status_validates_plan_hash_linkage_and_pending_state() {
        let (output, mut plan, mut receipt, _) = fixture();
        assert_eq!(status(output.path()).unwrap().status, "running");
        receipt.pending = Some(Intent {
            operation: "upload".into(),
            asset: Some("tool.tar.gz".into()),
        });
        save(output.path(), &mut receipt).unwrap();
        assert!(status(output.path()).is_err());
        receipt.release_id = Some(91);
        save(output.path(), &mut receipt).unwrap();
        status(output.path()).unwrap();
        plan.title = "changed after planning".into();
        io::write_json_atomic(&output.path().join("plan.json"), &plan).unwrap();
        assert!(status(output.path()).is_err());
    }

    #[test]
    fn interrupted_snapshot_preparation_recovers_only_before_any_remote_intent() {
        let (output, plan, mut receipt, _) = fixture();
        let collection = tempfile::tempdir().unwrap();
        fs::create_dir(collection.path().join("verified")).unwrap();
        for asset in &plan.assets {
            fs::copy(
                output.path().join("snapshot").join(&asset.name),
                collection.path().join("verified").join(&asset.name),
            )
            .unwrap();
        }
        fs::remove_dir_all(output.path().join("snapshot")).unwrap();
        let archive = collection.path().join("verified/tool.tar.gz");
        let original = fs::read(&archive).unwrap();
        fs::remove_file(&archive).unwrap();
        assert!(snapshot(collection.path(), output.path(), &plan).is_err());
        assert!(!output.path().join("snapshot").exists());
        let partial: Vec<_> = fs::read_dir(output.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(".snapshot-")
            })
            .collect();
        assert_eq!(partial.len(), 1);
        assert!(partial[0].join("SHA256SUMS").exists());
        fs::write(&archive, original).unwrap();
        ensure_snapshot(collection.path(), output.path(), &plan, &receipt).unwrap();
        validate_snapshot(output.path(), &plan).unwrap();
        assert!(partial[0].exists());
        fs::remove_dir_all(output.path().join("snapshot")).unwrap();
        event(&mut receipt, "create_tag", "intent");
        assert!(ensure_snapshot(collection.path(), output.path(), &plan, &receipt).is_err());
        assert!(!output.path().join("snapshot").exists());
    }

    #[test]
    fn events_are_bounded_and_remain_a_valid_chronological_snapshot() {
        let (_, plan, mut receipt, _) = fixture();
        for _ in 0..EVENT_LIMIT + 2 {
            event(&mut receipt, "check", "started");
        }
        assert_eq!(receipt.events.len(), EVENT_LIMIT);
        validate_receipt(&plan, &receipt).unwrap();
    }
}
