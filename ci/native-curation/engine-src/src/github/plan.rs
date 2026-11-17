use super::model::*;
use crate::{
    cohort::{self, io, model::Policy},
    source,
};
use anyhow::{Result, ensure};
use std::{fs, path::Path};

pub struct Options {
    pub repository: String,
    pub tag: String,
    pub create_tag_if_missing: bool,
    pub title: String,
    pub notes: String,
    pub prerelease: bool,
}

pub fn repository_name(name: &str) -> Result<()> {
    let parts: Vec<_> = name.split('/').collect();
    ensure!(
        parts.len() == 2
            && parts.iter().all(|p| !p.is_empty()
                && *p != "."
                && *p != ".."
                && p.len() <= 100
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))),
        "repository must be an explicit GitHub owner/repo name"
    );
    Ok(())
}

pub fn tag_name(tag: &str) -> Result<()> {
    ensure!(
        !tag.is_empty()
            && tag.len() <= 255
            && tag != "@"
            && !tag.starts_with('/')
            && !tag.ends_with('/')
            && !tag.ends_with('.')
            && !tag.contains("..")
            && !tag.contains("@{")
            && tag
                .bytes()
                .all(|b| b > 32 && b != 127 && !b"~^:?*[\\".contains(&b))
            && tag
                .split('/')
                .all(|s| !s.is_empty() && !s.starts_with('.') && !s.ends_with(".lock")),
        "invalid Git tag name"
    );
    Ok(())
}

pub fn id(plan: &Plan) -> Result<String> {
    let mut copy = plan.clone();
    copy.id.clear();
    let mut bytes = b"cli-release-kit/github-draft-plan/v1\0".to_vec();
    bytes.extend(serde_json::to_vec(&copy)?);
    Ok(source::digest(&bytes))
}

pub fn shape(plan: &Plan) -> Result<()> {
    ensure!(plan.schema == 1, "unsupported GitHub draft plan schema");
    ensure!(
        plan.implementation == crate::model::IMPLEMENTATION,
        "unsupported draft implementation"
    );
    for value in [
        &plan.id,
        &plan.engine_source_id,
        &plan.collection_id,
        &plan.policy_id,
    ] {
        ensure!(
            cohort::plan::is_digest(value),
            "invalid draft content identity"
        );
    }
    ensure!(plan.id == id(plan)?, "draft plan content identity mismatch");
    ensure!(
        plan.source_commit.len() == 40
            && plan
                .source_commit
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid source commit"
    );
    repository_name(&plan.repository.full_name)?;
    ensure!(plan.repository.id != 0, "invalid repository identity");
    tag_name(&plan.tag)?;
    ensure!(
        !plan.title.trim().is_empty()
            && plan.title.len() <= 256
            && !plan.title.chars().any(char::is_control),
        "invalid draft title"
    );
    ensure!(
        plan.notes.len() <= 1024 * 1024 && !plan.notes.contains("<!-- cli-release-kit"),
        "notes exceed limit or contain a reserved draft marker"
    );
    ensure!(
        !plan.assets.is_empty() && plan.assets.len() <= 10_000,
        "invalid draft asset count"
    );
    let mut previous: Option<&str> = None;
    let mut case_names = std::collections::BTreeSet::new();
    let mut total = 0u64;
    for asset in &plan.assets {
        ensure!(
            !asset.name.is_empty()
                && asset.name.len() <= 255
                && asset.name.as_bytes()[0].is_ascii_alphanumeric()
                && !asset.name.ends_with('.')
                && asset
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "asset filename is not supported by the GitHub draft adapter: {}",
            asset.name
        );
        ensure!(
            previous.is_none_or(|p| p < asset.name.as_str())
                && case_names.insert(asset.name.to_ascii_lowercase()),
            "draft assets must be unique and canonically sorted"
        );
        ensure!(
            cohort::plan::is_digest(&asset.sha256) && asset.size <= io::FILE_LIMIT,
            "invalid draft asset digest or size"
        );
        total = total
            .checked_add(asset.size)
            .ok_or_else(|| anyhow::anyhow!("asset size overflow"))?;
        ensure!(
            total <= io::BUNDLE_LIMIT,
            "draft assets exceed total size limit"
        );
        previous = Some(&asset.name);
    }
    ensure!(
        plan.assets.iter().any(|a| a.name == "SHA256SUMS"),
        "draft lacks original SHA256SUMS"
    );
    Ok(())
}

fn assets(collection: &Path, mut names: Vec<String>) -> Result<Vec<Asset>> {
    names.push("SHA256SUMS".into());
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let path = crate::config::safe_join(&collection.join("verified"), &name)?;
            Ok(Asset {
                name,
                size: fs::symlink_metadata(&path)?.len(),
                sha256: source::file_digest(&path)?,
            })
        })
        .collect()
}

pub(crate) struct CollectionView {
    pub id: String,
    pub policy_id: String,
    pub source_commit: String,
    pub assets: Vec<Asset>,
}

/// Both producer protocols must prove their exact package set before publishing.
pub(crate) fn verified_collection(
    root: &Path,
    collection: &Path,
    policy: &Policy,
) -> Result<CollectionView> {
    let value: serde_json::Value = io::read_json(&collection.join("collection.json"))?;
    match value.get("schema").and_then(serde_json::Value::as_u64) {
        Some(3) => {
            let verified = cohort::bundle::verify_collection(root, collection, policy)?;
            let source: cohort::model::Plan = io::read_json(&collection.join("plan.json"))?;
            Ok(CollectionView {
                id: verified.id,
                policy_id: verified.policy_id,
                source_commit: source.source.commit,
                assets: assets(
                    collection,
                    verified
                        .selections
                        .iter()
                        .map(|s| s.filename.clone())
                        .collect(),
                )?,
            })
        }
        Some(4) => {
            let verified = crate::delivery::bundle::verify_collection(root, collection, policy)?;
            let source: crate::delivery::model::Plan =
                io::read_json(&collection.join("plan.json"))?;
            Ok(CollectionView {
                id: verified.id,
                policy_id: verified.policy_id,
                source_commit: source.source.commit,
                assets: assets(
                    collection,
                    verified
                        .selections
                        .iter()
                        .map(|s| s.filename.clone())
                        .collect(),
                )?,
            })
        }
        _ => anyhow::bail!("unsupported verified collection protocol"),
    }
}

pub fn create(
    root: &Path,
    collection: &Path,
    policy: &Policy,
    options: Options,
    api: &mut dyn Api,
) -> Result<Plan> {
    repository_name(&options.repository)?;
    tag_name(&options.tag)?;
    let verified = verified_collection(root, collection, policy)?;
    create_verified(verified, options, api)
}

pub fn create_v5(
    root: &Path,
    collection: &Path,
    policy: &crate::v5::proof::Policy,
    options: Options,
    api: &mut dyn Api,
) -> Result<Plan> {
    repository_name(&options.repository)?;
    tag_name(&options.tag)?;
    let verified = verified_collection_v5(root, collection, policy)?;
    create_verified(verified, options, api)
}

fn verified_collection_v5(
    root: &Path,
    collection: &Path,
    policy: &crate::v5::proof::Policy,
) -> Result<CollectionView> {
    let verified = crate::v5::bundle::verify_collection(root, collection, policy)?;
    let source: crate::v5::model::Plan = io::read_json(&collection.join("plan.json"))?;
    Ok(CollectionView {
        id: verified.id,
        policy_id: verified.policy_id,
        source_commit: source.source.commit,
        assets: assets(
            collection,
            verified
                .selections
                .iter()
                .map(|s| s.filename.clone())
                .collect(),
        )?,
    })
}

fn create_verified(verified: CollectionView, options: Options, api: &mut dyn Api) -> Result<Plan> {
    let repository = api.repository(&options.repository)?;
    ensure!(
        repository
            .full_name
            .eq_ignore_ascii_case(&options.repository),
        "repository was renamed or transferred"
    );
    let mut plan = Plan {
        schema: 1,
        id: String::new(),
        implementation: crate::model::IMPLEMENTATION.into(),
        engine_source_id: cohort::model::ENGINE_SOURCE_ID.into(),
        collection_id: verified.id,
        policy_id: verified.policy_id,
        source_commit: verified.source_commit,
        repository,
        tag: options.tag,
        create_tag_if_missing: options.create_tag_if_missing,
        title: options.title,
        notes: options.notes,
        prerelease: options.prerelease,
        assets: verified.assets,
    };
    plan.id = id(&plan)?;
    shape(&plan)?;
    api.commit_exists(&plan.repository.full_name, &plan.source_commit)?;
    match api.tag(&plan.repository.full_name, &plan.tag)? {
        Some(commit) => ensure!(
            commit == plan.source_commit,
            "remote tag points to another commit"
        ),
        None => ensure!(
            plan.create_tag_if_missing,
            "remote tag is missing; explicitly opt in with --create-tag-if-missing"
        ),
    }
    Ok(plan)
}

pub fn load(path: &Path) -> Result<Plan> {
    let plan = io::read_json(path)?;
    shape(&plan)?;
    Ok(plan)
}

pub fn validate(
    root: &Path,
    collection: &Path,
    policy: &Policy,
    plan: &Plan,
    execute: bool,
) -> Result<()> {
    validate_execution(plan, execute)?;
    let verified = verified_collection(root, collection, policy)?;
    validate_verified(plan, verified)
}

pub fn validate_v5(
    root: &Path,
    collection: &Path,
    policy: &crate::v5::proof::Policy,
    plan: &Plan,
    execute: bool,
) -> Result<()> {
    validate_execution(plan, execute)?;
    let verified = verified_collection_v5(root, collection, policy)?;
    validate_verified(plan, verified)
}

fn validate_execution(plan: &Plan, execute: bool) -> Result<()> {
    shape(plan)?;
    if execute {
        ensure!(
            plan.engine_source_id == cohort::model::ENGINE_SOURCE_ID,
            "draft execution requires the engine source identity approved by its plan"
        );
    }
    Ok(())
}

fn validate_verified(plan: &Plan, verified: CollectionView) -> Result<()> {
    ensure!(
        verified.id == plan.collection_id
            && verified.policy_id == plan.policy_id
            && verified.source_commit == plan.source_commit,
        "draft plan belongs to a different collection, policy or source"
    );
    ensure!(
        verified.assets == plan.assets,
        "draft asset manifest differs from verified collection"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_ambiguous_remote_paths_and_git_refs() {
        for name in [
            "owner",
            "../repo",
            "https://github.com/o/r",
            "o/r?x=y",
            "o/r/more",
        ] {
            assert!(repository_name(name).is_err(), "{name}");
        }
        for tag in [
            "", "@", "v..1", "a.lock", "a//b", "a/.b", "a@{b", "a\\b", "a\nb", "v1.",
        ] {
            assert!(tag_name(tag).is_err(), "{tag}");
        }
        for tag in ["v1.0.0", "release/v2", "v1.0.0+metadata"] {
            tag_name(tag).unwrap();
        }
    }
}
