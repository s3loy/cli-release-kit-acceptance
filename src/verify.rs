use crate::{
    archive,
    config::safe_join,
    execute::{binary_name, checksum_text},
    model::{IMPLEMENTATION, Plan, Receipt, SCHEMA},
    source::{digest, file_digest},
};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub fn verify(root: &Path, output: &Path) -> Result<Receipt> {
    let output = output.canonicalize()?;
    let plan: Plan = read_json(&safe_join(&output, "plan.json")?)?;
    let receipt: Receipt = read_json(&safe_join(&output, "receipt.json")?)?;
    crate::plan::validate_saved(root, &plan)?;
    ensure!(
        receipt.schema == SCHEMA && receipt.implementation == IMPLEMENTATION,
        "unsupported receipt schema or implementation"
    );
    ensure!(
        receipt.plan_id == plan.id,
        "receipt references a different plan"
    );
    ensure!(
        receipt.status == "verified" && receipt.error.is_none() && !receipt.publication_ready,
        "receipt is not a successful local verified result"
    );
    ensure!(
        receipt.toolchain.len() == 3
            && ["cargo", "rustc", "engine_sha256"].iter().all(|key| receipt
                .toolchain
                .get(*key)
                .is_some_and(|value| !value.is_empty())),
        "missing execution tool identities"
    );
    let directory = safe_join(&output, "verified")?;
    ensure!(directory.is_dir(), "verified artifact selection is absent");
    check_artifacts(root, &plan, &receipt, &directory)?;
    let checksums = fs::read_to_string(safe_join(&directory, "SHA256SUMS")?)?;
    ensure!(
        checksums == checksum_text(&receipt.artifacts),
        "checksum coverage, order or bytes differ"
    );
    Ok(receipt)
}

pub(crate) fn check_artifacts(
    root: &Path,
    plan: &Plan,
    receipt: &Receipt,
    directory: &Path,
) -> Result<()> {
    let expected: BTreeSet<_> = plan
        .outputs
        .iter()
        .map(|output| output.filename.as_str())
        .collect();
    ensure!(
        expected.len() == plan.outputs.len(),
        "duplicate planned output"
    );
    let actual: BTreeSet<_> = receipt
        .artifacts
        .iter()
        .map(|artifact| artifact.filename.as_str())
        .collect();
    ensure!(
        actual.len() == receipt.artifacts.len() && actual == expected,
        "receipt artifact set differs from plan"
    );
    let mut directory_files = BTreeSet::new();
    for entry in fs::read_dir(directory)? {
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
    directory_files.remove("SHA256SUMS");
    ensure!(
        directory_files
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == expected,
        "artifact directory has missing or extra files"
    );
    for artifact in &receipt.artifacts {
        let path = safe_join(directory, &artifact.filename)?;
        ensure!(
            file_digest(&path)? == artifact.sha256,
            "archive digest changed: {}",
            artifact.filename
        );
        let content = archive::inspect(&path)?;
        ensure!(
            archive::members(&content) == artifact.members,
            "archive member digest, set or permissions differ from receipt"
        );
        let output = plan
            .outputs
            .iter()
            .find(|output| output.filename == artifact.filename)
            .context("unknown artifact")?;
        let product = plan
            .products
            .iter()
            .find(|product| product.package == output.product)
            .context("unknown product")?;
        let mut names = BTreeSet::new();
        for binary in &product.binaries {
            let name = binary_name(binary, &output.target);
            ensure!(
                content.get(&name).is_some_and(|item| item.executable),
                "archive binary missing or not executable: {name}"
            );
            names.insert(name);
        }
        for asset in &product.assets {
            ensure!(
                names.insert(asset.path.clone()),
                "duplicate member in independent content contract"
            );
            let item = content
                .get(&asset.path)
                .context("declared asset is absent")?;
            ensure!(
                !item.executable,
                "resource unexpectedly executable: {}",
                asset.path
            );
            let generated = plan
                .config
                .generated
                .iter()
                .any(|directory| asset.source.starts_with(&format!("{directory}/")));
            if !generated {
                let source = safe_join(root, &asset.source)?;
                ensure!(
                    digest(&item.bytes) == file_digest(&source)?,
                    "archive resource bytes differ from tracked source: {}",
                    asset.path
                );
            }
        }
        ensure!(
            names == content.keys().cloned().collect(),
            "archive has extra or missing contract members"
        );
    }
    Ok(())
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    crate::cohort::io::read_json(path)
}
