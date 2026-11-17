//! Protocol 4 record identities and scoped trust authorization.
use super::{
    model::Plan,
    run::{Assignment, PackageRecord, PayloadRecord},
};
use crate::cohort::{crypto, model::Policy};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use serde::Serialize;

pub fn content_id<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    crypto::content_id(domain, value)
}
pub fn payload_id(value: &PayloadRecord) -> Result<String> {
    let mut copy = value.clone();
    copy.id.clear();
    copy.proof = None;
    content_id(b"cli-release-kit/delivery-payload/v1\0", &copy)
}
pub fn package_id(value: &PackageRecord) -> Result<String> {
    let mut copy = value.clone();
    copy.id.clear();
    copy.proof = None;
    content_id(b"cli-release-kit/delivery-package/v1\0", &copy)
}
pub fn seal_payload(value: &mut PayloadRecord, key: Option<&SigningKey>) -> Result<()> {
    value.id = payload_id(value)?;
    value.proof = key.map(|key| {
        crypto::seal_record(
            &value.id,
            b"cli-release-kit/trusted-delivery-payload/v1\0",
            key,
        )
    });
    Ok(())
}
pub fn seal_package(value: &mut PackageRecord, key: Option<&SigningKey>) -> Result<()> {
    value.id = package_id(value)?;
    value.proof = key.map(|key| {
        crypto::seal_record(
            &value.id,
            b"cli-release-kit/trusted-delivery-package/v1\0",
            key,
        )
    });
    Ok(())
}
pub fn verify_payload(value: &PayloadRecord, key: Option<&str>) -> Result<()> {
    ensure!(
        value.id == payload_id(value)?,
        "payload record identity mismatch"
    );
    crypto::verify_record(
        &value.id,
        b"cli-release-kit/trusted-delivery-payload/v1\0",
        value.proof.as_ref(),
        key,
    )
}
pub fn verify_package(value: &PackageRecord, key: Option<&str>) -> Result<()> {
    ensure!(
        value.id == package_id(value)?,
        "package record identity mismatch"
    );
    crypto::verify_record(
        &value.id,
        b"cli-release-kit/trusted-delivery-package/v1\0",
        value.proof.as_ref(),
        key,
    )
}
pub fn authorize(
    plan: &Plan,
    assignment: &Assignment,
    payload: &PayloadRecord,
    package: &PackageRecord,
    policy: &Policy,
) -> Result<()> {
    crypto::validate_policy(policy)?;
    let expected = assignment
        .trusted_key
        .as_deref()
        .context("unsigned candidate requires a fresh trusted rebuild")?;
    verify_payload(payload, Some(expected))?;
    verify_package(package, Some(expected))?;
    ensure!(
        payload.status == "complete" && package.status == "complete" && !assignment.skip_runtime,
        "build-only evidence cannot enter verified collection"
    );
    let spec = plan
        .packages
        .get(package.package)
        .context("unknown package")?;
    ensure!(
        spec.build == payload.build
            && package.payload_id == payload.id
            && payload.assignment_id == assignment.id
            && package.assignment_id == assignment.id
            && payload.plan_id == plan.id
            && package.plan_id == plan.id
            && payload.engine_source_id == plan.engine_source_id
            && package.engine_source_id == plan.engine_source_id,
        "trusted records bind another build, plan, assignment or engine"
    );
    let build = &plan.builds[spec.build];
    let product = &plan.config.products[build.product];
    let target = plan.config.targets[build.target].key();
    ensure!(
        policy
            .trusted_keys
            .iter()
            .any(|key| key.public_key == expected
                && (key.products.is_empty() || key.products.contains(&product.id))
                && (key.targets.is_empty() || key.targets.contains(&target))
                && key
                    .source_commit
                    .as_ref()
                    .is_none_or(|v| v == &plan.source.commit)
                && key
                    .engine_source_id
                    .as_ref()
                    .is_none_or(|v| v == &plan.engine_source_id)),
        "trusted rebuild key unknown, revoked or outside product, target, source or engine scope"
    );
    Ok(())
}
