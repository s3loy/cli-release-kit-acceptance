//! Protocol 5 record identities and scoped trust authorization.
use super::{
    model::{Plan, RuntimeConstraint},
    run::{Assignment, PackageRecord, PayloadRecord},
};
use crate::cohort::{crypto, model::TrustedKey};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use serde::Serialize;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Policy {
    pub schema: u32,
    pub trusted_keys: Vec<TrustedKey>,
    pub allowed_runtime_constraints: Vec<RuntimeConstraint>,
}
pub fn validate_policy(policy: &Policy) -> Result<()> {
    ensure!(
        policy.schema == 5,
        "protocol 5 requires a schema 5 trust policy"
    );
    crypto::validate_policy(&crate::cohort::model::Policy {
        schema: 1,
        trusted_keys: policy.trusted_keys.clone(),
    })?;
    ensure!(
        !policy.allowed_runtime_constraints.is_empty(),
        "policy must explicitly allow runtime constraints"
    );
    let ids = policy
        .allowed_runtime_constraints
        .iter()
        .map(super::runtime::constraint_id)
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    ensure!(
        ids.len() == policy.allowed_runtime_constraints.len(),
        "duplicate allowed runtime constraint"
    );
    for constraint in &policy.allowed_runtime_constraints {
        match constraint.mode {
            super::model::RuntimeMode::Native => ensure!(
                constraint.emulator.is_none()
                    && constraint.cpu.is_none()
                    && constraint.emulator_sha256.is_none()
                    && constraint.rootfs_sha256.is_none(),
                "native policy constraint has emulation fields"
            ),
            super::model::RuntimeMode::Emulated => ensure!(
                constraint.emulator.is_some()
                    && constraint.cpu.as_ref().is_some_and(|v| !v.is_empty())
                    && constraint
                        .emulator_sha256
                        .as_ref()
                        .is_some_and(|v| super::run::is_digest(v))
                    && constraint
                        .rootfs_sha256
                        .as_ref()
                        .is_none_or(|v| super::run::is_digest(v)),
                "incomplete emulated policy constraint"
            ),
        }
    }
    Ok(())
}
pub fn policy_id(policy: &Policy) -> Result<String> {
    validate_policy(policy)?;
    content_id(b"cli-release-kit/v5-trust-policy/v1\0", policy)
}

pub fn content_id<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    crypto::content_id(domain, value)
}
pub fn payload_id(value: &PayloadRecord) -> Result<String> {
    let mut copy = value.clone();
    copy.id.clear();
    copy.proof = None;
    content_id(b"cli-release-kit/v5-payload/v1\0", &copy)
}
pub fn package_id(value: &PackageRecord) -> Result<String> {
    let mut copy = value.clone();
    copy.id.clear();
    copy.proof = None;
    content_id(b"cli-release-kit/v5-package/v1\0", &copy)
}
pub fn seal_payload(value: &mut PayloadRecord, key: Option<&SigningKey>) -> Result<()> {
    value.id = payload_id(value)?;
    value.proof = key
        .map(|key| crypto::seal_record(&value.id, b"cli-release-kit/trusted-v5-payload/v1\0", key));
    Ok(())
}
pub fn seal_package(value: &mut PackageRecord, key: Option<&SigningKey>) -> Result<()> {
    value.id = package_id(value)?;
    value.proof = key
        .map(|key| crypto::seal_record(&value.id, b"cli-release-kit/trusted-v5-package/v1\0", key));
    Ok(())
}
pub fn verify_payload(value: &PayloadRecord, key: Option<&str>) -> Result<()> {
    ensure!(
        value.id == payload_id(value)?,
        "payload record identity mismatch"
    );
    crypto::verify_record(
        &value.id,
        b"cli-release-kit/trusted-v5-payload/v1\0",
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
        b"cli-release-kit/trusted-v5-package/v1\0",
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
    validate_policy(policy)?;
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
    let target = plan.targets[build.target].key();
    let constraint = &plan.config.targets[build.target].runtime;
    ensure!(
        policy.allowed_runtime_constraints.contains(constraint),
        "runtime constraint is outside explicitly allowed policy"
    );
    ensure!(
        !payload.runtime.is_empty(),
        "complete payload lacks runtime evidence"
    );
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
