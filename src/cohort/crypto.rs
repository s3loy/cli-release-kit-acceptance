use super::{io, model::*};
use crate::source;
use anyhow::{Context, Result, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn decode<const N: usize>(text: &str) -> Result<[u8; N]> {
    ensure!(
        text.len() == N * 2
            && text
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid canonical key/signature encoding"
    );
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}
pub(crate) fn content_id<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    let mut bytes = domain.to_vec();
    bytes.extend(serde_json::to_vec(value)?);
    Ok(source::digest(&bytes))
}
pub(crate) fn seal_record(id: &str, domain: &[u8], key: &SigningKey) -> Proof {
    let mut message = domain.to_vec();
    message.extend(id.as_bytes());
    Proof {
        public_key: public_key(key),
        signature: hex(&key.sign(&message).to_bytes()),
    }
}
pub(crate) fn verify_record(
    id: &str,
    domain: &[u8],
    proof: Option<&Proof>,
    expected: Option<&str>,
) -> Result<()> {
    match (proof, expected) {
        (None, None) => Ok(()),
        (Some(proof), Some(expected)) => {
            ensure!(
                proof.public_key == expected,
                "record proof key differs from assignment"
            );
            let key = VerifyingKey::from_bytes(&decode(&proof.public_key)?)?;
            let signature = Signature::from_bytes(&decode(&proof.signature)?);
            let mut message = domain.to_vec();
            message.extend(id.as_bytes());
            key.verify_strict(&message, &signature)
                .context("invalid delivery record signature")
        }
        _ => anyhow::bail!("record signature presence differs from assignment"),
    }
}
pub fn public_key(key: &SigningKey) -> String {
    hex(&key.verifying_key().to_bytes())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Private {
    schema: u32,
    secret_key: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Public {
    schema: u32,
    pub public_key: String,
}
pub fn keygen(private: &Path, public: &Path) -> Result<String> {
    ensure!(
        !private.exists() && !public.exists() && private != public,
        "key output already exists"
    );
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("OS randomness unavailable: {e}"))?;
    let key = SigningKey::from_bytes(&seed);
    let public_key = public_key(&key);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(private)?;
    file.write_all(&serde_json::to_vec_pretty(&Private {
        schema: 1,
        secret_key: hex(&seed),
    })?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    // The public file contains no secret material and is safe to register in policy.
    let mut public_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(public)?;
    public_file.write_all(&serde_json::to_vec_pretty(&Public {
        schema: 1,
        public_key: public_key.clone(),
    })?)?;
    public_file.write_all(b"\n")?;
    public_file.sync_all()?;
    Ok(public_key)
}
pub fn load_key(path: &Path) -> Result<SigningKey> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "private key must be a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            meta.permissions().mode() & 0o077 == 0,
            "private key permissions must exclude group and other users"
        );
    }
    let p: Private = io::read_json(path)?;
    ensure!(p.schema == 1, "unsupported key schema");
    Ok(SigningKey::from_bytes(&decode(&p.secret_key)?))
}
pub fn unit_id(record: &UnitRecord) -> Result<String> {
    let mut v = record.clone();
    v.id.clear();
    v.proof = None;
    let mut b = b"cli-release-kit/unit-record/v1\0".to_vec();
    b.extend(serde_json::to_vec(&v)?);
    Ok(source::digest(&b))
}
pub fn seal_unit(record: &mut UnitRecord, key: &SigningKey) -> Result<()> {
    record.id = unit_id(record)?;
    let mut message = b"cli-release-kit/trusted-unit/v1\0".to_vec();
    message.extend(record.id.as_bytes());
    record.proof = Some(Proof {
        public_key: public_key(key),
        signature: hex(&key.sign(&message).to_bytes()),
    });
    Ok(())
}
pub fn verify_unit_proof(record: &UnitRecord) -> Result<()> {
    ensure!(
        record.id == unit_id(record)?,
        "unit record identity mismatch"
    );
    let proof = record
        .proof
        .as_ref()
        .context("unit is an unsigned candidate; trusted rebuild required")?;
    let key = VerifyingKey::from_bytes(&decode(&proof.public_key)?)?;
    let sig = Signature::from_bytes(&decode(&proof.signature)?);
    let mut message = b"cli-release-kit/trusted-unit/v1\0".to_vec();
    message.extend(record.id.as_bytes());
    key.verify_strict(&message, &sig)
        .context("invalid trusted unit signature")
}
pub fn policy_id(policy: &Policy) -> Result<String> {
    let mut b = b"cli-release-kit/trust-policy/v1\0".to_vec();
    b.extend(serde_json::to_vec(policy)?);
    Ok(source::digest(&b))
}
pub fn load_policy(path: &Path) -> Result<Policy> {
    let value: Policy = toml::from_str(&fs::read_to_string(path)?)?;
    validate_policy(&value)?;
    Ok(value)
}
pub fn validate_policy(p: &Policy) -> Result<()> {
    ensure!(
        p.schema == 1 && !p.trusted_keys.is_empty(),
        "policy must register trusted rebuild keys"
    );
    let mut keys = std::collections::BTreeSet::new();
    for key in &p.trusted_keys {
        VerifyingKey::from_bytes(&decode(&key.public_key)?)?;
        ensure!(keys.insert(&key.public_key), "duplicate policy key");
    }
    Ok(())
}
pub fn authorize(
    plan: &Plan,
    assignment: &Assignment,
    record: &UnitRecord,
    policy: &Policy,
) -> Result<()> {
    validate_policy(policy)?;
    verify_unit_proof(record)?;
    ensure!(
        record.status == "complete",
        "build-only unit cannot enter verified collection"
    );
    let proof = record.proof.as_ref().context("missing proof")?;
    ensure!(
        assignment.trusted_key.as_ref() == Some(&proof.public_key),
        "proof key differs from assignment"
    );
    ensure!(
        record.plan_id == plan.id
            && record.engine_source_id == plan.engine_source_id
            && record.assignment_id == assignment.id,
        "unit proof belongs to another plan/engine/assignment"
    );
    let unit = plan.units.get(record.unit).context("unknown unit")?;
    let product = &plan.config.products[unit.product];
    let target = plan.config.targets[unit.target].key();
    ensure!(
        policy
            .trusted_keys
            .iter()
            .any(|key| key.public_key == proof.public_key
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
        "trusted rebuild key is unknown, revoked or outside policy scope"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn record_proofs_bind_domain_id_and_assignment() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let public = public_key(&key);
        let proof = seal_record("record", b"payload\0", &key);
        verify_record("record", b"payload\0", Some(&proof), Some(&public)).unwrap();
        assert!(verify_record("record", b"package\0", Some(&proof), Some(&public)).is_err());
        assert!(verify_record("other", b"payload\0", Some(&proof), Some(&public)).is_err());
        assert!(verify_record("record", b"payload\0", Some(&proof), None).is_err());
        assert!(verify_record("record", b"payload\0", None, Some(&public)).is_err());
        verify_record("record", b"payload\0", None, None).unwrap();
    }
}
