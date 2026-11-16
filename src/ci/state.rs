//! Explicit transport of a stopped draft publisher and its original collection.
use super::{config, model::Config};
use crate::{
    cohort::{self, io, model::FileEntry},
    github, source,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::Path,
};

const PACKET_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
const MEMBERS: usize = 20_010;
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    run_id: String,
    run_attempt: String,
    config_id: String,
    source_commit: String,
    engine_source_id: String,
    collection_id: String,
    policy_id: String,
    files: BTreeMap<String, FileEntry>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    modes: BTreeMap<String, u32>,
}
fn origin(run_id: &str, run_attempt: &str) -> Result<()> {
    for value in [run_id, run_attempt] {
        ensure!(
            !value.is_empty()
                && value.len() <= 20
                && value.bytes().all(|b| b.is_ascii_digit())
                && !value.starts_with('0'),
            "state requires an explicit positive run ID and attempt"
        );
    }
    Ok(())
}
fn regular(path: &Path, limit: u64) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= limit,
        "state input must be a bounded regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(metadata.nlink() == 1, "state input must not be hardlinked");
    }
    Ok(())
}
fn private(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}
fn private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
fn packet_name(name: &str) -> Result<()> {
    ensure!(
        name.len() <= 4096
            && name.split('/').count() <= 32
            && !name.contains('\\')
            && !name.contains(':')
            && !name.chars().any(char::is_control),
        "unsafe state path"
    );
    crate::config::relative(name)?;
    ensure!(
        name.split('/')
            .all(|part| !part.is_empty() && !part.ends_with(['.', ' '])),
        "ambiguous state path"
    );
    ensure!(
        name.starts_with("collection/")
            || name == "attempt/plan.json"
            || name == "attempt/receipt.json"
            || name.starts_with("attempt/snapshot/"),
        "unexpected state path"
    );
    Ok(())
}
fn validate_manifest(
    manifest: &Manifest,
    config: &Config,
    run_id: &str,
    run_attempt: &str,
) -> Result<()> {
    origin(run_id, run_attempt)?;
    ensure!(
        manifest.schema == 1 && manifest.run_id == run_id && manifest.run_attempt == run_attempt,
        "state origin differs from explicitly requested run and attempt"
    );
    ensure!(
        manifest.config_id == config::id(config)?
            && manifest.engine_source_id == config.engine.source_id,
        "state configuration or engine differs"
    );
    ensure!(
        manifest.source_commit.len() == 40
            && manifest
                .source_commit
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            && [&manifest.collection_id, &manifest.policy_id]
                .iter()
                .all(|v| cohort::plan::is_digest(v)),
        "invalid state content identities"
    );
    ensure!(
        !manifest.files.is_empty() && manifest.files.len() <= MEMBERS,
        "state member count exceeds limit"
    );
    let mut names = BTreeMap::new();
    let mut total = 0u64;
    for (name, entry) in &manifest.files {
        packet_name(name)?;
        // Check every prefix too, so A/file and a/other cannot diverge by host.
        let components: Vec<_> = name.split('/').collect();
        for length in 1..=components.len() {
            let prefix = components[..length].join("/");
            let folded = prefix.to_ascii_lowercase();
            if let Some(previous) = names.insert(folded, prefix.clone()) {
                ensure!(previous == prefix, "case-colliding state path");
            }
            if length < components.len() {
                ensure!(
                    !manifest.files.contains_key(&prefix),
                    "state file shadows a directory"
                );
            }
        }
        ensure!(
            entry.size
                <= if name.ends_with(".json") {
                    io::JSON_LIMIT
                } else {
                    io::FILE_LIMIT
                }
                && cohort::plan::is_digest(&entry.sha256),
            "invalid state file size or digest"
        );
        total = total
            .checked_add(entry.size)
            .context("state size overflow")?;
        ensure!(total <= PACKET_LIMIT, "state exceeds 4 GiB");
    }
    for (name, mode) in &manifest.modes {
        ensure!(
            manifest.files.contains_key(name)
                && payload_mode_path(name)
                && matches!(mode, 0o644 | 0o755),
            "state mode must describe a verified delivery payload file"
        );
    }
    ensure!(
        manifest.files.contains_key("attempt/plan.json")
            && manifest.files.contains_key("attempt/receipt.json")
            && manifest.files.contains_key("collection/collection.json"),
        "state is incomplete"
    );
    Ok(())
}

fn payload_mode_path(name: &str) -> bool {
    let Some(relative) = name.strip_prefix("collection/results/") else {
        return false;
    };
    let Some((bundle, relative)) = relative.split_once('/') else {
        return false;
    };
    let Some(relative) = relative.strip_prefix("payloads/") else {
        return false;
    };
    let Some((build, relative)) = relative.split_once('/') else {
        return false;
    };
    cohort::plan::is_digest(bundle)
        && build
            .parse::<usize>()
            .is_ok_and(|value| value.to_string() == build)
        && relative
            .strip_prefix("files/")
            .is_some_and(|value| !value.is_empty())
}

// Called only after complete collection verification. Record modes, rather
// than ambient permissions, define the narrow executable transport surface.
fn payload_modes(collection: &Path) -> Result<BTreeMap<String, u32>> {
    let value: serde_json::Value = io::read_json(&collection.join("collection.json"))?;
    let schema = value.get("schema").and_then(serde_json::Value::as_u64);
    let bundles = match schema {
        Some(4) => {
            io::read_json::<crate::delivery::bundle::Collection>(
                &collection.join("collection.json"),
            )?
            .bundles
        }
        Some(5) => {
            io::read_json::<crate::v5::bundle::Collection>(&collection.join("collection.json"))?
                .bundles
        }
        _ => return Ok(BTreeMap::new()),
    };
    let mut modes = BTreeMap::new();
    for id in bundles {
        let bundle_root = crate::config::safe_join(collection, &format!("results/{id}"))?;
        let builds = if schema == Some(5) {
            io::read_json::<crate::v5::bundle::Bundle>(&bundle_root.join("bundle.json"))?.builds
        } else {
            io::read_json::<crate::delivery::bundle::Bundle>(&bundle_root.join("bundle.json"))?
                .builds
        };
        for build in builds {
            let prefix = format!("payloads/{build}");
            let path = crate::config::safe_join(&bundle_root, &format!("{prefix}/payload.json"))?;
            let files = if schema == Some(5) {
                io::read_json::<crate::v5::run::PayloadRecord>(&path)?.files
            } else {
                io::read_json::<crate::delivery::run::PayloadRecord>(&path)?.files
            };
            for (name, entry) in files {
                ensure!(matches!(entry.mode, 0o644 | 0o755), "unsafe payload mode");
                let path = format!("collection/results/{id}/{prefix}/files/{name}");
                ensure!(
                    modes.insert(path, entry.mode).is_none(),
                    "duplicate payload mode path"
                );
            }
        }
    }
    Ok(modes)
}
fn checked_state(
    root: &Path,
    config: &Config,
    collection: &Path,
    attempt: &Path,
) -> Result<(github::model::Plan, BTreeMap<String, FileEntry>)> {
    config::assert_current_engine(config)?;
    let policy_path = crate::config::safe_join(root, &config.delivery.policy)?;
    let plan = github::plan::load(&attempt.join("plan.json"))?;
    let collection_record: serde_json::Value = io::read_json(&collection.join("collection.json"))?;
    if collection_record
        .get("schema")
        .and_then(serde_json::Value::as_u64)
        == Some(5)
    {
        ensure!(
            config.execution_protocol == 5,
            "state collection protocol differs from trusted configuration"
        );
        regular(&policy_path, io::JSON_LIMIT)?;
        let policy: crate::v5::proof::Policy = toml::from_str(&fs::read_to_string(policy_path)?)?;
        crate::v5::proof::validate_policy(&policy)?;
        github::plan::validate_v5(root, collection, &policy, &plan, true)?;
    } else {
        ensure!(
            config.execution_protocol != 5,
            "state collection protocol differs from trusted configuration"
        );
        let policy = cohort::crypto::load_policy(&policy_path)?;
        github::plan::validate(root, collection, &policy, &plan, true)?;
    }
    ensure!(
        plan.repository.full_name == config.delivery.repository
            && plan.create_tag_if_missing == config.delivery.create_tag_if_missing,
        "state delivery contract differs from trusted configuration"
    );
    github::run::status(attempt)?;
    // Only the canonical records, complete snapshot and inactive lock are allowed.
    let expected: BTreeSet<_> = ["plan.json".to_owned(), "receipt.json".to_owned()]
        .into_iter()
        .chain(
            plan.assets
                .iter()
                .map(|asset| format!("snapshot/{}", asset.name)),
        )
        .collect();
    for entry in fs::read_dir(attempt)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().context("non-UTF8 publisher state member")?;
        ensure!(
            matches!(
                name,
                "plan.json" | "receipt.json" | "snapshot" | ".writer.lock"
            ),
            "unexpected publisher state member"
        );
    }
    let snapshot = attempt.join("snapshot");
    let metadata = fs::symlink_metadata(&snapshot)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "complete regular publisher snapshot is required"
    );
    for entry in fs::read_dir(&snapshot)? {
        regular(&entry?.path(), io::FILE_LIMIT)?;
    }
    let mut actual = io::inventory(attempt)?;
    if let Some(lock) = actual.remove(".writer.lock") {
        ensure!(lock.size == 0, "unexpected writer lock content");
    }
    ensure!(
        actual.keys().cloned().collect::<BTreeSet<_>>() == expected,
        "publisher state has missing or unexpected files; a complete saved snapshot is required"
    );
    for asset in &plan.assets {
        ensure!(
            actual.get(&format!("snapshot/{}", asset.name))
                == Some(&FileEntry {
                    size: asset.size,
                    sha256: asset.sha256.clone()
                }),
            "publisher snapshot differs from planned assets"
        );
    }
    let mut files = io::inventory(collection)?
        .into_iter()
        .map(|(name, entry)| (format!("collection/{name}"), entry))
        .collect::<BTreeMap<_, _>>();
    files.extend(
        actual
            .into_iter()
            .map(|(name, entry)| (format!("attempt/{name}"), entry)),
    );
    Ok((plan, files))
}
fn lock(attempt: &Path) -> Result<io::WriterLock> {
    let metadata = fs::symlink_metadata(attempt)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "publisher state must be a regular directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "publisher state must be private (mode 0700)"
        );
    }
    let path = attempt.join(".writer.lock");
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    match fs::symlink_metadata(&path) {
        Ok(_) => regular(&path, 0)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            options.create_new(true);
        }
        Err(error) => return Err(error.into()),
    }
    let file = options.open(&path)?;
    regular(&path, 0)?;
    io::WriterLock::acquire(file).context("publisher still has an active local writer")
}
fn header(name: &str, size: u64) -> Result<tar::Header> {
    mode_header(name, size, 0o600)
}
fn mode_header(name: &str, size: u64, mode: u32) -> Result<tar::Header> {
    let mut header = tar::Header::new_ustar();
    header.set_path(name)?;
    header.set_size(size);
    header.set_mode(mode);
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    Ok(header)
}
#[allow(clippy::too_many_arguments)]
pub fn pack(
    root: &Path,
    config: &Config,
    collection: &Path,
    attempt: &Path,
    run_id: &str,
    run_attempt: &str,
    output: &Path,
) -> Result<()> {
    origin(run_id, run_attempt)?;
    let _writer = lock(attempt)?;
    let (plan, files) = checked_state(root, config, collection, attempt)?;
    let modes = payload_modes(collection)?;
    let manifest = Manifest {
        schema: 1,
        run_id: run_id.into(),
        run_attempt: run_attempt.into(),
        config_id: config::id(config)?,
        source_commit: plan.source_commit,
        engine_source_id: plan.engine_source_id,
        collection_id: plan.collection_id,
        policy_id: plan.policy_id,
        files,
        modes,
    };
    validate_manifest(&manifest, config, run_id, run_attempt)?;
    let output = io::guard_output(root, output)?;
    ensure!(
        !output.starts_with(collection.canonicalize()?)
            && !output.starts_with(attempt.canonicalize()?),
        "state output overlaps inputs"
    );
    let result = (|| {
        let mut builder = tar::Builder::new(private_file(&output)?);
        let bytes = serde_json::to_vec(&manifest)?;
        ensure!(
            bytes.len() as u64 <= io::JSON_LIMIT,
            "state manifest exceeds limit"
        );
        builder.append(&header("state.json", bytes.len() as u64)?, bytes.as_slice())?;
        for (name, entry) in &manifest.files {
            let (base, member) = if let Some(member) = name.strip_prefix("collection/") {
                (collection, member)
            } else {
                (
                    attempt,
                    name.strip_prefix("attempt/")
                        .context("invalid attempt path")?,
                )
            };
            let path = crate::config::safe_join(base, member)?;
            regular(&path, io::FILE_LIMIT)?;
            ensure!(
                fs::metadata(&path)?.len() == entry.size
                    && source::file_digest(&path)? == entry.sha256,
                "state input changed before save"
            );
            let mut reader = HashReader {
                input: File::open(path)?.take(entry.size + 1),
                hash: Sha256::new(),
                count: 0,
            };
            builder.append(
                &mode_header(
                    name,
                    entry.size,
                    manifest.modes.get(name).copied().unwrap_or(0o600),
                )?,
                &mut reader,
            )?;
            let mut extra = [0; 1];
            ensure!(
                reader.read(&mut extra)? == 0
                    && reader.count == entry.size
                    && format!("{:x}", reader.hash.finalize()) == entry.sha256,
                "state input changed while saving"
            );
        }
        builder.finish()?;
        builder.into_inner()?.sync_all()?;
        io::sync_directory(output.parent().context("state output has no parent")?)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(output);
    }
    result
}
struct HashReader<R> {
    input: R,
    hash: Sha256,
    count: u64,
}
impl<R: Read> Read for HashReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let count = self.input.read(bytes)?;
        self.hash.update(&bytes[..count]);
        self.count += count as u64;
        Ok(count)
    }
}
fn entry_name<R: Read>(entry: &tar::Entry<'_, R>) -> Result<String> {
    ensure!(
        entry.header().entry_type() == tar::EntryType::Regular
            && entry.header().as_ustar().is_some()
            && entry.header().link_name()?.is_none(),
        "state tar accepts regular ustar members only"
    );
    let bytes = entry.path_bytes();
    Ok(std::str::from_utf8(&bytes)
        .context("non-UTF8 state path")?
        .into())
}
#[allow(clippy::too_many_arguments)]
pub fn restore(
    root: &Path,
    config: &Config,
    archive: &Path,
    run_id: &str,
    run_attempt: &str,
    old_writer_stopped: bool,
    output: &Path,
) -> Result<()> {
    ensure!(
        old_writer_stopped,
        "restore requires the operator to confirm the original writer has stopped; a cross-host file lock is not a fence"
    );
    config::assert_current_engine(config)?;
    origin(run_id, run_attempt)?;
    regular(
        archive,
        PACKET_LIMIT + io::JSON_LIMIT + MEMBERS as u64 * 1024 + 2048,
    )?;
    let mut input = File::open(archive)?;
    let archive_len = input.metadata()?.len();
    ensure!(
        archive_len >= 1536 && archive_len % 512 == 0,
        "state tar lacks its complete end marker"
    );
    input.seek(SeekFrom::End(-1024))?;
    let mut end = [0; 1024];
    input.read_exact(&mut end)?;
    ensure!(
        end.iter().all(|byte| *byte == 0),
        "state tar has an invalid end marker or trailing data"
    );
    input.seek(SeekFrom::Start(0))?;
    let output = io::guard_output(root, output)?;
    private(&output)?;
    let result = (|| {
        let mut tar = tar::Archive::new(input.take(archive_len));
        let mut entries = tar.entries()?.raw(true);
        let mut first = entries.next().context("state manifest missing")??;
        ensure!(
            entry_name(&first)? == "state.json"
                && first.size() <= io::JSON_LIMIT
                && first.header().mode()? == 0o600,
            "state manifest must be the first bounded regular member"
        );
        let manifest_path = output.join("state.json");
        let mut manifest_file = private_file(&manifest_path)?;
        std::io::copy(&mut first, &mut manifest_file)?;
        drop(manifest_file);
        drop(first);
        let manifest: Manifest = io::read_json(&manifest_path)?;
        validate_manifest(&manifest, config, run_id, run_attempt)?;
        fs::remove_file(manifest_path)?;
        private(&output.join("collection"))?;
        private(&output.join("attempt"))?;
        let mut seen = BTreeSet::new();
        for entry in entries {
            let mut entry = entry?;
            let name = entry_name(&entry)?;
            packet_name(&name)?;
            let expected = manifest
                .files
                .get(&name)
                .context("unplanned state tar member")?;
            ensure!(
                seen.insert(name.clone())
                    && entry.size() == expected.size
                    && entry.header().mode()?
                        == manifest.modes.get(&name).copied().unwrap_or(0o600),
                "duplicate or changed state tar member"
            );
            let destination = crate::config::safe_join(&output, &name)?;
            fs::create_dir_all(destination.parent().context("state member has no parent")?)?;
            let mut file = private_file(&destination)?;
            let mut reader = HashReader {
                input: (&mut entry).take(expected.size + 1),
                hash: Sha256::new(),
                count: 0,
            };
            std::io::copy(&mut reader, &mut file)?;
            ensure!(
                reader.count == expected.size
                    && format!("{:x}", reader.hash.finalize()) == expected.sha256,
                "state tar file digest or size differs"
            );
            if let Some(mode) = manifest.modes.get(&name) {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    file.set_permissions(fs::Permissions::from_mode(*mode))?;
                }
                #[cfg(not(unix))]
                let _ = mode;
            }
            file.sync_all()?;
        }
        ensure!(
            seen.len() == manifest.files.len(),
            "state tar is missing planned files"
        );
        // Reject concatenated archives and nonzero data after the first terminator.
        let mut trailing = tar.into_inner();
        let mut buffer = [0; 8192];
        loop {
            let count = trailing.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            ensure!(
                buffer[..count].iter().all(|b| *b == 0),
                "unexpected state tar trailing data"
            );
        }
        let (plan, files) = checked_state(
            root,
            config,
            &output.join("collection"),
            &output.join("attempt"),
        )?;
        ensure!(
            files == manifest.files
                && payload_modes(&output.join("collection"))? == manifest.modes
                && plan.source_commit == manifest.source_commit
                && plan.collection_id == manifest.collection_id
                && plan.policy_id == manifest.policy_id,
            "restored state identities differ"
        );
        io::sync_directory(&output)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(output);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_origin_and_writer_stop_are_required() {
        for (run, attempt) in [
            ("", "1"),
            ("latest", "1"),
            ("12", "0"),
            ("001", "2"),
            ("1/2", "1"),
        ] {
            assert!(origin(run, attempt).is_err());
        }
        assert!(origin("123", "2").is_ok());
        let temporary = tempfile::tempdir().unwrap();
        let config = config::tests::example();
        let error = restore(
            temporary.path(),
            &config,
            Path::new("absent"),
            "1",
            "1",
            false,
            &temporary.path().join("out"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("original writer"));
    }
    #[test]
    fn transport_paths_exclude_keys_locks_and_checkout() {
        for name in [
            "attempt/.writer.lock",
            "attempt/key.json",
            "attempt/.snapshot-a/file",
            "../collection/file",
            "collection/../key",
            "collection/A\\file",
            "source/file",
            "collection/x.",
            "collection/C:/key",
        ] {
            assert!(packet_name(name).is_err(), "{name}");
        }
        assert!(packet_name("collection/results/a/units/0/tool.tar.gz").is_ok());
        assert!(packet_name("attempt/snapshot/SHA256SUMS").is_ok());
    }
    #[test]
    fn local_writer_must_have_released_lock() {
        let temporary = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let first = lock(temporary.path()).unwrap();
        assert!(lock(temporary.path()).is_err());
        drop(first);
        assert!(lock(temporary.path()).is_ok());
    }
    fn manifest(config: &Config) -> Manifest {
        Manifest {
            schema: 1,
            run_id: "123".into(),
            run_attempt: "2".into(),
            config_id: config::id(config).unwrap(),
            source_commit: "a".repeat(40),
            engine_source_id: config.engine.source_id.clone(),
            collection_id: "b".repeat(64),
            policy_id: "c".repeat(64),
            modes: BTreeMap::new(),
            files: [
                "attempt/plan.json",
                "attempt/receipt.json",
                "collection/collection.json",
            ]
            .into_iter()
            .map(|name| {
                (
                    name.into(),
                    FileEntry {
                        size: 2,
                        sha256: source::digest(b"{}"),
                    },
                )
            })
            .collect(),
        }
    }
    #[test]
    fn rehashed_manifest_cannot_change_origin_or_cross_host_paths() {
        let config = config::tests::example();
        let mut value = manifest(&config);
        assert!(validate_manifest(&value, &config, "123", "2").is_ok());
        assert!(validate_manifest(&value, &config, "123", "1").is_err());
        value.files.insert(
            "collection/A/file".into(),
            FileEntry {
                size: 2,
                sha256: source::digest(b"{}"),
            },
        );
        value.files.insert(
            "collection/a/other".into(),
            FileEntry {
                size: 2,
                sha256: source::digest(b"{}"),
            },
        );
        assert!(validate_manifest(&value, &config, "123", "2").is_err());
    }
    #[test]
    fn legacy_packets_omit_modes_and_only_delivery_payloads_can_restore_permissions() {
        let config = config::tests::example();
        let mut value = manifest(&config);
        let encoded = serde_json::to_value(&value).unwrap();
        assert!(encoded.get("modes").is_none());
        let decoded: Manifest = serde_json::from_value(encoded).unwrap();
        assert!(decoded.modes.is_empty());
        let name = format!(
            "collection/results/{}/payloads/0/files/bin/tool",
            "d".repeat(64)
        );
        value.files.insert(
            name.clone(),
            FileEntry {
                size: 2,
                sha256: source::digest(b"{}"),
            },
        );
        value.modes.insert(name.clone(), 0o755);
        validate_manifest(&value, &config, "123", "2").unwrap();
        for mode in [0o777, 0o4755, 0o600, 0o100755] {
            value.modes.insert(name.clone(), mode);
            assert!(validate_manifest(&value, &config, "123", "2").is_err());
        }
        value.modes.clear();
        for name in [
            "attempt/plan.json",
            "collection/collection.json",
            "collection/verified/tool.tar.gz",
        ] {
            value.modes.insert(name.into(), 0o755);
            assert!(validate_manifest(&value, &config, "123", "2").is_err());
            value.modes.clear();
        }
    }
    #[test]
    fn hostile_tar_is_rejected_before_core_and_partial_output_removed() {
        for kind in ["symlink", "duplicate", "unknown", "digest", "trailing"] {
            let root = tempfile::tempdir().unwrap();
            let storage = tempfile::tempdir().unwrap();
            let config = config::tests::example();
            let archive = storage.path().join("packet.tar");
            let mut builder = tar::Builder::new(File::create(&archive).unwrap());
            let bytes = serde_json::to_vec(&manifest(&config)).unwrap();
            builder
                .append(
                    &header("state.json", bytes.len() as u64).unwrap(),
                    bytes.as_slice(),
                )
                .unwrap();
            if kind == "symlink" {
                let mut h = header("attempt/plan.json", 0).unwrap();
                h.set_entry_type(tar::EntryType::Symlink);
                h.set_link_name("../key").unwrap();
                h.set_cksum();
                builder.append(&h, std::io::empty()).unwrap();
            } else if kind == "unknown" {
                builder
                    .append(&header("attempt/key.json", 2).unwrap(), b"{}".as_slice())
                    .unwrap();
            } else if kind == "digest" {
                builder
                    .append(&header("attempt/plan.json", 2).unwrap(), b"[]".as_slice())
                    .unwrap();
            } else {
                builder
                    .append(&header("attempt/plan.json", 2).unwrap(), b"{}".as_slice())
                    .unwrap();
                if kind == "duplicate" {
                    builder
                        .append(&header("attempt/plan.json", 2).unwrap(), b"{}".as_slice())
                        .unwrap();
                }
            }
            if kind == "trailing" {
                for name in ["attempt/receipt.json", "collection/collection.json"] {
                    builder
                        .append(&header(name, 2).unwrap(), b"{}".as_slice())
                        .unwrap();
                }
            }
            builder.finish().unwrap();
            let mut file = builder.into_inner().unwrap();
            if kind == "trailing" {
                use std::io::Write;
                file.write_all(b"malicious").unwrap();
            }
            drop(file);
            let output = storage.path().join("restored");
            let error =
                restore(root.path(), &config, &archive, "123", "2", true, &output).unwrap_err();
            assert!(!output.exists(), "{kind}: {error:#}");
            let message = error.to_string();
            assert!(
                message.contains(match kind {
                    "symlink" => "regular ustar",
                    "duplicate" => "duplicate",
                    "unknown" => "unexpected state path",
                    "digest" => "digest",
                    _ => "end marker",
                }),
                "{kind}: {error:#}"
            );
        }
    }
}
