use super::model::FileEntry;
use crate::{config, source};
use anyhow::{Context, Result, ensure};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const JSON_LIMIT: u64 = 16 * 1024 * 1024;
pub const FILE_LIMIT: u64 = 512 * 1024 * 1024;
pub const BUNDLE_LIMIT: u64 = 2 * 1024 * 1024 * 1024;

pub(crate) struct WriterLock(File);

impl WriterLock {
    pub(crate) fn acquire(file: File) -> Result<Self> {
        file.try_lock()?;
        Ok(Self(file))
    }
}

impl Drop for WriterLock {
    fn drop(&mut self) {
        // A concurrent fork can briefly share this file description. Release
        // the lock at the operation boundary instead of waiting for every copy.
        let _ = self.0.unlock();
    }
}

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Strict, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Strict(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::String(v.into())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::String(v)))
            }
            fn visit_none<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut out = Vec::new();
                while let Some(Strict(v)) = a.next_element()? {
                    out.push(v);
                }
                Ok(Strict(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some((k, Strict(v))) = a.next_entry::<String, Strict>()? {
                    if out.insert(k.clone(), v).is_some() {
                        return Err(de::Error::custom(format!("duplicate JSON key: {k}")));
                    }
                }
                Ok(Strict(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("inspect JSON file {}", path.display()))?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "JSON must be a regular file: {}",
        path.display()
    );
    ensure!(
        meta.len() <= JSON_LIMIT,
        "JSON exceeds 16 MiB: {}",
        path.display()
    );
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("open JSON file {}", path.display()))?
        .take(JSON_LIMIT + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read JSON file {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= JSON_LIMIT,
        "JSON grew beyond limit: {}",
        path.display()
    );
    let Strict(value) = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid or ambiguous JSON in {}", path.display()))?;
    serde_json::from_value(value)
        .with_context(|| format!("invalid versioned record in {}", path.display()))
}
pub fn random_id() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("OS randomness unavailable: {e}"))?;
    Ok(b.iter().map(|b| format!("{b:02x}")).collect())
}
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
pub fn write_json_atomic<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)
        .with_context(|| format!("serialize JSON record {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= JSON_LIMIT,
        "record exceeds 16 MiB: {}",
        path.display()
    );
    let parent = path.parent().context("record has no parent")?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("invalid record filename")?;
    config::safe_join(parent, name)?;
    let temporary = config::safe_join(parent, &format!("{name}.tmp-{}", random_id()?))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .with_context(|| format!("create temporary JSON file {}", temporary.display()))?;
    file.write_all(&bytes)
        .and_then(|()| file.write_all(b"\n"))
        .with_context(|| format!("write temporary JSON file {}", temporary.display()))?;
    file.sync_all()
        .with_context(|| format!("sync temporary JSON file {}", temporary.display()))?;
    drop(file);
    fs::rename(&temporary, path).with_context(|| {
        format!(
            "replace JSON file {} from {}",
            path.display(),
            temporary.display()
        )
    })?;
    sync_directory(parent)
        .with_context(|| format!("sync JSON parent directory {}", parent.display()))?;
    Ok(())
}
pub fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
pub fn fresh_directory(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()
        .context("output parent must exist")?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("output must name a fresh directory")?;
    let output = config::safe_join(&parent, name)?;
    ensure!(
        matches!(fs::symlink_metadata(&output),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
        "output already exists or cannot be inspected"
    );
    fs::create_dir(&output)?;
    Ok(output)
}
pub fn inventory(root: &Path) -> Result<BTreeMap<String, FileEntry>> {
    fn scan(
        root: &Path,
        dir: &Path,
        out: &mut BTreeMap<String, FileEntry>,
        total: &mut u64,
    ) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = path
                .strip_prefix(root)?
                .to_str()
                .context("non-UTF8 member")?
                .replace('\\', "/");
            config::relative(&name)?;
            let meta = fs::symlink_metadata(&path)?;
            ensure!(!meta.file_type().is_symlink(), "bundle symlink: {name}");
            if meta.is_dir() {
                scan(root, &path, out, total)?;
                continue;
            }
            ensure!(meta.is_file(), "non-regular bundle member: {name}");
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                ensure!(meta.nlink() == 1, "hardlinked bundle member: {name}");
            }
            ensure!(meta.len() <= FILE_LIMIT, "bundle member exceeds limit");
            *total = total
                .checked_add(meta.len())
                .context("bundle size overflow")?;
            ensure!(
                *total <= BUNDLE_LIMIT && out.len() < 10_000,
                "bundle exceeds resource limits"
            );
            let key = name.to_ascii_lowercase();
            ensure!(
                !out.keys().any(|p| p.to_ascii_lowercase() == key),
                "case-colliding bundle member"
            );
            out.insert(
                name,
                FileEntry {
                    sha256: source::file_digest(&path)?,
                    size: meta.len(),
                },
            );
        }
        Ok(())
    }
    let meta = fs::symlink_metadata(root)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "bundle root must be a directory"
    );
    let mut out = BTreeMap::new();
    scan(root, root, &mut out, &mut 0)?;
    Ok(out)
}
pub fn copy_file_checked(source_path: &Path, dest: &Path, expected: &FileEntry) -> Result<()> {
    ensure!(expected.size <= FILE_LIMIT, "file exceeds resource limit");
    let meta = fs::symlink_metadata(source_path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "copy source is not a regular file"
    );
    ensure!(meta.len() == expected.size, "copy source size changed");
    let parent = dest.parent().context("copy destination missing parent")?;
    fs::create_dir_all(parent)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(dest)?;
    let size = std::io::copy(
        &mut File::open(source_path)?.take(expected.size + 1),
        &mut file,
    )?;
    file.sync_all()?;
    drop(file);
    ensure!(
        size == expected.size && source::file_digest(dest)? == expected.sha256,
        "copied bytes changed or digest mismatch"
    );
    Ok(())
}

/// Validate a fresh output without creating it; permit canonical external parents.
pub fn guard_output(root: &Path, path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()
        .context("output parent must exist")?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("invalid output name")?;
    let out = config::safe_join(&parent, name)?;
    ensure!(
        matches!(fs::symlink_metadata(&out),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
        "output already exists or cannot be inspected"
    );
    let root = root.canonicalize()?;
    ensure!(!root.starts_with(&out), "output overlaps source root");
    if out.starts_with(&root) {
        ensure!(
            out.starts_with(root.join("target")) && out != root.join("target"),
            "source-tree outputs must be beneath ignored target/"
        );
        let relative = out
            .strip_prefix(&root)?
            .to_str()
            .context("non-UTF8 output")?;
        config::safe_join(&root, relative)?;
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
        .context("output must be ignored")?;
        ensure!(
            source::git(&root, &["ls-files", "--", relative])?.is_empty(),
            "output overlaps tracked inputs"
        );
    }
    Ok(out)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn writer_lock_releases_while_a_duplicate_descriptor_stays_open() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("writer.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let duplicate = {
            let owner = WriterLock::acquire(file).unwrap();
            let duplicate = owner.0.try_clone().unwrap();
            assert!(contender.try_lock().is_err());
            duplicate
        };
        contender
            .try_lock()
            .expect("the completed owner must release its lock before duplicates close");
        contender.unlock().unwrap();
        drop(duplicate);
    }
}
