use crate::{config::relative, model::Member, source::digest};
use anyhow::{Context, Result, bail, ensure};
use flate2::{Compression, bufread::GzDecoder, write::GzEncoder};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, Write};
use std::path::Path;

pub const CONTENT_LIMIT: u64 = 512 * 1024 * 1024;
const ENTRY_LIMIT: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    pub bytes: Vec<u8>,
    pub executable: bool,
}

pub fn write(path: &Path, files: &BTreeMap<String, Content>) -> Result<()> {
    ensure!(!files.is_empty(), "empty archive");
    let total: usize = files.values().map(|c| c.bytes.len()).sum();
    ensure!(total as u64 <= CONTENT_LIMIT, "archive content too large");
    for name in files.keys() {
        relative(name)?;
    }
    let file = File::create(path)?;
    if path.to_string_lossy().ends_with(".tar.gz") {
        let gzip = GzEncoder::new(file, Compression::default());
        let mut archive = tar::Builder::new(gzip);
        for (name, content) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(content.bytes.len() as u64);
            header.set_mode(if content.executable { 0o755 } else { 0o644 });
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            archive.append_data(&mut header, name, content.bytes.as_slice())?;
        }
        archive.into_inner()?.finish()?.sync_all()?;
    } else if path.to_string_lossy().ends_with(".zip") {
        let mut archive = zip::ZipWriter::new(file);
        for (name, content) in files {
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(if content.executable { 0o755 } else { 0o644 });
            archive.start_file(name, options)?;
            archive.write_all(&content.bytes)?;
        }
        archive.finish()?.sync_all()?;
    } else {
        bail!("unsupported archive format: {}", path.display());
    }
    Ok(())
}

fn insert(
    files: &mut BTreeMap<String, Content>,
    name: String,
    mode: u32,
    declared_size: u64,
    reader: impl Read,
    remaining: &mut u64,
) -> Result<()> {
    relative(&name)?;
    ensure!(files.len() < ENTRY_LIMIT, "too many archive members");
    ensure!(
        !files.contains_key(&name),
        "duplicate archive member: {name}"
    );
    ensure!(mode & 0o7000 == 0, "special permission bits on {name}");
    ensure!(
        mode & 0o777 == if mode & 0o111 != 0 { 0o755 } else { 0o644 },
        "archive permissions must be 0755 for executables or 0644 for resources: {name}"
    );
    ensure!(
        declared_size <= *remaining,
        "archive content limit exceeded"
    );
    let mut bytes = Vec::new();
    reader.take(*remaining + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == declared_size,
        "archive member size mismatch: {name}"
    );
    *remaining -= declared_size;
    files.insert(
        name,
        Content {
            bytes,
            executable: mode & 0o111 != 0,
        },
    );
    Ok(())
}

pub fn inspect(path: &Path) -> Result<BTreeMap<String, Content>> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "archive is not a regular file"
    );
    ensure!(meta.len() <= CONTENT_LIMIT, "archive file too large");
    let file = File::open(path)?;
    let mut files = BTreeMap::new();
    let mut remaining = CONTENT_LIMIT;
    if path.to_string_lossy().ends_with(".tar.gz") {
        let mut archive = tar::Archive::new(GzDecoder::new(BufReader::new(file)));
        for entry in archive.entries()? {
            let entry = entry?;
            ensure!(
                entry.header().entry_type().is_file(),
                "non-regular tar member"
            );
            let name = std::str::from_utf8(&entry.path_bytes())?.to_owned();
            let mode = entry.header().mode()?;
            let size = entry.size();
            insert(&mut files, name, mode, size, entry, &mut remaining)?;
        }
        // Reading to EOF checks the gzip trailer rather than trusting tar's end marker.
        let mut gzip = archive.into_inner();
        let mut tail = Vec::new();
        gzip.by_ref().take(1025).read_to_end(&mut tail)?;
        ensure!(
            tail.len() <= 1024 && tail.iter().all(|b| *b == 0),
            "unexpected tar trailing data"
        );
        let mut last = [0];
        ensure!(
            gzip.read(&mut last)? == 0,
            "unexpected compressed archive tail"
        );
        ensure!(
            gzip.into_inner().fill_buf()?.is_empty(),
            "extra gzip stream or trailing bytes"
        );
    } else if path.to_string_lossy().ends_with(".zip") {
        let mut archive = zip::ZipArchive::new(file)?;
        ensure!(archive.offset() == 0, "ZIP has prepended data");
        ensure!(archive.len() <= ENTRY_LIMIT, "too many ZIP entries");
        ensure!(archive.comment().is_empty(), "unsupported ZIP comments");
        let directory_start = archive.central_directory_start();
        let mut central_position = directory_start;
        for index in 0..archive.len() {
            let entry = archive.by_index(index)?;
            ensure!(entry.is_file(), "non-file ZIP member");
            // This engine writes the bounded ZIP32 profile without comments or
            // extra fields. Contiguous directory records also detect duplicates
            // hidden by zip-rs's filename-keyed central-directory map.
            // PKWARE APPNOTE 4.3.12/4.3.16: fixed record sizes are 46/22 bytes.
            ensure!(
                entry.extra_data().unwrap_or_default().is_empty() && entry.comment().is_empty(),
                "unsupported ZIP extra metadata"
            );
            ensure!(
                entry.central_header_start() == central_position,
                "duplicate or unaccounted ZIP directory records"
            );
            central_position += 46 + entry.name_raw().len() as u64;
            let name = std::str::from_utf8(entry.name_raw())?.to_owned();
            let mode = entry.unix_mode().context("ZIP member has no Unix mode")?;
            ensure!(mode & 0o170000 == 0o100000, "non-regular ZIP member");
            let size = entry.size();
            insert(&mut files, name, mode, size, entry, &mut remaining)?;
        }
        ensure!(
            central_position + 22 == meta.len(),
            "ZIP has extra directory records or trailing bytes"
        );
        // Central-directory readers alone can overlook conflicting local names.
        // Read physical entries through the library's streaming API as well.
        let mut physical = File::open(path)?;
        let mut seen = std::collections::BTreeSet::new();
        let mut budget = CONTENT_LIMIT;
        while let Some(entry) = zip::read::read_zipfile_from_stream(&mut physical)? {
            let name = std::str::from_utf8(entry.name_raw())?.to_owned();
            relative(&name)?;
            ensure!(seen.insert(name.clone()), "duplicate ZIP local member");
            let expected = files
                .get(&name)
                .context("ZIP local member absent from directory")?;
            ensure!(entry.size() <= budget, "ZIP local content too large");
            let mut bytes = Vec::new();
            entry.take(budget + 1).read_to_end(&mut bytes)?;
            ensure!(bytes == expected.bytes, "ZIP local/directory bytes differ");
            budget -= bytes.len() as u64;
        }
        ensure!(
            seen.len() == files.len() && physical.stream_position()? == directory_start + 4,
            "ZIP local/directory file sets differ"
        );
    } else {
        bail!("unsupported archive format: {}", path.display());
    }
    Ok(files)
}

pub fn members(files: &BTreeMap<String, Content>) -> Vec<Member> {
    files
        .iter()
        .map(|(path, content)| Member {
            path: path.clone(),
            sha256: digest(&content.bytes),
            executable: content.executable,
        })
        .collect()
}

pub fn validate(path: &Path, expected: &BTreeMap<String, Content>) -> Result<Vec<Member>> {
    let actual = inspect(path)?;
    ensure!(
        &actual == expected,
        "archive bytes, permissions or exact member set differ: {}",
        path.display()
    );
    Ok(members(&actual))
}

pub fn extract(files: &BTreeMap<String, Content>, directory: &Path) -> Result<()> {
    fs::create_dir(directory)?;
    for (name, content) in files {
        let path = crate::config::safe_join(directory, name)?;
        fs::create_dir_all(path.parent().context("member has no parent")?)?;
        fs::write(&path, &content.bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                &path,
                fs::Permissions::from_mode(if content.executable { 0o755 } else { 0o644 }),
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_archive_formats_roundtrip_and_check_exact_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let expected = BTreeMap::from([
            (
                "bin/tool".into(),
                Content {
                    bytes: b"binary".to_vec(),
                    executable: true,
                },
            ),
            (
                "README.md".into(),
                Content {
                    bytes: b"resource".to_vec(),
                    executable: false,
                },
            ),
        ]);
        for suffix in ["tar.gz", "zip"] {
            let path = temp.path().join(format!("test.{suffix}"));
            write(&path, &expected).unwrap();
            assert_eq!(validate(&path, &expected).unwrap().len(), 2);
            let mut wrong = expected.clone();
            wrong.get_mut("README.md").unwrap().bytes.push(b'!');
            assert!(validate(&path, &wrong).is_err());
        }
    }

    #[test]
    fn unsafe_zip_member_fails() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("bad.zip");
        let mut zip = zip::ZipWriter::new(File::create(&path).unwrap());
        zip.start_file("../escape", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"bad").unwrap();
        zip.finish().unwrap();
        assert!(inspect(&path).is_err());
    }

    #[test]
    fn archive_modes_are_checked_before_runtime_normalization() {
        let temp = tempfile::tempdir().unwrap();
        for mode in [0o001, 0o777, 0o000, 0o666] {
            let path = temp.path().join(format!("mode-{mode}.tar.gz"));
            let mut tar = tar::Builder::new(GzEncoder::new(
                File::create(&path).unwrap(),
                Compression::default(),
            ));
            let mut header = tar::Header::new_gnu();
            header.set_size(1);
            header.set_mode(mode);
            header.set_cksum();
            tar.append_data(&mut header, "binary", b"x".as_slice())
                .unwrap();
            tar.into_inner().unwrap().finish().unwrap();
            assert!(inspect(&path).is_err(), "mode {mode:o}");
        }
    }

    #[test]
    fn duplicate_zip_headers_and_trailing_bytes_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("duplicate.zip");
        let files = BTreeMap::from([
            (
                "one".into(),
                Content {
                    bytes: b"a".to_vec(),
                    executable: false,
                },
            ),
            (
                "two".into(),
                Content {
                    bytes: b"b".to_vec(),
                    executable: false,
                },
            ),
        ]);
        write(&path, &files).unwrap();
        let original = fs::read(&path).unwrap();
        let mut bytes = original.clone();
        for index in 0..bytes.len() - 2 {
            if &bytes[index..index + 3] == b"two" {
                bytes[index..index + 3].copy_from_slice(b"one");
            }
        }
        fs::write(&path, bytes).unwrap();
        assert!(inspect(&path).is_err());
        let mut extra = original;
        extra.extend_from_slice(b"trailing");
        fs::write(&path, extra).unwrap();
        assert!(inspect(&path).is_err());
    }

    #[test]
    fn tar_duplicate_links_permissions_and_appended_streams_fail() {
        let temp = tempfile::tempdir().unwrap();
        for kind in ["duplicate", "symlink", "permissions"] {
            let path = temp.path().join(format!("{kind}.tar.gz"));
            let gzip = GzEncoder::new(File::create(&path).unwrap(), Compression::default());
            let mut builder = tar::Builder::new(gzip);
            let mut header = tar::Header::new_gnu();
            header.set_size(1);
            header.set_mode(if kind == "permissions" { 0o4755 } else { 0o644 });
            if kind == "symlink" {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_link_name("../outside").unwrap();
            }
            header.set_cksum();
            builder
                .append_data(&mut header, "entry", b"a".as_slice())
                .unwrap();
            if kind == "duplicate" {
                builder
                    .append_data(&mut header, "entry", b"b".as_slice())
                    .unwrap();
            }
            builder.into_inner().unwrap().finish().unwrap();
            assert!(inspect(&path).is_err(), "{kind}");
        }
        let path = temp.path().join("appended.tar.gz");
        let files = BTreeMap::from([(
            "entry".into(),
            Content {
                bytes: b"a".to_vec(),
                executable: false,
            },
        )]);
        write(&path, &files).unwrap();
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"trailing")
            .unwrap();
        assert!(inspect(&path).is_err());
    }
}
