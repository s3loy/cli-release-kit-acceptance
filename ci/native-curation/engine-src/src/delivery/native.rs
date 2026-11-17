//! Reproducible invocation of the pinned native packaging backend.
use super::{
    inspect::{self, ArtifactInspection},
    model::{Format, NFPM_VERSION, PackageSpec, PayloadManifest},
};
use crate::{process, source};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeTool {
    pub path: PathBuf,
    pub version: String,
    pub sha256: String,
}

pub fn resolve_nfpm(requested: Option<&Path>) -> Result<NativeTool> {
    let candidate = if let Some(path) = requested {
        path.to_path_buf()
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|p| p.join(if cfg!(windows) { "nfpm.exe" } else { "nfpm" }))
            .find(|p| p.is_file())
            .context("nFPM 2.49.0 is required; pass --nfpm or put nfpm on PATH")?
    };
    let path = fs::canonicalize(&candidate).context("resolve nFPM executable")?;
    ensure!(
        fs::metadata(&path)?.is_file(),
        "nFPM executable is not a regular file"
    );
    let before = source::file_digest(&path)?;
    let output = process::capture(
        &std::env::current_dir()?,
        &[path.to_string_lossy().into_owned(), "--version".into()],
        30,
    )?;
    let versions: Vec<_> = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("GitVersion:").map(str::trim))
        .collect();
    ensure!(
        versions == [NFPM_VERSION],
        "expected nFPM {NFPM_VERSION}, observed version output: {output}"
    );
    ensure!(
        source::file_digest(&path)? == before,
        "nFPM changed during version probe"
    );
    Ok(NativeTool {
        path,
        version: NFPM_VERSION.into(),
        sha256: before,
    })
}

#[derive(Serialize)]
struct Config<'a> {
    name: &'a str,
    arch: &'a str,
    platform: &'static str,
    version: String,
    version_schema: &'static str,
    prerelease: String,
    version_metadata: String,
    release: String,
    description: &'a str,
    license: &'a str,
    maintainer: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    homepage: Option<&'a str>,
    depends: &'a [String],
    contents: Vec<Content>,
    mtime: String,
    rpm: RpmConfig,
    deb: DebConfig<'a>,
    archlinux: ArchConfig<'a>,
}
#[derive(Serialize)]
struct DebConfig<'a> {
    fields: BTreeMap<&'static str, &'a str>,
}
#[derive(Serialize)]
struct RpmConfig {
    buildhost: &'static str,
    compression: &'static str,
}
#[derive(Serialize)]
struct ArchConfig<'a> {
    packager: &'a str,
}
#[derive(Serialize)]
struct Content {
    src: PathBuf,
    dst: String,
    file_info: FileInfo,
}
#[derive(Serialize)]
struct FileInfo {
    mode: u32,
    owner: &'static str,
    group: &'static str,
    mtime: String,
}

/// The pinned backend's semver parser separates these three fields.
pub(crate) fn version_parts(raw: &str) -> Result<(String, String, String)> {
    let raw = raw.strip_prefix('v').unwrap_or(raw);
    let (core_pre, meta) = raw.split_once('+').unwrap_or((raw, ""));
    let (core, pre) = core_pre.split_once('-').unwrap_or((core_pre, ""));
    let parts: Vec<_> = core.split('.').collect();
    ensure!(
        parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())),
        "native version must be a three-component semantic version"
    );
    for value in [pre, meta] {
        ensure!(
            value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'),
            "unsupported semantic version component"
        );
    }
    let normalized = parts
        .iter()
        .map(|v| v.parse::<u64>().map(|v| v.to_string()))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .join(".");
    Ok((normalized, pre.into(), meta.into()))
}

pub fn validate_version(_format: Format, version: &str) -> Result<()> {
    version_parts(version)?;
    Ok(())
}

pub fn version_for(format: Format, raw: &str, release: u32) -> Result<String> {
    let (mut value, pre, meta) = version_parts(raw)?;
    match format {
        Format::Deb | Format::Ipk => {
            if !pre.is_empty() {
                value.push('~');
                value.push_str(&pre);
            }
            if !meta.is_empty() {
                value.push('+');
                value.push_str(&meta);
            }
            value.push_str(&format!("-{release}"));
        }
        Format::Rpm => {
            if !pre.is_empty() {
                value.push('~');
                value.push_str(&pre.replace('-', "_"));
            }
            if !meta.is_empty() {
                value.push('+');
                value.push_str(&meta);
            }
        }
        Format::Apk => {
            if !pre.is_empty() {
                value.push('_');
                value.push_str(&pre);
            }
            value.push_str(&format!("-r{release}"));
            if !meta.is_empty() {
                value.push('-');
                if !["p", "cvs", "svn", "git", "hg"]
                    .iter()
                    .any(|p| meta.starts_with(p))
                {
                    value.push('p');
                }
                value.push_str(&meta);
            }
        }
        Format::Pacman => {
            value = raw.strip_prefix('v').unwrap_or(raw).replace('-', "_");
            value.push_str(&format!("-{release}"));
        }
        _ => {}
    }
    Ok(value)
}

pub(crate) fn native_version(spec: &PackageSpec) -> Result<String> {
    let value = version_for(spec.format, &spec.metadata.version, spec.metadata.release)?;
    ensure!(
        spec.native_version.as_deref() == Some(value.as_str()),
        "planned native version differs from fixed backend normalization"
    );
    Ok(value)
}

pub fn package(
    spec: &PackageSpec,
    payload_root: &Path,
    files: &PayloadManifest,
    tool: &NativeTool,
    output: &Path,
) -> Result<ArtifactInspection> {
    package_inner(spec, payload_root, files, tool, output, None)
}
pub(crate) fn package_with_profile(
    spec: &PackageSpec,
    profile: &crate::catalog::PackageProfile,
    payload_root: &Path,
    files: &PayloadManifest,
    tool: &NativeTool,
    output: &Path,
) -> Result<ArtifactInspection> {
    ensure!(
        profile.format == spec.format && profile.package_arch == spec.metadata.arch,
        "native package profile binding differs"
    );
    package_inner(spec, payload_root, files, tool, output, Some(profile))
}
fn package_inner(
    spec: &PackageSpec,
    payload_root: &Path,
    files: &PayloadManifest,
    tool: &NativeTool,
    output: &Path,
    profile: Option<&crate::catalog::PackageProfile>,
) -> Result<ArtifactInspection> {
    ensure!(
        spec.format.is_native(),
        "native backend received an archive format"
    );
    ensure!(
        spec.backend
            .as_ref()
            .is_some_and(|b| b.name == "nfpm" && b.version == NFPM_VERSION),
        "package plan does not pin nFPM {NFPM_VERSION}"
    );
    ensure!(
        tool.version == NFPM_VERSION && source::file_digest(&tool.path)? == tool.sha256,
        "nFPM identity changed"
    );
    ensure!(!output.try_exists()?, "package output already exists");
    let output = output
        .parent()
        .context("package output has no parent")?
        .canonicalize()?
        .join(output.file_name().context("package filename missing")?);
    ensure!(
        output.file_name().and_then(|s| s.to_str()) == Some(&spec.filename),
        "package output differs from planned filename"
    );
    let parent = output.parent().unwrap();
    let work = parent.join(format!(".native-{}", spec.id));
    let directory = &mut fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directory.mode(0o700);
    }
    directory
        .create(&work)
        .context("create fresh private native packaging work directory")?;
    let result = (|| {
        let stamp = timestamp(spec.source_epoch)?;
        let mut contents = Vec::new();
        ensure!(
            spec.install.len() == files.len(),
            "install mapping does not cover payload exactly"
        );
        let mut seen = std::collections::BTreeSet::new();
        for mapping in &spec.install {
            crate::config::relative(&mapping.source)?;
            crate::config::relative(&mapping.destination)?;
            ensure!(
                seen.insert(mapping.source.clone()),
                "duplicate mapped payload source"
            );
            let expected = files
                .get(&mapping.source)
                .context("mapping source absent from payload")?;
            let path = crate::config::safe_join(payload_root, &mapping.source)?;
            let meta = fs::symlink_metadata(&path)?;
            ensure!(
                meta.is_file()
                    && !meta.file_type().is_symlink()
                    && meta.len() == expected.size
                    && source::file_digest(&path)? == expected.sha256,
                "payload changed before native packaging"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                ensure!(
                    meta.permissions().mode() & 0o7777 == expected.mode,
                    "payload mode changed before native packaging"
                );
            }
            contents.push(Content {
                src: fs::canonicalize(path)?,
                dst: format!("/{}", mapping.destination),
                file_info: FileInfo {
                    mode: expected.mode,
                    owner: "root",
                    group: "root",
                    mtime: stamp.clone(),
                },
            });
        }
        let (mut version, mut prerelease, mut version_metadata) =
            version_parts(&spec.metadata.version)?;
        if spec.format == Format::Pacman {
            version = spec
                .metadata
                .version
                .strip_prefix('v')
                .unwrap_or(&spec.metadata.version)
                .replace('-', "_");
            prerelease.clear();
            version_metadata.clear();
        }
        native_version(spec)?;
        let cfg = Config {
            name: &spec.metadata.name,
            arch: profile
                .and_then(|p| p.nfpm_input_arch.as_deref())
                .unwrap_or(&spec.metadata.arch),
            platform: "linux",
            version,
            version_schema: "none",
            prerelease,
            version_metadata,
            release: spec.metadata.release.to_string(),
            description: spec
                .metadata
                .description
                .as_deref()
                .context("native description missing")?,
            license: spec
                .metadata
                .license
                .as_deref()
                .context("native license missing")?,
            maintainer: spec
                .metadata
                .maintainer
                .as_deref()
                .context("native maintainer missing")?,
            homepage: spec.metadata.homepage.as_deref(),
            depends: &spec.metadata.dependencies,
            contents,
            mtime: stamp,
            rpm: RpmConfig {
                buildhost: "relship",
                compression: "gzip",
            },
            deb: DebConfig {
                fields: BTreeMap::from([(
                    "X-License",
                    spec.metadata.license.as_deref().unwrap_or_default(),
                )]),
            },
            archlinux: ArchConfig {
                packager: spec.metadata.maintainer.as_deref().unwrap_or_default(),
            },
        };
        let config = work.join("nfpm.json");
        fs::write(&config, serde_json::to_vec_pretty(&cfg)?)?;
        let candidate = work.join(&spec.filename);
        let mut runner = process::Commands::new(&work, &work.join("logs"), 1200)?;
        runner.run(
            &[
                tool.path.to_string_lossy().into_owned(),
                "package".into(),
                "--config".into(),
                config.to_string_lossy().into_owned(),
                "--packager".into(),
                spec.format.nfpm_name().unwrap().into(),
                "--target".into(),
                candidate.to_string_lossy().into_owned(),
            ],
            "package",
            &BTreeMap::from([
                ("SOURCE_DATE_EPOCH".into(), spec.source_epoch.to_string()),
                ("TZ".into(), "UTC".into()),
            ]),
        )?;
        let produced: Vec<_> = fs::read_dir(&work)?
            .map(|v| v.map(|e| e.file_name()))
            .collect::<std::io::Result<_>>()?;
        ensure!(
            produced.len() == 3
                && produced
                    .iter()
                    .all(|p| p == "nfpm.json" || p == "logs" || p == spec.filename.as_str()),
            "backend produced unexpected files"
        );
        ensure!(
            source::file_digest(&tool.path)? == tool.sha256,
            "nFPM changed during packaging"
        );
        let inspection = match profile {
            Some(profile) => inspect::inspect_with_profile(spec, profile, &candidate, files)?,
            None => inspect::inspect(spec, &candidate, files)?,
        };
        fs::OpenOptions::new()
            .write(true)
            .open(&candidate)?
            .sync_all()?;
        fs::hard_link(&candidate, &output)
            .context("publish inspected package without replacing an existing file")?;
        Ok(inspection)
    })();
    // Keep failed backend logs available for diagnosis.
    if result.is_ok() {
        fs::remove_dir_all(&work)?;
    }
    result
}

/// Write delivery archives with the plan's timestamp and complete file modes.
pub fn package_archive(
    spec: &PackageSpec,
    payload_root: &Path,
    files: &PayloadManifest,
    output: &Path,
) -> Result<ArtifactInspection> {
    use std::io::Write;
    ensure!(
        !spec.format.is_native(),
        "archive writer received a native format"
    );
    ensure!(!output.try_exists()?, "archive output already exists");
    let out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    let load = |name: &str, expected: &super::model::PayloadEntry| -> Result<Vec<u8>> {
        let path = crate::config::safe_join(payload_root, name)?;
        let meta = fs::symlink_metadata(&path)?;
        ensure!(
            meta.is_file()
                && !meta.file_type().is_symlink()
                && meta.len() == expected.size
                && meta.len() <= inspect::FILE_LIMIT,
            "archive input is not the verified regular payload"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                meta.permissions().mode() & 0o7777 == expected.mode,
                "archive payload mode changed"
            );
        }
        let bytes = fs::read(path)?;
        ensure!(
            source::digest(&bytes) == expected.sha256 && expected.mode & !0o777 == 0,
            "archive input changed or unsafe mode"
        );
        Ok(bytes)
    };
    match spec.format {
        Format::TarGz => {
            let gzip = flate2::GzBuilder::new()
                .mtime(0)
                .write(out, flate2::Compression::default());
            let mut tar = tar::Builder::new(gzip);
            for (name, expected) in files {
                let bytes = load(name, expected)?;
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(expected.size);
                header.set_uid(0);
                header.set_gid(0);
                header.set_mode(expected.mode);
                header.set_mtime(spec.source_epoch);
                header.set_cksum();
                tar.append_data(&mut header, name, bytes.as_slice())?;
            }
            tar.into_inner()?.finish()?.sync_all()?;
        }
        Format::Zip => {
            let mut zip = zip::ZipWriter::new(out);
            for (name, expected) in files {
                let bytes = load(name, expected)?;
                zip.start_file(
                    name,
                    zip::write::SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Deflated)
                        .unix_permissions(expected.mode)
                        .last_modified_time(zip_time(spec.source_epoch)?),
                )?;
                zip.write_all(&bytes)?;
            }
            zip.finish()?.sync_all()?;
        }
        _ => unreachable!(),
    }
    inspect::inspect(spec, output, files)
}

pub(crate) fn zip_time(epoch: u64) -> Result<zip::DateTime> {
    // ZIP stores UTC calendar values with two-second resolution, starting in 1980.
    let stamp = timestamp(epoch.clamp(315532800, 4354819198))?;
    zip::DateTime::from_date_and_time(
        stamp[0..4].parse()?,
        stamp[5..7].parse()?,
        stamp[8..10].parse()?,
        stamp[11..13].parse()?,
        stamp[14..16].parse()?,
        stamp[17..19].parse::<u8>()? & !1,
    )
    .context("invalid ZIP timestamp")
}

fn timestamp(epoch: u64) -> Result<String> {
    ensure!(
        epoch <= 253402300799,
        "source timestamp exceeds RFC3339 range"
    );
    let days = (epoch / 86400) as i64 + 719468;
    let era = days / 146097;
    let doe = days - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        epoch / 3600 % 24,
        epoch / 60 % 60,
        epoch % 60
    ))
}
