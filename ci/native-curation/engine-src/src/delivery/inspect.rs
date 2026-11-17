//! Bounded, non-extracting readers for delivery artifacts.
use super::model::{Format, PackageMetadata, PackageSpec, PayloadEntry, PayloadManifest};
use anyhow::{Context, Result, bail, ensure};
use flate2::bufread::GzDecoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    path::Path,
};

pub const FILE_LIMIT: u64 = 512 * 1024 * 1024;
pub const TOTAL_LIMIT: u64 = 4 * 1024 * 1024 * 1024;
pub const METADATA_LIMIT: u64 = 16 * 1024 * 1024;
pub const MEMBER_LIMIT: usize = 20_000;
pub const BINARY_CONTENTS_LIMIT: u64 = 256 * 1024 * 1024;
type NativeFields = BTreeMap<String, Vec<String>>;
type ControlData = (NativeFields, Option<Vec<u8>>);
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactInspection {
    pub files: PayloadManifest,
    pub metadata: Option<PackageMetadata>,
    pub native_fields: BTreeMap<String, Vec<String>>,
}

pub fn expected_files(spec: &PackageSpec, payload: &PayloadManifest) -> Result<PayloadManifest> {
    if !spec.format.is_native() {
        return Ok(payload.clone());
    }
    let mut result = BTreeMap::new();
    let mut sources = BTreeSet::new();
    for mapping in &spec.install {
        crate::config::relative(&mapping.source)?;
        crate::config::relative(&mapping.destination)?;
        ensure!(sources.insert(&mapping.source), "duplicate install source");
        let entry = payload
            .get(&mapping.source)
            .context("unknown install source")?;
        ensure!(
            result
                .insert(mapping.destination.clone(), entry.clone())
                .is_none(),
            "duplicate install destination"
        );
    }
    ensure!(
        sources.len() == payload.len(),
        "install mapping does not cover exact payload"
    );
    check_names(result.keys().map(String::as_str))?;
    Ok(result)
}

pub fn inspect(
    spec: &PackageSpec,
    artifact: &Path,
    payload: &PayloadManifest,
) -> Result<ArtifactInspection> {
    inspect_inner(spec, artifact, payload, None, None).map(|(inspection, _)| inspection)
}
/// Protocol 5 supplies a canonical typed package profile; legacy entry points
/// retain their original architecture constraints.
pub(crate) fn inspect_with_profile(
    spec: &PackageSpec,
    profile: &crate::catalog::PackageProfile,
    artifact: &Path,
    payload: &PayloadManifest,
) -> Result<ArtifactInspection> {
    validate_profile(spec, profile)?;
    inspect_inner(
        spec,
        artifact,
        payload,
        Some(profile.inspection_profile),
        None,
    )
    .map(|(inspection, _)| inspection)
}
/// Collect selected payload bytes only after the complete package passes the
/// same static inspection as `inspect_with_profile`. Paths name final package
/// members, including install destinations for native packages.
pub fn inspect_binary_contents(
    spec: &PackageSpec,
    profile: &crate::catalog::PackageProfile,
    artifact: &Path,
    payload: &PayloadManifest,
    requested: &BTreeSet<String>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    validate_profile(spec, profile)?;
    inspect_inner(
        spec,
        artifact,
        payload,
        Some(profile.inspection_profile),
        Some(requested),
    )
    .map(|(_, contents)| contents)
}
fn validate_profile(spec: &PackageSpec, profile: &crate::catalog::PackageProfile) -> Result<()> {
    let target = crate::catalog::resolve(&profile.target)?;
    ensure!(
        crate::catalog::package_support(&target, spec.format)? == *profile
            && profile.format == spec.format
            && profile.package_arch == spec.metadata.arch,
        "package inspection profile differs from canonical catalog contract"
    );
    Ok(())
}
fn inspect_inner(
    spec: &PackageSpec,
    artifact: &Path,
    payload: &PayloadManifest,
    profile: Option<crate::catalog::InspectionProfile>,
    requested: Option<&BTreeSet<String>>,
) -> Result<(ArtifactInspection, BTreeMap<String, Vec<u8>>)> {
    let meta = fs::symlink_metadata(artifact)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "artifact must be a regular file"
    );
    ensure!(
        meta.len() <= TOTAL_LIMIT,
        "artifact exceeds package size limit"
    );
    let expected = expected_files(spec, payload)?;
    let mut state = State::new(&expected, spec.source_epoch);
    state.capture = requested
        .map(|requested| BinaryContents::new(&expected, requested))
        .transpose()?;
    state.apk_data = spec.format == Format::Apk;
    let fields = match spec.format {
        Format::TarGz => {
            let mut input = BufReader::new(File::open(artifact)?);
            gzip_tar(&mut input, &mut state, &[])?;
            ensure!(
                input.fill_buf()?.is_empty(),
                "extra gzip stream or trailing bytes"
            );
            BTreeMap::new()
        }
        Format::Zip => {
            zip_payload(artifact, &mut state)?;
            BTreeMap::new()
        }
        Format::Deb => deb(artifact, &mut state, spec)?,
        Format::Ipk => ipk(artifact, &mut state, spec)?,
        Format::Apk => apk(artifact, &mut state, spec)?,
        Format::Pacman => pacman(artifact, &mut state, spec)?,
        Format::Rpm => rpm(artifact, &mut state, spec, profile)?,
    };
    ensure!(
        state.files == expected,
        "package payload differs in exact paths, bytes, sizes or complete modes"
    );
    let contents = state
        .capture
        .map(|capture| capture.files)
        .unwrap_or_default();
    Ok((
        ArtifactInspection {
            files: state.files,
            metadata: spec.format.is_native().then(|| spec.metadata.clone()),
            native_fields: fields,
        },
        contents,
    ))
}

fn check_names<'a>(names: impl Iterator<Item = &'a str>) -> Result<()> {
    let mut folded = BTreeSet::new();
    for name in names {
        crate::config::relative(name)?;
        ensure!(
            folded.insert(name.to_lowercase()),
            "case-colliding package paths"
        );
    }
    Ok(())
}
struct BinaryContents<'a> {
    requested: &'a BTreeSet<String>,
    files: BTreeMap<String, Vec<u8>>,
}
impl<'a> BinaryContents<'a> {
    fn new(expected: &PayloadManifest, requested: &'a BTreeSet<String>) -> Result<Self> {
        let mut total = 0u64;
        for name in requested {
            let entry = expected
                .get(name)
                .with_context(|| format!("unknown requested package payload: {name}"))?;
            total = total
                .checked_add(entry.size)
                .context("binary contents size overflow")?;
            ensure!(
                total <= BINARY_CONTENTS_LIMIT,
                "requested binary contents exceed capture limit"
            );
        }
        Ok(Self {
            requested,
            files: BTreeMap::new(),
        })
    }
}
struct State<'a> {
    expected: &'a PayloadManifest,
    files: PayloadManifest,
    names: BTreeSet<String>,
    parents: BTreeSet<String>,
    dirs: BTreeSet<String>,
    total: u64,
    members: usize,
    epoch: u64,
    apk_data: bool,
    md5: BTreeMap<String, String>,
    sha1: BTreeMap<String, String>,
    capture: Option<BinaryContents<'a>>,
}
impl<'a> State<'a> {
    fn new(expected: &'a PayloadManifest, epoch: u64) -> Self {
        let mut parents = BTreeSet::new();
        for path in expected.keys() {
            let mut p = Path::new(path).parent();
            while let Some(v) = p {
                if v.as_os_str().is_empty() {
                    break;
                }
                parents.insert(v.to_string_lossy().into_owned());
                p = v.parent();
            }
        }
        Self {
            expected,
            files: BTreeMap::new(),
            names: BTreeSet::new(),
            parents,
            dirs: BTreeSet::new(),
            total: 0,
            members: 0,
            epoch,
            apk_data: false,
            md5: BTreeMap::new(),
            sha1: BTreeMap::new(),
            capture: None,
        }
    }
    fn budget(&mut self, size: u64) -> Result<()> {
        self.members += 1;
        ensure!(self.members <= MEMBER_LIMIT, "too many package members");
        ensure!(size <= FILE_LIMIT, "package member exceeds file limit");
        self.total = self
            .total
            .checked_add(size)
            .context("package size overflow")?;
        ensure!(
            self.total <= TOTAL_LIMIT,
            "package uncompressed size exceeds limit"
        );
        Ok(())
    }
    fn member(&mut self, name: &str, size: u64) -> Result<()> {
        self.budget(size)?;
        ensure!(
            self.names.insert(name.to_lowercase()),
            "duplicate or case-colliding package member: {name}"
        );
        Ok(())
    }
    fn file(&mut self, name: &str, size: u64, mode: u32, reader: impl Read) -> Result<()> {
        let expected = self
            .expected
            .get(name)
            .with_context(|| format!("unexpected package payload: {name}"))?;
        ensure!(mode & !0o777 == 0, "special file permissions on {name}");
        ensure!(
            mode == expected.mode && size == expected.size,
            "package file mode/size mismatch: {name}"
        );
        let mut contents = self
            .capture
            .as_ref()
            .filter(|capture| capture.requested.contains(name))
            .map(|_| Vec::new());
        let (actual, md5, sha1) = payload_hashes(reader, size, contents.as_mut())?;
        self.md5.insert(name.into(), md5);
        self.sha1.insert(name.into(), sha1);
        ensure!(
            actual == expected.sha256,
            "package payload digest mismatch: {name}"
        );
        self.files.insert(
            name.into(),
            PayloadEntry {
                size,
                mode,
                sha256: actual,
            },
        );
        if let Some(contents) = contents {
            self.capture
                .as_mut()
                .context("binary contents capture is unavailable")?
                .files
                .insert(name.into(), contents);
        }
        Ok(())
    }
}
fn payload_hashes(
    mut reader: impl Read,
    size: u64,
    mut contents: Option<&mut Vec<u8>>,
) -> Result<(String, String, String)> {
    let mut sha256 = Sha256::new();
    let mut md5 = md5::Md5::new();
    let mut sha1 = sha1::Sha1::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        ensure!(count <= size, "member exceeds declared size");
        sha256.update(&buffer[..n]);
        md5.update(&buffer[..n]);
        sha1.update(&buffer[..n]);
        if let Some(contents) = contents.as_deref_mut() {
            contents.extend_from_slice(&buffer[..n]);
        }
    }
    ensure!(count == size, "truncated package member");
    Ok((
        format!("{:x}", sha256.finalize()),
        format!("{:x}", md5.finalize()),
        format!("{:x}", sha1.finalize()),
    ))
}
fn hash_reader(mut reader: impl Read, expected: u64) -> Result<String> {
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count += n as u64;
        ensure!(count <= expected, "member exceeds declared size");
        hash.update(&buffer[..n]);
    }
    ensure!(count == expected, "truncated package member");
    Ok(format!("{:x}", hash.finalize()))
}
fn bytes(reader: impl Read, size: u64, limit: u64) -> Result<Vec<u8>> {
    ensure!(size <= limit, "package metadata exceeds limit");
    let mut result = Vec::new();
    reader.take(limit + 1).read_to_end(&mut result)?;
    ensure!(
        result.len() as u64 == size && result.len() as u64 <= limit,
        "metadata size mismatch"
    );
    Ok(result)
}
fn canonical(raw: &[u8], directory: bool) -> Result<String> {
    ensure!(raw.len() <= 4096, "package path exceeds 4096-byte limit");
    let raw = std::str::from_utf8(raw).context("non-UTF8 package path")?;
    let raw = raw.strip_prefix("./").unwrap_or(raw);
    let raw = if directory {
        raw.strip_suffix('/').unwrap_or(raw)
    } else {
        raw
    };
    if directory && (raw.is_empty() || raw == ".") {
        return Ok(String::new());
    }
    crate::config::relative(raw)?;
    Ok(raw.into())
}
fn zero_tail(mut reader: impl Read) -> Result<()> {
    let mut count = 0;
    let mut buf = [0u8; 4096];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        count += n;
        ensure!(
            count <= 1024 * 1024 && buf[..n].iter().all(|b| *b == 0),
            "unexpected data after tar end"
        );
    }
    Ok(())
}
#[derive(Default)]
struct TarExtension {
    path: Option<String>,
    apk_sha1: Option<String>,
    apk_target_hint: Option<String>,
}
fn pax_extension(data: &[u8], apk: bool, header_name: &[u8]) -> Result<TarExtension> {
    let mut result = TarExtension::default();
    let mut remaining = data;
    let mut count = 0;
    while !remaining.is_empty() {
        count += 1;
        ensure!(count <= 2, "too many PAX attributes");
        let space = remaining
            .iter()
            .position(|b| *b == b' ')
            .context("invalid PAX length")?;
        ensure!(
            remaining[..space].iter().all(u8::is_ascii_digit),
            "invalid PAX length"
        );
        let length = std::str::from_utf8(&remaining[..space])?.parse::<usize>()?;
        ensure!(
            length > space + 2 && length <= remaining.len(),
            "PAX record length differs"
        );
        let record = std::str::from_utf8(&remaining[space + 1..length])?
            .strip_suffix('\n')
            .context("PAX record lacks newline")?;
        let (key, value) = record.split_once('=').context("invalid PAX attribute")?;
        match key {
            "path" => {
                ensure!(
                    result.path.is_none() && !value.is_empty() && value.len() <= 4096,
                    "invalid or duplicate PAX path"
                );
                canonical(value.as_bytes(), value.ends_with('/'))?;
                result.path = Some(value.into());
            }
            "APK-TOOLS.checksum.SHA1" if apk => {
                ensure!(
                    result.apk_sha1.is_none()
                        && value.len() == 40
                        && value.chars().all(|c| c.is_ascii_hexdigit()),
                    "invalid or duplicate APK PAX SHA1"
                );
                result.apk_sha1 = Some(value.into());
            }
            _ => bail!("unexpected PAX attribute: {key}"),
        }
        remaining = &remaining[length..];
    }
    ensure!(
        result.path.is_some() || result.apk_sha1.is_some(),
        "empty PAX metadata"
    );
    if result.apk_sha1.is_some() && result.path.is_none() {
        let name = canonical(header_name, false)?;
        let path = Path::new(&name);
        let parent = path.parent().context("invalid APK PAX path")?;
        ensure!(
            parent.file_name().is_some_and(|p| p == "PaxHeaders.0"),
            "unexpected APK PAX path"
        );
        result.apk_target_hint = Some(
            parent
                .parent()
                .unwrap_or(Path::new(""))
                .join(path.file_name().context("APK PAX filename missing")?)
                .to_string_lossy()
                .into_owned(),
        );
    }
    Ok(result)
}
fn tar_scan(
    reader: &mut dyn Read,
    state: &mut State<'_>,
    controls: &[&str],
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut archive = tar::Archive::new(reader);
    let mut found = BTreeMap::new();
    let mut extension: Option<TarExtension> = None;
    for item in archive.entries()?.raw(true) {
        let item = item?;
        let header = item.header();
        let kind = header.entry_type().as_byte();
        if kind == b'L' || kind == b'x' {
            ensure!(
                extension.is_none(),
                "consecutive or conflicting tar extension headers"
            );
            ensure!(
                header.uid()? == 0 && header.gid()? == 0 && header.mode()? & !0o777 == 0,
                "unsafe tar extension envelope"
            );
            let size = item.size();
            state.budget(size)?;
            if kind == b'L' {
                ensure!(
                    item.path_bytes().as_ref() == b"././@LongLink"
                        || item.path_bytes().as_ref() == b"@LongLink",
                    "unexpected GNU long-name control path"
                );
                let data = bytes(item, size, 4097)?;
                let path = data
                    .strip_suffix(&[0])
                    .context("GNU long name lacks NUL terminator")?;
                let path = std::str::from_utf8(path)?;
                canonical(path.as_bytes(), path.ends_with('/'))?;
                extension = Some(TarExtension {
                    path: Some(path.into()),
                    ..Default::default()
                });
            } else {
                let header_name = item.path_bytes().into_owned();
                extension = Some(pax_extension(
                    &bytes(item, size, 8192)?,
                    state.apk_data,
                    &header_name,
                )?);
            }
            continue;
        }
        let is_dir = header.entry_type().is_dir();
        ensure!(
            is_dir || header.entry_type().is_file(),
            "links, devices, scripts and unsupported tar headers are forbidden"
        );
        let pending = extension.take();
        let name = if let Some(path) = pending.as_ref().and_then(|v| v.path.as_ref()) {
            canonical(path.as_bytes(), is_dir)?
        } else {
            canonical(&item.path_bytes(), is_dir)?
        };
        let mode = header.mode()?;
        ensure!(mode & !0o777 == 0, "special permission bits");
        ensure!(
            header.uid()? == 0
                && header.gid()? == 0
                && header
                    .username()?
                    .is_none_or(|v| v.is_empty() || v == "root")
                && header
                    .groupname()?
                    .is_none_or(|v| v.is_empty() || v == "root"),
            "package member owner must be root"
        );
        let size = item.size();
        state.member(&name, size)?;
        if is_dir {
            ensure!(
                pending.as_ref().is_none_or(|v| v.apk_sha1.is_none()),
                "APK checksum must precede a regular file"
            );
            ensure!(
                size == 0 && mode == 0o755 && (name.is_empty() || state.parents.contains(&name)),
                "unexpected directory or mode: {name}"
            );
            ensure!(
                header.mtime()? == state.epoch,
                "package directory timestamp mismatch"
            );
            state.dirs.insert(name);
        } else if controls.contains(&name.as_str()) {
            ensure!(
                pending.is_none(),
                "unexpected tar extensions on native control files"
            );
            let apk_control = controls == [".PKGINFO"];
            ensure!(
                mode == if apk_control { 0o600 } else { 0o644 },
                "unexpected control mode"
            );
            ensure!(
                header.mtime()? == if apk_control { 0 } else { state.epoch },
                "control timestamp differs"
            );
            found.insert(name, bytes(item, size, METADATA_LIMIT)?);
        } else {
            ensure!(
                header.mtime()? == state.epoch,
                "package file timestamp mismatch"
            );
            state.file(&name, size, mode, item)?;
            if state.apk_data {
                let pending = pending.context("APK payload missing checksum PAX record")?;
                let expected_sha1 = pending
                    .apk_sha1
                    .context("APK payload missing checksum PAX attribute")?;
                ensure!(
                    pending.apk_target_hint.as_ref().is_none_or(|v| v == &name)
                        && state.sha1.get(&name) == Some(&expected_sha1),
                    "APK PAX target/SHA1 differs from actual file"
                );
            }
        }
    }
    ensure!(extension.is_none(), "orphan tar extension header");
    zero_tail(archive.into_inner())?;
    Ok(found)
}

fn gzip_tar(
    reader: &mut dyn BufRead,
    state: &mut State<'_>,
    controls: &[&str],
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut decoder = GzDecoder::new(reader);
    tar_scan(&mut decoder, state, controls)
}
fn zip_preflight(path: &Path) -> Result<()> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    ensure!(size >= 22, "truncated ZIP envelope");
    file.seek(SeekFrom::End(-22))?;
    let mut eocd = [0u8; 22];
    file.read_exact(&mut eocd)?;
    ensure!(
        &eocd[..4] == b"PK\x05\x06" && eocd[4..8] == [0; 4] && eocd[20..22] == [0; 2],
        "unsupported ZIP end record"
    );
    let count = u16::from_le_bytes(eocd[10..12].try_into()?) as usize;
    ensure!(
        count <= MEMBER_LIMIT && eocd[8..10] == eocd[10..12],
        "ZIP central record count exceeds limit"
    );
    let central_size = u32::from_le_bytes(eocd[12..16].try_into()?) as u64;
    let offset = u32::from_le_bytes(eocd[16..20].try_into()?) as u64;
    ensure!(
        central_size <= METADATA_LIMIT && offset + central_size + 22 == size,
        "ZIP central metadata exceeds limit or has unaccounted bytes"
    );
    Ok(())
}
fn zip_payload(path: &Path, state: &mut State<'_>) -> Result<()> {
    zip_preflight(path)?;
    let mut zip = zip::ZipArchive::new(File::open(path)?)?;
    ensure!(
        zip.offset() == 0 && zip.comment().is_empty() && zip.len() <= MEMBER_LIMIT,
        "unsupported ZIP envelope"
    );
    let directory = zip.central_directory_start();
    let mut central = directory;
    for i in 0..zip.len() {
        let entry = zip.by_index(i)?;
        ensure!(
            entry.is_file()
                && entry.extra_data().unwrap_or_default().is_empty()
                && entry.comment().is_empty(),
            "unsupported ZIP member metadata"
        );
        ensure!(
            entry.central_header_start() == central,
            "duplicate or unaccounted ZIP central records"
        );
        central += 46 + entry.name_raw().len() as u64;
        let name = canonical(entry.name_raw(), false)?;
        state.member(&name, entry.size())?;
        ensure!(
            entry.last_modified() == Some(super::native::zip_time(state.epoch)?),
            "ZIP timestamp differs from plan"
        );
        let mode = entry.unix_mode().context("ZIP has no Unix permissions")?;
        ensure!(
            mode & 0o170000 == 0o100000 && mode & 0o7000 == 0,
            "nonregular ZIP file mode"
        );
        state.file(&name, entry.size(), mode & 0o777, entry)?;
    }
    ensure!(
        central + 22 == fs::metadata(path)?.len(),
        "ZIP contains unaccounted directory or trailing bytes"
    );
    let mut physical = File::open(path)?;
    let mut seen = BTreeSet::new();
    while let Some(entry) = zip::read::read_zipfile_from_stream(&mut physical)? {
        let name = canonical(entry.name_raw(), false)?;
        ensure!(
            seen.insert(name.clone()) && seen.len() <= MEMBER_LIMIT,
            "duplicate ZIP local member"
        );
        let expected = state
            .files
            .get(&name)
            .context("ZIP local member absent from central directory")?;
        ensure!(
            entry.last_modified() == Some(super::native::zip_time(state.epoch)?),
            "ZIP local/central timestamp differs"
        );
        ensure!(
            entry.size() == expected.size,
            "ZIP local/central sizes differ"
        );
        ensure!(
            hash_reader(entry, expected.size)? == expected.sha256,
            "ZIP local/central bytes differ"
        );
    }
    ensure!(
        seen.len() == state.files.len() && physical.stream_position()? == directory + 4,
        "ZIP local/central file sets differ"
    );
    Ok(())
}

fn deb_preflight(path: &Path) -> Result<()> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)?;
    ensure!(&magic == b"!<arch>\n", "invalid Debian ar envelope");
    for expected in ["debian-binary", "control.tar.gz", "data.tar.gz"] {
        let mut header = [0u8; 60];
        file.read_exact(&mut header)?;
        ensure!(&header[58..] == b"`\n", "invalid Debian ar member header");
        let name = std::str::from_utf8(&header[..16])?.trim_end_matches(' ');
        let name = name.strip_suffix('/').unwrap_or(name);
        // Reject GNU/BSD filename and symbol tables before ar-rs can allocate them.
        ensure!(name == expected, "unexpected or reordered Debian ar member");
        let length = std::str::from_utf8(&header[48..58])?
            .trim()
            .parse::<u64>()?;
        ensure!(length <= TOTAL_LIMIT, "Debian ar member exceeds size limit");
        let end = file
            .stream_position()?
            .checked_add(length)
            .context("Debian ar member offset overflow")?;
        ensure!(end <= size, "truncated Debian ar member");
        file.seek(SeekFrom::Start(end))?;
        if length % 2 != 0 {
            let mut padding = [0u8; 1];
            file.read_exact(&mut padding)?;
            ensure!(padding == [b'\n'], "invalid Debian ar padding");
        }
    }
    ensure!(
        file.stream_position()? == size,
        "extra Debian ar records or trailing bytes"
    );
    Ok(())
}
fn deb(
    path: &Path,
    state: &mut State<'_>,
    spec: &PackageSpec,
) -> Result<BTreeMap<String, Vec<String>>> {
    deb_preflight(path)?;
    let mut archive = ar::Archive::new(File::open(path)?);
    let mut seen = BTreeSet::new();
    let mut control = None;
    while let Some(item) = archive.next_entry() {
        let mut item = item?;
        let name = std::str::from_utf8(item.header().identifier())?
            .trim_end_matches('/')
            .to_owned();
        ensure!(seen.insert(name.clone()), "duplicate deb ar member");
        ensure!(item.header().size() <= TOTAL_LIMIT, "deb member too large");
        ensure!(
            item.header().uid() == 0
                && item.header().gid() == 0
                && item.header().mode() & 0o7777 == 0o644
                && item.header().mtime() == spec.source_epoch,
            "unsafe deb outer ownership/mode/timestamp"
        );
        match name.as_str() {
            "debian-binary" => ensure!(
                bytes(&mut item, 4, 4)? == b"2.0\n",
                "unsupported deb format"
            ),
            "control.tar.gz" => {
                let mut input = BufReader::new(&mut item);
                control = Some(control_tar(
                    &mut input,
                    spec,
                    state.expected.values().map(|v| v.size).sum(),
                )?);
                ensure!(input.fill_buf()?.is_empty(), "extra control gzip data");
            }
            "data.tar.gz" => {
                let mut input = BufReader::new(&mut item);
                gzip_tar(&mut input, state, &[])?;
                ensure!(input.fill_buf()?.is_empty(), "extra data gzip stream");
            }
            _ => bail!("unsupported deb ar member: {name}"),
        }
    }
    ensure!(
        seen == BTreeSet::from([
            "debian-binary".into(),
            "control.tar.gz".into(),
            "data.tar.gz".into()
        ]),
        "deb member set differs"
    );
    let (fields, sums) = control.context("missing deb control")?;
    validate_md5sums(sums.as_deref().context("missing Debian checksums")?, state)?;
    Ok(fields)
}
fn ipk(
    path: &Path,
    state: &mut State<'_>,
    spec: &PackageSpec,
) -> Result<BTreeMap<String, Vec<String>>> {
    let mut input = BufReader::new(File::open(path)?);
    let mut gzip = GzDecoder::new(&mut input);
    let mut archive = tar::Archive::new(&mut gzip);
    let mut seen = BTreeSet::new();
    let mut control = None;
    for item in archive.entries()?.raw(true) {
        let mut item = item?;
        ensure!(
            item.header().entry_type().is_file(),
            "nonregular IPK outer member"
        );
        ensure!(
            item.header().uid()? == 0
                && item.header().gid()? == 0
                && item.header().mode()? == 0o644,
            "unsafe IPK outer ownership or mode"
        );
        ensure!(
            item.header().mtime()? == spec.source_epoch,
            "IPK outer timestamp differs"
        );
        let name = canonical(&item.path_bytes(), false)?;
        ensure!(seen.insert(name.clone()), "duplicate IPK outer member");
        ensure!(item.size() <= TOTAL_LIMIT, "IPK outer member too large");
        match name.as_str() {
            "debian-binary" => ensure!(
                bytes(&mut item, 4, 4)? == b"2.0\n",
                "unsupported IPK format"
            ),
            "control.tar.gz" => {
                let mut inner = BufReader::new(&mut item);
                control = Some(control_tar(
                    &mut inner,
                    spec,
                    state.expected.values().map(|v| v.size).sum(),
                )?);
                ensure!(inner.fill_buf()?.is_empty(), "extra IPK control stream");
            }
            "data.tar.gz" => {
                let mut inner = BufReader::new(&mut item);
                gzip_tar(&mut inner, state, &[])?;
                ensure!(inner.fill_buf()?.is_empty(), "extra IPK data stream");
            }
            _ => bail!("unexpected IPK outer member"),
        }
    }
    zero_tail(archive.into_inner())?;
    ensure!(input.fill_buf()?.is_empty(), "extra IPK gzip stream");
    ensure!(
        seen == BTreeSet::from([
            "debian-binary".into(),
            "control.tar.gz".into(),
            "data.tar.gz".into()
        ]),
        "IPK member set differs"
    );
    Ok(control.context("missing IPK control")?.0)
}
fn control_tar(
    reader: &mut dyn BufRead,
    spec: &PackageSpec,
    installed_bytes: u64,
) -> Result<ControlData> {
    let empty = BTreeMap::new();
    let mut state = State::new(&empty, spec.source_epoch);
    let expected_controls = if spec.format == Format::Deb {
        ["control", "md5sums"]
    } else {
        ["control", "conffiles"]
    };
    let controls = gzip_tar(reader, &mut state, &expected_controls)?;
    ensure!(controls.len() == 2, "native control member set differs");
    if spec.format == Format::Ipk {
        ensure!(
            controls
                .get("conffiles")
                .is_some_and(|v| v.is_empty() || v == b"\n"),
            "IPK config files are outside this profile"
        );
    }
    let fields = colon_fields(controls.get("control").context("missing package control")?)?;
    let allowed = if spec.format == Format::Deb {
        vec![
            "Package",
            "Version",
            "Section",
            "Priority",
            "Architecture",
            "Maintainer",
            "Installed-Size",
            "Description",
            "Homepage",
            "Depends",
            "X-License",
        ]
    } else {
        vec![
            "Package",
            "Version",
            "Section",
            "Priority",
            "Architecture",
            "Maintainer",
            "Installed-Size",
            "Description",
            "Homepage",
            "Depends",
            "License",
        ]
    };
    allowed_fields(&fields, &allowed, &[])?;
    value(&fields, "Package", &spec.metadata.name)?;
    value(&fields, "Version", &super::native::native_version(spec)?)?;
    value(&fields, "Architecture", &spec.metadata.arch)?;
    optional_value(&fields, "Description", spec.metadata.description.as_deref())?;
    optional_value(&fields, "Maintainer", spec.metadata.maintainer.as_deref())?;
    optional_value(&fields, "Homepage", spec.metadata.homepage.as_deref())?;
    if spec.format == Format::Ipk {
        optional_value(&fields, "License", spec.metadata.license.as_deref())?;
    } else {
        optional_value(&fields, "X-License", spec.metadata.license.as_deref())?;
    }
    value(&fields, "Priority", "optional")?;
    if spec.format == Format::Deb {
        value(&fields, "Section", "")?;
    } else {
        ensure!(!fields.contains_key("Section"), "unexpected IPK section");
    }
    let installed_kib = installed_bytes / 1024;
    if spec.format == Format::Deb || installed_kib > 0 {
        ensure!(
            numeric(&fields, "Installed-Size")? == installed_kib,
            "native installed size differs"
        );
    } else {
        ensure!(
            !fields.contains_key("Installed-Size"),
            "unexpected zero IPK installed size"
        );
    }
    let actual = fields
        .get("Depends")
        .map(|v| {
            v[0].split(',')
                .map(str::trim)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    ensure!(
        actual == spec.metadata.dependencies,
        "native dependency fields differ"
    );
    Ok((fields, controls.get("md5sums").cloned()))
}
fn validate_md5sums(data: &[u8], state: &State<'_>) -> Result<()> {
    let mut seen = BTreeSet::new();
    for line in std::str::from_utf8(data)?.lines() {
        let (hash, path) = line
            .split_once("  ")
            .context("invalid Debian md5sums record")?;
        crate::config::relative(path)?;
        ensure!(
            seen.insert(path) && state.md5.get(path).is_some_and(|v| v == hash),
            "Debian checksum metadata differs from actual payload"
        );
    }
    ensure!(
        seen.len() == state.files.len(),
        "Debian checksum member set differs"
    );
    Ok(())
}
fn colon_fields(bytes: &[u8]) -> Result<BTreeMap<String, Vec<String>>> {
    let text = std::str::from_utf8(bytes)?;
    let mut result: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut last = None;
    for line in text.lines() {
        ensure!(
            !line.contains('\r') && !line.contains('\0'),
            "invalid control character"
        );
        if let Some(cont) = line.strip_prefix(' ') {
            let key: &String = last
                .as_ref()
                .context("control continuation without field")?;
            let target = &mut result.get_mut(key).unwrap()[0];
            target.push('\n');
            target.push_str(if cont == "." { "" } else { cont });
        } else {
            ensure!(!line.is_empty(), "unexpected control paragraph");
            let (key, value) = line
                .split_once(':')
                .context("malformed package control field")?;
            ensure!(
                !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "invalid control key"
            );
            ensure!(
                result
                    .insert(key.into(), vec![value.trim_start_matches(' ').to_owned()])
                    .is_none(),
                "duplicate package control field"
            );
            last = Some(key.to_owned());
        }
    }
    Ok(result)
}
fn equals_fields(bytes: &[u8]) -> Result<BTreeMap<String, Vec<String>>> {
    let mut result = BTreeMap::<String, Vec<String>>::new();
    for line in std::str::from_utf8(bytes)?.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        ensure!(
            !line.chars().any(|c| c.is_control()),
            "invalid metadata control character"
        );
        let (key, value) = line
            .split_once(" = ")
            .context("invalid native metadata field")?;
        result.entry(key.into()).or_default().push(value.into());
    }
    Ok(result)
}
fn allowed_fields(
    fields: &BTreeMap<String, Vec<String>>,
    allowed: &[&str],
    repeated: &[&str],
) -> Result<()> {
    for (key, values) in fields {
        ensure!(
            allowed.contains(&key.as_str()),
            "unexpected native metadata field: {key}"
        );
        ensure!(
            repeated.contains(&key.as_str()) || values.len() == 1,
            "repeated singleton native metadata field: {key}"
        );
    }
    Ok(())
}
fn value(fields: &BTreeMap<String, Vec<String>>, key: &str, expected: &str) -> Result<()> {
    ensure!(
        fields.get(key).is_some_and(|v| v == &[expected]),
        "native metadata {key} differs from plan"
    );
    Ok(())
}
fn optional_value(
    fields: &BTreeMap<String, Vec<String>>,
    key: &str,
    expected: Option<&str>,
) -> Result<()> {
    if let Some(v) = expected.filter(|v| !v.is_empty()) {
        value(fields, key, v)
    } else {
        ensure!(
            !fields.contains_key(key),
            "unexpected native metadata {key}"
        );
        Ok(())
    }
}
fn numeric(fields: &BTreeMap<String, Vec<String>>, key: &str) -> Result<u64> {
    fields
        .get(key)
        .and_then(|v| v.first())
        .context("missing numeric metadata")?
        .parse::<u64>()
        .context("invalid numeric metadata")
}
fn apk(
    path: &Path,
    state: &mut State<'_>,
    spec: &PackageSpec,
) -> Result<BTreeMap<String, Vec<String>>> {
    let mut input = BufReader::new(File::open(path)?);
    let empty = BTreeMap::new();
    let mut control_state = State::new(&empty, spec.source_epoch);
    let controls = gzip_tar(&mut input, &mut control_state, &[".PKGINFO"])?;
    ensure!(
        controls.len() == 1,
        "APK control segment must contain only .PKGINFO"
    );
    let fields = equals_fields(controls.get(".PKGINFO").context("missing APK metadata")?)?;
    allowed_fields(
        &fields,
        &[
            "pkgname",
            "pkgver",
            "arch",
            "size",
            "pkgdesc",
            "url",
            "maintainer",
            "license",
            "depend",
            "datahash",
        ],
        &["depend"],
    )?;
    value(&fields, "pkgname", &spec.metadata.name)?;
    value(&fields, "pkgver", &super::native::native_version(spec)?)?;
    value(&fields, "arch", &spec.metadata.arch)?;
    optional_value(&fields, "pkgdesc", spec.metadata.description.as_deref())?;
    optional_value(&fields, "url", spec.metadata.homepage.as_deref())?;
    optional_value(&fields, "maintainer", spec.metadata.maintainer.as_deref())?;
    optional_value(&fields, "license", spec.metadata.license.as_deref())?;
    ensure!(
        fields.get("depend").cloned().unwrap_or_default() == spec.metadata.dependencies,
        "APK dependency fields differ"
    );
    ensure!(
        numeric(&fields, "size")? == state.expected.values().map(|v| v.size).sum::<u64>(),
        "APK installed size differs"
    );
    let position = input.stream_position()?;
    let mut raw = File::open(path)?;
    raw.seek(SeekFrom::Start(position))?;
    let hash = hash_reader(raw, fs::metadata(path)?.len() - position)?;
    value(&fields, "datahash", &hash)?;
    gzip_tar(&mut input, state, &[])?;
    ensure!(
        input.fill_buf()?.is_empty(),
        "APK must contain exactly two unsigned gzip segments"
    );
    Ok(fields)
}
fn pacman(
    path: &Path,
    state: &mut State<'_>,
    spec: &PackageSpec,
) -> Result<BTreeMap<String, Vec<String>>> {
    let mut decoder = zstd::stream::read::Decoder::new(File::open(path)?)?.single_frame();
    decoder.window_log_max(27)?;
    let controls = tar_scan(&mut decoder, state, &[".PKGINFO", ".MTREE"])?;
    ensure!(
        decoder.finish().fill_buf()?.is_empty(),
        "extra pacman zstd frame/trailing bytes"
    );
    ensure!(controls.len() == 2, "pacman control set differs");
    let fields = equals_fields(
        controls
            .get(".PKGINFO")
            .context("missing pacman metadata")?,
    )?;
    allowed_fields(
        &fields,
        &[
            "pkgname",
            "pkgbase",
            "pkgver",
            "pkgdesc",
            "url",
            "builddate",
            "packager",
            "arch",
            "license",
            "size",
            "depend",
        ],
        &["depend"],
    )?;
    value(&fields, "pkgname", &spec.metadata.name)?;
    value(&fields, "pkgbase", &spec.metadata.name)?;
    value(&fields, "pkgver", &super::native::native_version(spec)?)?;
    value(&fields, "arch", &spec.metadata.arch)?;
    optional_value(&fields, "pkgdesc", spec.metadata.description.as_deref())?;
    optional_value(&fields, "url", spec.metadata.homepage.as_deref())?;
    optional_value(&fields, "license", spec.metadata.license.as_deref())?;
    value(
        &fields,
        "packager",
        spec.metadata.maintainer.as_deref().unwrap_or_default(),
    )?;
    ensure!(
        numeric(&fields, "size")? == state.expected.values().map(|v| v.size).sum::<u64>(),
        "pacman installed size differs"
    );
    ensure!(
        numeric(&fields, "builddate")? == spec.source_epoch,
        "pacman build date differs"
    );
    ensure!(
        fields.get("depend").cloned().unwrap_or_default() == spec.metadata.dependencies,
        "pacman dependencies differ"
    );
    mtree(
        controls.get(".MTREE").context("missing pacman mtree")?,
        controls.get(".PKGINFO").unwrap(),
        state,
    )?;
    Ok(fields)
}
fn mtree(compressed: &[u8], pkginfo: &[u8], state: &State<'_>) -> Result<()> {
    let mut gzip = GzDecoder::new(compressed);
    let mut decoded = Vec::new();
    gzip.by_ref()
        .take(METADATA_LIMIT + 1)
        .read_to_end(&mut decoded)?;
    ensure!(
        decoded.len() as u64 <= METADATA_LIMIT,
        "mtree exceeds metadata limit"
    );
    ensure!(gzip.get_ref().is_empty(), "extra mtree gzip bytes");
    let mut seen = BTreeSet::new();
    for line in std::str::from_utf8(&decoded)?.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let raw_name = parts.next().context("empty mtree record")?;
        let mut fields = BTreeMap::new();
        for part in parts {
            let (key, value) = part.split_once('=').context("invalid mtree record")?;
            ensure!(
                fields.insert(key, value).is_none(),
                "duplicate mtree attribute"
            );
        }
        let is_dir = fields.get("type") == Some(&"dir");
        let name = canonical(raw_name.as_bytes(), is_dir)?;
        ensure!(seen.insert(name.clone()), "duplicate mtree path");
        if is_dir {
            ensure!(
                fields.len() == 3
                    && fields.get("mode") == Some(&"755")
                    && fields.get("time") == Some(&format!("{}.0", state.epoch).as_str())
                    && state.dirs.contains(&name),
                "mtree directory differs from actual tar header"
            );
            continue;
        }
        ensure!(
            fields.len() == 6 && fields.get("type") == Some(&"file"),
            "unexpected mtree attributes"
        );
        let (size, mode, hash) = if name == ".PKGINFO" {
            (pkginfo.len() as u64, 0o644, crate::source::digest(pkginfo))
        } else {
            let entry = state.expected.get(&name).context("unknown mtree member")?;
            (entry.size, entry.mode, entry.sha256.clone())
        };
        ensure!(
            fields.get("sha256digest") == Some(&hash.as_str())
                && fields
                    .get("size")
                    .context("mtree size missing")?
                    .parse::<u64>()?
                    == size
                && u32::from_str_radix(fields.get("mode").context("mtree mode missing")?, 8)?
                    == mode
                && fields.get("time") == Some(&format!("{}.0", state.epoch).as_str()),
            "mtree content differs from actual payload"
        );
        let md5 = if name == ".PKGINFO" {
            format!("{:x}", md5::Md5::digest(pkginfo))
        } else {
            state
                .md5
                .get(&name)
                .context("mtree MD5 path missing")?
                .clone()
        };
        ensure!(
            fields.get("md5digest") == Some(&md5.as_str()),
            "mtree MD5 differs from actual payload"
        );
    }
    ensure!(
        seen.len() == state.expected.len() + state.dirs.len() + 1
            && state.dirs.iter().all(|v| seen.contains(v))
            && seen.contains(".PKGINFO"),
        "mtree member set differs"
    );
    Ok(())
}

// Validate all allocation-driving lengths before handing bytes to rpm-rs.
fn rpm_header_guard(file: &mut File, offset: u64, signature: bool) -> Result<u64> {
    file.seek(SeekFrom::Start(offset))?;
    let mut header = [0u8; 16];
    file.read_exact(&mut header)?;
    ensure!(
        header[..8] == [0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0],
        "invalid RPM header envelope"
    );
    let count = u32::from_be_bytes(header[8..12].try_into()?) as u64;
    let size = u32::from_be_bytes(header[12..16].try_into()?) as u64;
    ensure!(
        count <= MEMBER_LIMIT as u64 && size <= METADATA_LIMIT,
        "RPM header allocation limit exceeded"
    );
    let end = offset
        .checked_add(16 + count * 16 + size)
        .context("RPM offset overflow")?;
    ensure!(end <= file.metadata()?.len(), "truncated RPM header");
    let mut tags = BTreeSet::new();
    let mut indices = Vec::new();
    for _ in 0..count {
        let mut index = [0u8; 16];
        file.read_exact(&mut index)?;
        let tag = u32::from_be_bytes(index[..4].try_into()?);
        let kind = u32::from_be_bytes(index[4..8].try_into()?);
        let start = u32::from_be_bytes(index[8..12].try_into()?) as u64;
        let items = u32::from_be_bytes(index[12..16].try_into()?) as u64;
        ensure!(tags.insert(tag), "duplicate RPM header tag");
        ensure!(
            start <= size && kind <= 9,
            "RPM header index outside data store"
        );
        let width = match kind {
            0 => 0,
            1 | 2 | 7 => 1,
            3 => 2,
            4 => 4,
            5 => 8,
            6 | 8 | 9 => 0,
            _ => unreachable!(),
        };
        if kind == 7 {
            ensure!(items <= METADATA_LIMIT, "RPM binary tag too large");
        } else {
            ensure!(
                items <= MEMBER_LIMIT as u64,
                "RPM tag item count exceeds limit"
            );
        }
        ensure!(
            items * width <= size - start,
            "RPM tag length exceeds store"
        );
        if kind == 6 {
            ensure!(items == 1, "RPM string item count differs");
        }
        indices.push((kind, start as usize, items as usize, width as usize));
    }
    let mut store = vec![0u8; size as usize];
    file.read_exact(&mut store)?;
    let mut allocation = count as usize * 128 + store.len();
    for (kind, mut start, items, width) in indices {
        if [6, 8, 9].contains(&kind) {
            allocation = allocation
                .checked_add(items * 32)
                .context("RPM allocation overflow")?;
            for _ in 0..items {
                let length = store[start..]
                    .iter()
                    .position(|b| *b == 0)
                    .context("unterminated RPM header string")?;
                allocation = allocation
                    .checked_add(length)
                    .context("RPM allocation overflow")?;
                start += length + 1;
                ensure!(
                    allocation <= 64 * 1024 * 1024,
                    "RPM expanded header allocation limit exceeded"
                );
            }
        } else {
            allocation = allocation
                .checked_add(items * width)
                .context("RPM allocation overflow")?;
        }
        ensure!(
            allocation <= 64 * 1024 * 1024,
            "RPM expanded header allocation limit exceeded"
        );
    }
    Ok(if signature {
        end + (8 - end % 8) % 8
    } else {
        end
    })
}
fn rpm_preflight(path: &Path) -> Result<u64> {
    let mut file = File::open(path)?;
    let mut lead = [0u8; 96];
    file.read_exact(&mut lead)?;
    ensure!(
        lead[..4] == [0xed, 0xab, 0xee, 0xdb] && lead[4] == 3,
        "invalid RPM lead"
    );
    let main = rpm_header_guard(&mut file, 96, true)?;
    rpm_header_guard(&mut file, main, false)
}
fn rpm_internal_integrity(
    path: &Path,
    metadata: &::rpm::PackageMetadata,
    payload_offset: u64,
) -> Result<u64> {
    let expected_tags = BTreeSet::from([62u32, 269, 273, 1000, 1004, 1007]);
    let actual_tags = metadata
        .signature
        .get_all_entries()?
        .iter()
        .map(|v| v.0)
        .collect::<BTreeSet<_>>();
    ensure!(
        actual_tags == expected_tags,
        "RPM signature control tag set differs from the fixed unsigned profile"
    );
    for (tag, length) in [(269u32, 40usize), (273, 64)] {
        ensure!(
            matches!(metadata.signature.entry(tag)?, ::rpm::IndexData::StringTag(value) if value.len() == length),
            "invalid RPM signature digest encoding"
        );
    }
    // rpm-rs hashes the serialized complete main header for these signature tags.
    let header_digests = metadata.check_digests()?;
    ensure!(
        header_digests.header_sha1.is_verified() && header_digests.header_sha256.is_verified(),
        "RPM internal header digest mismatch"
    );
    ensure!(
        metadata
            .header
            .entry(::rpm::IndexTag::RPMTAG_PAYLOADSHA256ALGO)?
            == ::rpm::IndexData::Int32(vec![8]),
        "unsupported RPM payload digest algorithm"
    );
    let length = fs::metadata(path)?.len();
    let mut payload = File::open(path)?;
    payload.seek(SeekFrom::Start(payload_offset))?;
    let sha256 = hash_reader(payload, length - payload_offset)?;
    // rpm-rs Package::check_digests uses the compressed payload for PAYLOADSHA256.
    ensure!(
        metadata
            .header
            .entry(::rpm::IndexTag::RPMTAG_PAYLOADSHA256)?
            == ::rpm::IndexData::StringArray(vec![sha256]),
        "RPM internal payload SHA-256 mismatch"
    );
    let header_offset = metadata.get_package_segment_offsets().header;
    let combined_size = length - header_offset;
    ensure!(
        combined_size <= u64::from(u32::MAX)
            && metadata
                .signature
                .entry(::rpm::IndexSignatureTag::RPMSIGTAG_SIZE)?
                == ::rpm::IndexData::Int32(vec![combined_size as u32]),
        "RPM signed content size differs"
    );
    let mut combined = File::open(path)?;
    combined.seek(SeekFrom::Start(header_offset))?;
    let (_, combined_md5, _) = payload_hashes(combined, combined_size, None)?;
    // RPMSIGTAG_MD5 covers the complete main header plus the compressed archive.
    let expected_md5 = metadata
        .signature
        .get_entry_data_as_binary(::rpm::IndexSignatureTag::RPMSIGTAG_MD5)?;
    ensure!(
        expected_md5.len() == 16
            && expected_md5
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect::<String>()
                == combined_md5,
        "RPM internal header/payload MD5 mismatch"
    );
    match metadata
        .signature
        .entry(::rpm::IndexSignatureTag::RPMSIGTAG_PAYLOADSIZE)?
    {
        ::rpm::IndexData::Int32(value) if value.len() == 1 => Ok(u64::from(value[0])),
        _ => bail!("invalid RPM uncompressed payload size encoding"),
    }
}
struct CountedPayload<R> {
    inner: R,
    count: u64,
}
impl<R: Read> Read for CountedPayload<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buffer)?;
        self.count = self
            .count
            .checked_add(n as u64)
            .ok_or_else(|| std::io::Error::other("RPM CPIO byte count overflow"))?;
        if self.count > TOTAL_LIMIT + MEMBER_LIMIT as u64 * 8192 + 1024 * 1024 {
            return Err(std::io::Error::other("RPM CPIO envelope exceeds limit"));
        }
        Ok(n)
    }
}

fn rpm(
    path: &Path,
    state: &mut State<'_>,
    spec: &PackageSpec,
    profile: Option<crate::catalog::InspectionProfile>,
) -> Result<BTreeMap<String, Vec<String>>> {
    let payload_offset = rpm_preflight(path)?;
    let mut input = BufReader::new(File::open(path)?);
    let metadata = ::rpm::PackageMetadata::parse(&mut input)?;
    ensure!(
        input.stream_position()? == payload_offset,
        "RPM metadata offsets differ"
    );
    let expected_cpio_size = rpm_internal_integrity(path, &metadata, payload_offset)?;
    ensure!(
        metadata.get_name()? == spec.metadata.name
            && metadata.get_version()? == super::native::native_version(spec)?
            && metadata.get_release()? == spec.metadata.release.to_string()
            && metadata.get_arch()? == spec.metadata.arch,
        "RPM identity fields differ"
    );
    ensure!(!metadata.is_source_package(), "source RPM is unsupported");
    ensure!(
        metadata.get_payload_compressor()? == ::rpm::CompressionType::Gzip,
        "RPM payload compression must be gzip"
    );
    ensure!(
        metadata.get_description()? == spec.metadata.description.as_deref().unwrap_or_default(),
        "RPM description differs"
    );
    ensure!(
        metadata.get_license()? == spec.metadata.license.as_deref().unwrap_or_default(),
        "RPM license differs"
    );
    ensure!(
        metadata.get_packager()? == spec.metadata.maintainer.as_deref().unwrap_or_default(),
        "RPM packager differs"
    );
    match &spec.metadata.homepage {
        Some(homepage) => ensure!(metadata.get_url()? == homepage, "RPM homepage differs"),
        None => ensure!(
            metadata.get_url().map_or(true, |s| s.is_empty()),
            "unexpected RPM homepage"
        ),
    }
    ensure!(
        metadata.get_build_time()? == spec.source_epoch,
        "RPM build timestamp differs"
    );
    ensure!(
        metadata.get_build_host()? == "relship",
        "RPM build host differs from fixed backend policy"
    );
    ensure!(
        metadata.get_installed_size()? == state.expected.values().map(|v| v.size).sum::<u64>(),
        "RPM installed size differs"
    );
    ensure!(
        metadata.get_summary()? == spec.metadata.description.as_deref().unwrap_or_default(),
        "RPM summary differs"
    );
    // All interpreter, trigger, scriptlet and capability tags are outside this profile.
    let forbidden = [
        1023u32, 1024, 1025, 1026, 1065, 1066, 1067, 1068, 1069, 1079, 1085, 1086, 1087, 1088,
        1091, 1092, 1100, 1101, 1102, 1151, 1152, 1153, 1154, 1171, 1174, 1175, 5005, 5006, 5010,
        5020, 5021, 5022, 5023, 5024, 5025, 5026, 5027, 5063, 5064, 5065, 5066, 5067, 5068, 5069,
        5070, 5071, 5072, 5073, 5074, 5075, 5076, 5077, 5078, 5079, 5080, 5081, 5082, 5084, 5085,
        5103, 5104, 5105, 5106, 5107, 5108,
    ];
    ensure!(
        forbidden
            .iter()
            .all(|tag| !metadata.header.entry_is_present(*tag)),
        "RPM scripts/triggers/capabilities are unsupported"
    );
    let allowed_tags = [
        63u32, 100, 1000, 1001, 1002, 1004, 1005, 1006, 1007, 1009, 1014, 1015, 1020, 1021, 1022,
        1028, 1030, 1033, 1034, 1035, 1036, 1037, 1039, 1040, 1044, 1045, 1047, 1048, 1049, 1050,
        1064, 1095, 1096, 1097, 1112, 1113, 1116, 1117, 1118, 1124, 1125, 1126, 1140, 5011, 5092,
        5093,
    ];
    ensure!(
        metadata
            .header
            .get_all_entries()?
            .iter()
            .all(|(tag, _)| allowed_tags.contains(tag)),
        "RPM header contains an unexpected control tag"
    );
    ensure!(
        metadata
            .header
            .entry(::rpm::IndexTag::RPMTAG_PAYLOADFORMAT)?
            == ::rpm::IndexData::StringTag("cpio".into()),
        "RPM payload format differs"
    );
    ensure!(
        metadata.get_conflicts()?.is_empty()
            && metadata.get_obsoletes()?.is_empty()
            && metadata.get_recommends()?.is_empty()
            && metadata.get_suggests()?.is_empty()
            && metadata.get_enhances()?.is_empty()
            && metadata.get_supplements()?.is_empty(),
        "RPM has unplanned dependency relations"
    );
    let provides = metadata.get_provides()?;
    let abi = match (spec.metadata.arch.as_str(), profile) {
        ("x86_64", None | Some(crate::catalog::InspectionProfile::RpmX86_64)) => "x86-64",
        ("aarch64", None | Some(crate::catalog::InspectionProfile::RpmAarch64)) => "aarch-64",
        ("i686", Some(crate::catalog::InspectionProfile::RpmI686)) => "x86-32",
        ("armv6l", Some(crate::catalog::InspectionProfile::RpmArmSoft)) => "armv6l-32",
        ("armv7l", Some(crate::catalog::InspectionProfile::RpmArmSoft)) => "armv7l-32",
        ("armv6hl", Some(crate::catalog::InspectionProfile::RpmArmHard)) => "armv6hl-32",
        ("armv7hl", Some(crate::catalog::InspectionProfile::RpmArmHard)) => "armv7hl-32",
        _ => bail!("unsupported RPM architecture or typed profile"),
    };
    let mut expected_provides = BTreeSet::from([
        spec.metadata.name.clone(),
        format!("{}({abi})", spec.metadata.name),
    ]);
    let evr = format!(
        "{}-{}",
        super::native::native_version(spec)?,
        spec.metadata.release
    );
    let mut raw_provides = Vec::new();
    for provide in provides {
        ensure!(
            expected_provides.remove(&provide.name)
                && provide.flags == ::rpm::DependencyFlags::EQUAL
                && provide.version == evr,
            "RPM provides differ from the fixed backend profile"
        );
        raw_provides.push(format!("{} = {}", provide.name, provide.version));
    }
    ensure!(expected_provides.is_empty(), "missing RPM package provides");
    let mut header_paths = BTreeSet::new();
    for file in metadata.get_file_entries()? {
        let path = file.path();
        let raw = path.to_str().context("non-UTF8 RPM file path")?;
        let name = raw
            .strip_prefix('/')
            .context("RPM header path must be absolute")?;
        crate::config::relative(name)?;
        ensure!(
            header_paths.insert(name.to_lowercase()),
            "duplicate RPM header file path"
        );
        let entry = state
            .expected
            .get(name)
            .context("unexpected RPM header file")?;
        ensure!(
            file.digest()
                .is_some_and(|d| d.algorithm() == ::rpm::DigestAlgorithm::Sha2_256
                    && d.as_hex() == entry.sha256)
                && file.flags().bits() == 0
                && file.rdev() == 1,
            "RPM header digest/flags/device differs: digest={:?},flags={:?},rdev={}",
            file.digest(),
            file.flags(),
            file.rdev()
        );
        ensure!(
            u32::from(file.mode()) == 0o100000 | entry.mode
                && file.size() as u64 == entry.size
                && file.user() == "root"
                && file.group() == "root"
                && u64::from(file.modified_at().0) == state.epoch
                && file.caps().is_none_or(str::is_empty)
                && file.linkto().is_none_or(str::is_empty),
            "RPM header file metadata differs"
        );
    }
    ensure!(
        header_paths.len() == state.expected.len(),
        "RPM header file set differs"
    );
    let requires = metadata.get_requires()?;
    let mut actual_dependencies = Vec::new();
    let mut raw_dependencies = Vec::new();
    let mut expected_rpmlib = BTreeMap::from([
        ("rpmlib(CompressedFileNames)", "3.0.4-1"),
        ("rpmlib(FileDigests)", "4.6.0-1"),
        ("rpmlib(PayloadFilesHavePrefix)", "4.0-1"),
    ]);
    for dep in requires {
        let text = if dep.flags.comparator_str().is_empty() {
            dep.name.clone()
        } else {
            format!(
                "{} {} {}",
                dep.name,
                dep.flags.comparator_str(),
                dep.version
            )
        };
        raw_dependencies.push(text.clone());
        if dep.flags.contains(::rpm::DependencyFlags::RPMLIB) {
            ensure!(
                expected_rpmlib.remove(dep.name.as_str()) == Some(dep.version.as_str())
                    && dep.flags == (::rpm::DependencyFlags::RPMLIB | ::rpm::DependencyFlags::LE),
                "unexpected RPM backend requirement"
            );
        } else {
            ensure!(
                dep.flags.bits() & !14 == 0,
                "unsupported RPM dependency flags"
            );
            actual_dependencies.push(text);
        }
    }
    ensure!(
        expected_rpmlib.is_empty(),
        "missing RPM backend requirement"
    );
    let normalize_dep = |value: &str| {
        value
            .replace(['(', ')'], " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    let mut expected_deps = spec
        .metadata
        .dependencies
        .iter()
        .map(|v| normalize_dep(v))
        .collect::<Vec<_>>();
    actual_dependencies.sort();
    expected_deps.sort();
    ensure!(
        actual_dependencies == expected_deps,
        "RPM declared dependencies differ"
    );
    let mut compressed = CountedPayload {
        inner: GzDecoder::new(&mut input),
        count: 0,
    };
    let mut cpio = BufReader::new(&mut compressed);
    loop {
        let mut prefix = [0u8; 110];
        cpio.read_exact(&mut prefix)?;
        ensure!(
            &prefix[..6] == b"070701",
            "RPM payload must use newc without CRC"
        );
        let name_size = u32::from_str_radix(std::str::from_utf8(&prefix[94..102])?, 16)?;
        ensure!(
            name_size > 0 && name_size <= 4096,
            "RPM cpio name exceeds limit"
        );
        let mut item = cpio::newc::Reader::new(std::io::Cursor::new(prefix).chain(&mut cpio))?;
        let entry = item.entry();
        if entry.is_trailer() {
            ensure!(entry.file_size() == 0, "CPIO trailer has content");
            item.finish()?;
            break;
        }
        let is_dir = entry.mode() & 0o170000 == 0o040000;
        ensure!(
            is_dir || entry.mode() & 0o170000 == 0o100000,
            "nonregular RPM CPIO payload"
        );
        ensure!(
            entry.uid() == 0
                && entry.gid() == 0
                && entry.mode() & 0o7000 == 0
                && entry.rdev_major() == 0
                && entry.rdev_minor() == 0,
            "unsafe RPM CPIO owner/mode/device"
        );
        ensure!(entry.nlink() == 1 || is_dir, "RPM hard links unsupported");
        let name = canonical(entry.name().as_bytes(), is_dir)?;
        let mode = entry.mode() & 0o777;
        let size = u64::from(entry.file_size());
        ensure!(
            u64::from(entry.mtime()) == state.epoch,
            "RPM CPIO timestamp differs"
        );
        state.member(&name, size)?;
        if is_dir {
            ensure!(
                state.parents.contains(&name) && size == 0 && mode == 0o755,
                "unexpected RPM CPIO directory"
            );
        } else {
            state.file(&name, size, mode, &mut item)?;
        }
        item.finish()?;
    }
    zero_tail(&mut cpio)?;
    drop(cpio);
    ensure!(
        compressed.count == expected_cpio_size,
        "RPM uncompressed payload size differs"
    );
    drop(compressed);
    ensure!(
        input.fill_buf()?.is_empty(),
        "extra RPM gzip stream/trailing bytes"
    );
    Ok(BTreeMap::from([
        ("name".into(), vec![metadata.get_name()?.into()]),
        ("version".into(), vec![metadata.get_version()?.into()]),
        ("release".into(), vec![metadata.get_release()?.into()]),
        ("arch".into(), vec![metadata.get_arch()?.into()]),
        ("requires".into(), raw_dependencies),
        ("provides".into(), raw_provides),
        (
            "description".into(),
            vec![metadata.get_description()?.into()],
        ),
        ("license".into(), vec![metadata.get_license()?.into()]),
        ("packager".into(), vec![metadata.get_packager()?.into()]),
        (
            "url".into(),
            metadata
                .get_url()
                .ok()
                .map(str::to_owned)
                .into_iter()
                .collect(),
        ),
        (
            "buildtime".into(),
            vec![metadata.get_build_time()?.to_string()],
        ),
        ("buildhost".into(), vec![metadata.get_build_host()?.into()]),
    ]))
}

#[cfg(test)]
mod integrity_tests {
    use super::*;
    use ::rpm::{Header, HeaderEntry, IndexData, IndexSignatureTag, IndexTag, Package};
    use std::io::Write;

    fn set_header(package: &mut Package, tag: u32, data: IndexData) {
        let mut entries: Vec<_> = package
            .metadata
            .header
            .get_all_entries()
            .unwrap()
            .into_iter()
            .filter(|(number, _)| *number != 63 && *number != tag)
            .map(|(tag, data)| HeaderEntry::new(tag, data))
            .collect();
        entries.push(HeaderEntry::new(tag, data));
        package.metadata.header = Header::from_entries(entries, IndexTag::RPMTAG_HEADERIMMUTABLE);
    }
    fn signature(package: &mut Package, uncompressed_size: u32) {
        let header = package.metadata.header_bytes().unwrap();
        let mut md5 = md5::Md5::new();
        md5.update(&header);
        md5.update(&package.payload);
        package.metadata.signature = Header::from_entries(
            [
                HeaderEntry::new(
                    269,
                    IndexData::StringTag(format!("{:x}", sha1::Sha1::digest(&header))),
                ),
                HeaderEntry::new(273, IndexData::StringTag(crate::source::digest(&header))),
                HeaderEntry::new(
                    1000,
                    IndexData::Int32(vec![(header.len() + package.payload.len()) as u32]),
                ),
                HeaderEntry::new(1004, IndexData::Bin(md5.finalize().to_vec())),
                HeaderEntry::new(1007, IndexData::Int32(vec![uncompressed_size])),
            ],
            IndexSignatureTag::HEADER_SIGNATURES,
        );
    }
    fn fixture() -> (Package, u32) {
        let mut package =
            ::rpm::PackageBuilder::new("fixture", "1.2.3", "MIT", "x86_64", "fixture")
                .using_config(
                    ::rpm::BuildConfig::v4()
                        .compression(::rpm::CompressionType::None)
                        .source_date(1700000000u32),
                )
                .build()
                .unwrap();
        let uncompressed = package.payload.len() as u32;
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&package.payload).unwrap();
        package.payload = gzip.finish().unwrap();
        let sha256 = crate::source::digest(&package.payload);
        set_header(&mut package, 5092, IndexData::StringArray(vec![sha256]));
        set_header(&mut package, 5093, IndexData::Int32(vec![8]));
        signature(&mut package, uncompressed);
        (package, uncompressed)
    }
    fn check(package: &Package, path: &Path) -> Result<u64> {
        package.write(&mut File::create(path)?)?;
        let offset = rpm_preflight(path)?;
        let mut input = BufReader::new(File::open(path)?);
        let parsed = ::rpm::PackageMetadata::parse(&mut input)?;
        rpm_internal_integrity(path, &parsed, offset)
    }
    fn set_signature(package: &mut Package, tag: u32, data: IndexData) {
        let mut entries: Vec<_> = package
            .metadata
            .signature
            .get_all_entries()
            .unwrap()
            .into_iter()
            .filter(|(number, _)| *number != 62 && *number != tag)
            .map(|(tag, data)| HeaderEntry::new(tag, data))
            .collect();
        entries.push(HeaderEntry::new(tag, data));
        package.metadata.signature =
            Header::from_entries(entries, IndexSignatureTag::HEADER_SIGNATURES);
    }

    #[test]
    fn rpm_declared_digests_and_signature_controls_are_verified() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fixture.rpm");
        let (package, uncompressed) = fixture();
        assert_eq!(check(&package, &path).unwrap(), u64::from(uncompressed));
        let (mut package, uncompressed) = fixture();
        set_header(
            &mut package,
            5092,
            IndexData::StringArray(vec!["0".repeat(64)]),
        );
        signature(&mut package, uncompressed);
        assert!(
            check(&package, &path)
                .unwrap_err()
                .to_string()
                .contains("payload SHA-256 mismatch")
        );
        let (mut package, uncompressed) = fixture();
        set_header(&mut package, 5093, IndexData::Int32(vec![9]));
        signature(&mut package, uncompressed);
        assert!(
            check(&package, &path)
                .unwrap_err()
                .to_string()
                .contains("digest algorithm")
        );
        let (mut package, _) = fixture();
        set_signature(&mut package, 269, IndexData::StringTag("0".repeat(40)));
        assert!(
            check(&package, &path)
                .unwrap_err()
                .to_string()
                .contains("header digest mismatch")
        );
        let (mut package, _) = fixture();
        set_signature(&mut package, 273, IndexData::StringTag("0".repeat(64)));
        assert!(
            check(&package, &path)
                .unwrap_err()
                .to_string()
                .contains("header digest mismatch")
        );
        let (mut package, _) = fixture();
        set_signature(&mut package, 1004, IndexData::Bin(vec![0; 16]));
        assert!(
            check(&package, &path)
                .unwrap_err()
                .to_string()
                .contains("MD5 mismatch")
        );
        let (mut package, _) = fixture();
        set_signature(&mut package, 268, IndexData::Bin(vec![0; 16]));
        assert!(
            check(&package, &path)
                .unwrap_err()
                .to_string()
                .contains("signature control tag")
        );
    }
}
