//! Planned, app-local Microsoft CRT delivery and non-executing verification.
use super::{Architecture, BinaryObservation, NativeSdkExpectation, inspect_bytes};
use crate::delivery::model::PayloadManifest;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_LIBRARY: u64 = 512 * 1024 * 1024;
const MAX_LICENSE: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsRuntimeMode {
    #[default]
    FollowProject,
    Static,
    Dynamic,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeLibraryPin {
    pub filename: String,
    pub source: String,
    pub sha256: String,
    pub arch: Architecture,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LicensePin {
    pub source: String,
    pub sha256: String,
    pub destination: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WindowsRuntimePolicy {
    #[serde(default)]
    pub mode: WindowsRuntimeMode,
    #[serde(default)]
    pub libraries: Vec<RuntimeLibraryPin>,
    #[serde(default)]
    pub licenses: Vec<LicensePin>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeWitness {
    pub mode: WindowsRuntimeMode,
    /// Lowercase app-local basenames, including their full parsed import graph.
    pub libraries: BTreeMap<String, BinaryObservation>,
    /// Payload-relative destinations mapped to the declared source byte hashes.
    pub licenses: BTreeMap<String, String>,
}

fn hash(value: &str) -> Result<()> {
    super::environment::digest(&format!("sha256:{value}"))
}

fn basename(value: &str) -> Result<()> {
    crate::config::relative(value)?;
    ensure!(
        !value.contains('/'),
        "Windows DLL dependency must be a basename"
    );
    ensure!(value.is_ascii(), "Windows DLL dependency must be ASCII");
    ensure!(
        value.to_ascii_lowercase().ends_with(".dll"),
        "Windows dependency is not a DLL"
    );
    Ok(())
}

fn runtime_library(name: &str) -> bool {
    matches!(
        name,
        "ucrtbase.dll"
            | "vcruntime140.dll"
            | "vcruntime140_1.dll"
            | "vcruntime140_threads.dll"
            | "msvcp140.dll"
            | "msvcp140_1.dll"
            | "msvcp140_2.dll"
            | "msvcp140_atomic_wait.dll"
            | "msvcp140_codecvt_ids.dll"
            | "concrt140.dll"
            | "vccorlib140.dll"
            | "msvcr100.dll"
            | "msvcr110.dll"
            | "msvcr120.dll"
            | "msvcp100.dll"
            | "msvcp110.dll"
            | "msvcp120.dll"
    )
}

fn debug_runtime(name: &str) -> bool {
    name == "ucrtbased.dll"
        || ((name.starts_with("vcruntime")
            || name.starts_with("msvcp")
            || name.starts_with("msvcr")
            || name.starts_with("concrt")
            || name.starts_with("vccorlib"))
            && name.strip_suffix(".dll").is_some_and(|s| s.ends_with('d')))
}

fn api_contract(name: &str) -> bool {
    name.starts_with("api-ms-") || name.starts_with("ext-ms-")
}

fn system_library(name: &str) -> bool {
    api_contract(name)
        || matches!(
            name,
            "advapi32.dll"
                | "bcrypt.dll"
                | "bcryptprimitives.dll"
                | "cfgmgr32.dll"
                | "combase.dll"
                | "comdlg32.dll"
                | "crypt32.dll"
                | "cryptbase.dll"
                | "cryptsp.dll"
                | "dbghelp.dll"
                | "dnsapi.dll"
                | "dwmapi.dll"
                | "gdi32.dll"
                | "gdi32full.dll"
                | "imm32.dll"
                | "iphlpapi.dll"
                | "kernel32.dll"
                | "kernelbase.dll"
                | "mpr.dll"
                | "msvcrt.dll"
                | "ncrypt.dll"
                | "netapi32.dll"
                | "normaliz.dll"
                | "ntdll.dll"
                | "ole32.dll"
                | "oleaut32.dll"
                | "powrprof.dll"
                | "profapi.dll"
                | "psapi.dll"
                | "rpcrt4.dll"
                | "secur32.dll"
                | "setupapi.dll"
                | "shell32.dll"
                | "shlwapi.dll"
                | "sspicli.dll"
                | "user32.dll"
                | "userenv.dll"
                | "uxtheme.dll"
                | "version.dll"
                | "winhttp.dll"
                | "wininet.dll"
                | "winmm.dll"
                | "wintrust.dll"
                | "wldap32.dll"
                | "ws2_32.dll"
                | "wtsapi32.dll"
        )
}

// SDK paths must remain inspectable on a coordinator with another host OS.
// Native filesystem resolution is deliberately confined to staging/curation.
fn normalized_absolute(value: &str) -> Result<String> {
    ensure!(
        !value.is_empty() && value.len() <= 32768 && !value.chars().any(char::is_control),
        "Windows runtime source path is empty, unsafe, or exceeds bound"
    );
    let (prefix, body, separator, windows) = if value.starts_with('/') && !value.starts_with("//") {
        ("/".to_owned(), &value[1..], '/', false)
    } else {
        let bytes = value.as_bytes();
        ensure!(
            bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'/' | b'\\'),
            "Windows runtime source must use a normalized absolute SDK path"
        );
        (
            format!("{}:/", (bytes[0] as char).to_ascii_lowercase()),
            &value[3..],
            bytes[2] as char,
            true,
        )
    };
    ensure!(
        !body.contains(if separator == '/' { '\\' } else { '/' }),
        "Windows runtime source uses mixed path separators"
    );
    let parts = body.split(separator).collect::<Vec<_>>();
    if !body.is_empty() {
        for part in &parts {
            crate::config::relative(part)?;
            ensure!(
                !matches!(part.to_ascii_lowercase().as_str(), "system32" | "syswow64"),
                "Windows runtime sources cannot come from system DLL directories"
            );
        }
    }
    let body = parts.join("/");
    Ok(format!(
        "{prefix}{}",
        if windows {
            body.to_ascii_lowercase()
        } else {
            body
        }
    ))
}

fn within(source: &str, root: &str) -> bool {
    source != root
        && source
            .strip_prefix(root)
            .is_some_and(|tail| root.ends_with('/') || tail.starts_with('/'))
}

fn native_source_path(path: &Path) -> Result<String> {
    let value = path
        .to_str()
        .context("Windows runtime input path is not UTF-8")?;
    // std::fs::canonicalize on Windows returns the verbatim drive namespace.
    // Save the equivalent ordinary drive path; UNC/device paths stay invalid.
    let value = value.strip_prefix("\\\\?\\").unwrap_or(value);
    normalized_absolute(value)?;
    Ok(value.to_owned())
}

fn in_sdk(source: &str, sdk: &NativeSdkExpectation) -> Result<()> {
    let source = normalized_absolute(source)?;
    ensure!(
        sdk.roots.keys().any(|root| normalized_absolute(root)
            .is_ok_and(|root| source == root || within(&source, &root))),
        "Windows runtime input is outside all planned SDK roots"
    );
    Ok(())
}

impl WindowsRuntimePolicy {
    fn validate_structure(&self) -> Result<()> {
        ensure!(
            self.libraries.len() <= 64 && self.licenses.len() <= 64,
            "Windows runtime input count exceeds bound"
        );
        ensure!(
            self.libraries.is_empty() || !self.licenses.is_empty(),
            "Windows runtime DLL providers require explicit license inputs"
        );
        let mut names = BTreeSet::new();
        let mut sources = BTreeSet::new();
        for pin in &self.libraries {
            basename(&pin.filename)?;
            ensure!(
                pin.filename == pin.filename.to_ascii_lowercase() && runtime_library(&pin.filename),
                "unsupported, debug, or noncanonical Microsoft CRT provider"
            );
            hash(&pin.sha256)?;
            let source = normalized_absolute(&pin.source)?;
            ensure!(
                source
                    .rsplit('/')
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case(&pin.filename)),
                "Windows runtime provider source basename differs from its planned DLL name"
            );
            ensure!(
                names.insert(pin.filename.clone()) && sources.insert(source),
                "duplicate or case-colliding Windows runtime provider"
            );
        }
        let mut destinations = names;
        for pin in &self.licenses {
            hash(&pin.sha256)?;
            normalized_absolute(&pin.source)?;
            crate::config::relative(&pin.destination)?;
            ensure!(
                !pin.destination.to_ascii_lowercase().ends_with(".dll"),
                "Windows runtime license cannot be a DLL"
            );
            ensure!(
                destinations.insert(pin.destination.to_ascii_lowercase()),
                "case-colliding Windows runtime license destination"
            );
        }
        payload_names(
            self.libraries
                .iter()
                .map(|pin| pin.filename.clone())
                .chain(self.licenses.iter().map(|pin| pin.destination.clone())),
        )?;
        Ok(())
    }

    /// Pure model validation, including Windows drive paths on Unix coordinators.
    pub fn validate(&self, sdk: &NativeSdkExpectation) -> Result<()> {
        sdk.validate()?;
        self.validate_structure()?;
        for source in self
            .libraries
            .iter()
            .map(|p| &p.source)
            .chain(self.licenses.iter().map(|p| &p.source))
        {
            in_sdk(source, sdk)?;
        }
        Ok(())
    }
}

fn observation_shape(value: &BinaryObservation, arch: Architecture) -> Result<()> {
    ensure!(
        value.format == "pe"
            && value.arch == arch
            && value.machine
                == match arch {
                    Architecture::X86_64 => 0x8664,
                    Architecture::Aarch64 => 0xaa64,
                },
        "Windows runtime binary format or architecture differs from target"
    );
    ensure!(
        !value.has_search_path && !value.has_dynamic_plugins && value.interpreter.is_none(),
        "Windows runtime binary uses unsupported loader behavior"
    );
    hash(&value.sha256)?;
    Ok(())
}

fn inspect_provider(bytes: &[u8], arch: Architecture) -> Result<BinaryObservation> {
    let observed = inspect_bytes(bytes, "windows", arch)?;
    let pe_at = u32::from_le_bytes(
        bytes
            .get(0x3c..0x40)
            .context("missing PE header offset")?
            .try_into()?,
    ) as usize;
    let flags_at = pe_at.checked_add(22).context("PE header offset overflow")?;
    let flags = u16::from_le_bytes(
        bytes
            .get(flags_at..flags_at + 2)
            .context("missing PE characteristics")?
            .try_into()?,
    );
    ensure!(
        flags & 0x2000 != 0,
        "Microsoft CRT provider does not declare a PE DLL image"
    );
    Ok(observed)
}

fn closure(
    policy: &WindowsRuntimePolicy,
    primary: &[BinaryObservation],
    providers: &BTreeMap<String, BinaryObservation>,
) -> Result<RuntimeWitness> {
    policy.validate_structure()?;
    let arch = primary
        .first()
        .context("Windows runtime verification requires a primary executable")?
        .arch;
    ensure!(
        primary.len() <= 256,
        "Windows primary executable count exceeds bound"
    );
    let pins = policy
        .libraries
        .iter()
        .map(|p| (p.filename.as_str(), p))
        .collect::<BTreeMap<_, _>>();
    let mut queue = VecDeque::new();
    for value in primary {
        observation_shape(value, arch)?;
        queue.push_back(value);
    }
    let mut selected = BTreeMap::new();
    while let Some(value) = queue.pop_front() {
        ensure!(
            value.needed.len() <= 256,
            "Windows DLL dependency count exceeds bound"
        );
        for name in &value.needed {
            basename(name)?;
            let name = name.to_ascii_lowercase();
            ensure!(
                !debug_runtime(&name),
                "debug Microsoft CRT dependency is not redistributable: {name}"
            );
            let crt = runtime_library(&name)
                || name == "msvcrt.dll"
                || name.starts_with("api-ms-win-crt-");
            ensure!(
                policy.mode != WindowsRuntimeMode::Static || !crt,
                "static CRT policy observed a Microsoft CRT DLL dependency: {name}"
            );
            if system_library(&name) {
                continue;
            }
            ensure!(
                runtime_library(&name),
                "unsupported Windows DLL dependency outside Microsoft CRT delivery: {name}"
            );
            let pin = pins
                .get(name.as_str())
                .with_context(|| format!("unplanned Microsoft CRT dependency: {name}"))?;
            ensure!(
                pin.arch == arch,
                "Microsoft CRT provider architecture differs from primary executable"
            );
            let provider = providers
                .get(&name)
                .with_context(|| format!("missing Microsoft CRT provider bytes: {name}"))?;
            observation_shape(provider, arch)?;
            ensure!(
                provider.sha256 == pin.sha256,
                "Microsoft CRT provider bytes differ from planned SHA256: {name}"
            );
            if selected.insert(name.clone(), provider.clone()).is_none() {
                queue.push_back(provider);
            }
        }
    }
    Ok(RuntimeWitness {
        mode: policy.mode,
        libraries: selected,
        licenses: policy
            .licenses
            .iter()
            .map(|pin| (pin.destination.clone(), pin.sha256.clone()))
            .collect(),
    })
}

fn read_bounded_input(source: &str, sdk: &NativeSdkExpectation, maximum: u64) -> Result<Vec<u8>> {
    in_sdk(source, sdk)?;
    let path = Path::new(source);
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading planned Windows runtime input {source}"))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= maximum,
        "Windows runtime input must be a bounded regular file"
    );
    let actual = fs::canonicalize(path)?;
    ensure!(
        sdk.roots
            .keys()
            .any(|root| fs::canonicalize(root).is_ok_and(|root| actual.starts_with(root))),
        "Windows runtime input resolves outside pinned SDK roots"
    );
    // Reject a symlinked ancestor inside the declared root. Host aliases above
    // that root (for example macOS /var -> /private/var) do not change its tree.
    for ancestor in path.ancestors() {
        ensure!(
            !fs::symlink_metadata(ancestor)?.file_type().is_symlink(),
            "Windows runtime input has a symlinked ancestor"
        );
        if ancestor.to_str().is_some_and(|ancestor| {
            normalized_absolute(ancestor).is_ok_and(|ancestor| {
                sdk.roots
                    .keys()
                    .any(|root| normalized_absolute(root).is_ok_and(|root| ancestor == root))
            })
        }) {
            break;
        }
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum && bytes.len() as u64 == metadata.len(),
        "Windows runtime input changed size or exceeds bound"
    );
    Ok(bytes)
}

fn read_input(
    source: &str,
    expected: &str,
    sdk: &NativeSdkExpectation,
    maximum: u64,
) -> Result<Vec<u8>> {
    let bytes = read_bounded_input(source, sdk, maximum)?;
    ensure!(
        crate::source::digest(&bytes) == expected,
        "Windows runtime input differs from planned SHA256"
    );
    Ok(bytes)
}

fn payload_names(files: impl IntoIterator<Item = String>) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    let mut components = BTreeMap::new();
    for name in files {
        crate::config::relative(&name)?;
        ensure!(
            names.insert(name.to_ascii_lowercase()),
            "Windows payload contains case-colliding paths"
        );
        let parts = name.split('/').collect::<Vec<_>>();
        for end in 1..=parts.len() {
            let path = parts[..end].join("/");
            if let Some(previous) = components.insert(path.to_ascii_lowercase(), path.clone()) {
                ensure!(
                    previous == path,
                    "Windows payload contains case-colliding path components"
                );
            }
        }
    }
    for name in &names {
        let parts = name.split('/').collect::<Vec<_>>();
        for end in 1..parts.len() {
            ensure!(
                !names.contains(&parts[..end].join("/")),
                "Windows payload uses a file as another file's parent directory"
            );
        }
    }
    Ok(names)
}

fn existing_files(root: &Path) -> Result<Vec<String>> {
    let metadata = fs::symlink_metadata(root)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "Windows payload must be a real directory"
    );
    let mut pending = vec![root.to_path_buf()];
    let mut files = vec![];
    let mut count = 0;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            count += 1;
            ensure!(count <= 100_000, "Windows payload inventory exceeds bound");
            let metadata = fs::symlink_metadata(entry.path())?;
            ensure!(
                !metadata.file_type().is_symlink(),
                "Windows payload contains a symlink"
            );
            if metadata.is_dir() {
                pending.push(entry.path());
            } else {
                ensure!(
                    metadata.is_file(),
                    "Windows payload contains a special file"
                );
                files.push(
                    entry
                        .path()
                        .strip_prefix(root)?
                        .components()
                        .map(|part| {
                            part.as_os_str()
                                .to_str()
                                .context("Windows payload path is not UTF-8")
                        })
                        .collect::<Result<Vec<_>>>()?
                        .join("/"),
                );
            }
        }
    }
    Ok(files)
}

/// Stages only reachable, predeclared providers adjacent to the executables.
/// All source hashes and the complete normal/delay-import closure are checked
/// before the first payload write. No loader, PATH, or system-directory lookup occurs.
pub fn stage(
    policy: &WindowsRuntimePolicy,
    sdk: &NativeSdkExpectation,
    primary_observations: &[BinaryObservation],
    payload: &Path,
) -> Result<RuntimeWitness> {
    policy.validate(sdk)?;
    let mut bytes = BTreeMap::new();
    let mut providers = BTreeMap::new();
    let mut total = 0u64;
    for pin in &policy.libraries {
        let content = read_input(&pin.source, &pin.sha256, sdk, MAX_LIBRARY)?;
        total = total
            .checked_add(content.len() as u64)
            .context("Windows runtime input size overflow")?;
        ensure!(
            total <= MAX_LIBRARY,
            "combined Windows runtime inputs exceed bound"
        );
        providers.insert(pin.filename.clone(), inspect_provider(&content, pin.arch)?);
        bytes.insert(pin.filename.clone(), content);
    }
    let witness = closure(policy, primary_observations, &providers)?;
    bytes.retain(|name, _| witness.libraries.contains_key(name));
    for pin in &policy.licenses {
        let content = read_input(&pin.source, &pin.sha256, sdk, MAX_LICENSE)?;
        total = total
            .checked_add(content.len() as u64)
            .context("Windows runtime input size overflow")?;
        ensure!(
            total <= MAX_LIBRARY,
            "combined Windows runtime inputs exceed bound"
        );
        bytes.insert(pin.destination.clone(), content);
    }
    let existing = existing_files(payload)?;
    ensure!(
        existing
            .iter()
            .all(|name| !name.to_ascii_lowercase().ends_with(".dll")),
        "Windows payload already contains an unverified DLL"
    );
    let all = existing
        .into_iter()
        .chain(bytes.keys().cloned())
        .collect::<Vec<_>>();
    payload_names(all)?;
    for (name, content) in bytes {
        let destination = crate::config::safe_join(payload, &name)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)?;
        file.write_all(&content)?;
    }
    Ok(witness)
}

/// Recomputes the complete selected import graph from delivered bytes only.
/// Planned SDK paths remain provenance; this function never reads them.
pub fn verify(
    policy: &WindowsRuntimePolicy,
    primary_observations: &[BinaryObservation],
    files: &PayloadManifest,
    contents: &BTreeMap<String, Vec<u8>>,
) -> Result<RuntimeWitness> {
    policy.validate_structure()?;
    payload_names(files.keys().cloned())?;
    ensure!(
        contents.keys().all(|name| files.contains_key(name)),
        "Windows runtime bytes include paths outside payload manifest"
    );
    let arch = primary_observations
        .first()
        .context("Windows runtime verification requires a primary executable")?
        .arch;
    let pins = policy
        .libraries
        .iter()
        .map(|p| (p.filename.as_str(), p))
        .collect::<BTreeMap<_, _>>();
    let mut providers = BTreeMap::new();
    for (name, entry) in files {
        if name.to_ascii_lowercase().ends_with(".dll") {
            let content = contents
                .get(name)
                .context("Windows runtime DLL bytes are missing from offline inputs")?;
            ensure!(
                entry.mode == 0o644
                    && entry.size == content.len() as u64
                    && entry.sha256 == crate::source::digest(content),
                "Windows runtime DLL bytes differ from manifest SHA256 or size: {name}"
            );
            basename(name)?;
            let pin = pins
                .get(name.as_str())
                .context("unexpected or case-aliased DLL in Windows payload")?;
            ensure!(
                pin.arch == arch && entry.sha256 == pin.sha256,
                "delivered Microsoft CRT DLL differs from planned architecture or SHA256"
            );
            providers.insert(name.clone(), inspect_provider(content, arch)?);
        }
    }
    let witness = closure(policy, primary_observations, &providers)?;
    ensure!(
        providers.keys().eq(witness.libraries.keys()),
        "Windows payload contains an unused Microsoft CRT DLL"
    );
    for pin in &policy.licenses {
        let entry = files
            .get(&pin.destination)
            .context("Windows runtime license is missing from payload")?;
        let content = contents
            .get(&pin.destination)
            .context("Windows runtime license bytes are missing from offline inputs")?;
        ensure!(
            entry.mode == 0o644
                && entry.sha256 == pin.sha256
                && entry.size <= MAX_LICENSE
                && entry.size == content.len() as u64
                && crate::source::digest(content) == pin.sha256,
            "Windows runtime license differs from planned input"
        );
    }
    Ok(witness)
}

/// Curates explicit SDK redistributable directories without searching PATH or
/// system DLL directories. License paths must be supplied by the operator.
pub fn inspect_runtime(
    arch: Architecture,
    sdk: &NativeSdkExpectation,
    runtime_dirs: &[PathBuf],
    licenses: &[PathBuf],
    mode: WindowsRuntimeMode,
) -> Result<WindowsRuntimePolicy> {
    sdk.validate()?;
    ensure!(
        runtime_dirs.len() <= 32 && licenses.len() <= 64,
        "Windows runtime curation input count exceeds bound"
    );
    let mut policy = WindowsRuntimePolicy {
        mode,
        libraries: vec![],
        licenses: vec![],
    };
    for directory in runtime_dirs {
        let source = native_source_path(directory)?;
        let normalized = normalized_absolute(&source)?;
        ensure!(
            sdk.roots.keys().any(|root| normalized_absolute(root)
                .is_ok_and(|root| normalized == root || within(&normalized, &root))),
            "Windows runtime directory is outside all planned SDK roots"
        );
        let metadata = fs::symlink_metadata(directory)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "Windows runtime directory must be a real SDK directory"
        );
        let mut count = 0;
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            count += 1;
            ensure!(
                count <= 4096,
                "Windows runtime curation directory exceeds bound"
            );
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("Windows runtime filename is not UTF-8"))?
                .to_ascii_lowercase();
            ensure!(
                !debug_runtime(&name),
                "debug Microsoft CRT provider cannot be curated"
            );
            if !runtime_library(&name) {
                continue;
            }
            ensure!(
                policy.libraries.len() < 64,
                "Windows runtime provider count exceeds bound"
            );
            let source = native_source_path(&entry.path())?;
            let bytes = read_bounded_input(&source, sdk, MAX_LIBRARY)?;
            let sha256 = crate::source::digest(&bytes);
            inspect_provider(&bytes, arch)?;
            policy.libraries.push(RuntimeLibraryPin {
                filename: name,
                source,
                sha256,
                arch,
            });
        }
    }
    for license in licenses {
        let source = native_source_path(license)?;
        in_sdk(&source, sdk)?;
        let bytes = read_bounded_input(&source, sdk, MAX_LICENSE)?;
        let sha256 = crate::source::digest(&bytes);
        let name = license
            .file_name()
            .and_then(|s| s.to_str())
            .context("Windows runtime license needs a UTF-8 basename")?;
        policy.licenses.push(LicensePin {
            source,
            sha256,
            destination: format!("licenses/windows-runtime/{name}"),
        });
    }
    policy.libraries.sort_by(|a, b| a.filename.cmp(&b.filename));
    policy
        .licenses
        .sort_by(|a, b| a.destination.cmp(&b.destination));
    policy.validate(sdk)?;
    // Each curated provider must have a resolvable closure within this same
    // inventory, even if a future executable does not select that provider.
    if !policy.libraries.is_empty() {
        let mut providers = BTreeMap::new();
        for pin in &policy.libraries {
            let content = read_input(&pin.source, &pin.sha256, sdk, MAX_LIBRARY)?;
            providers.insert(pin.filename.clone(), inspect_provider(&content, arch)?);
        }
        let mut checked_policy = policy.clone();
        checked_policy.mode = WindowsRuntimeMode::FollowProject;
        closure(
            &checked_policy,
            &providers.values().cloned().collect::<Vec<_>>(),
            &providers,
        )?;
    }
    Ok(policy)
}
