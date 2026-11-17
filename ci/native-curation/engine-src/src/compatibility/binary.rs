use super::Architecture;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{self, File},
    io::Read,
    path::Path,
};

const MAX_BINARY: u64 = 512 * 1024 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct RequiredVersion {
    pub library: String,
    pub name: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BinaryObservation {
    pub format: String,
    pub arch: Architecture,
    pub machine: u32,
    pub interpreter: Option<String>,
    pub needed: Vec<String>,
    pub required_versions: Vec<RequiredVersion>,
    pub provided_versions: Vec<String>,
    pub minimum_os: Option<String>,
    pub sdk_version: Option<String>,
    pub has_search_path: bool,
    pub has_dynamic_plugins: bool,
    pub sha256: String,
}
fn range(bytes: &[u8], at: usize, size: usize) -> Result<&[u8]> {
    bytes
        .get(at..at.checked_add(size).context("binary offset overflow")?)
        .context("binary structure exceeds bounded input")
}
fn u16le(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(range(b, at, 2)?.try_into()?))
}
fn u32le(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(range(b, at, 4)?.try_into()?))
}
fn u64le(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(range(b, at, 8)?.try_into()?))
}
fn usize64(v: u64) -> Result<usize> {
    usize::try_from(v).context("binary offset exceeds address space")
}
fn cstr(bytes: &[u8], offset: usize) -> Result<String> {
    let tail = bytes
        .get(offset..)
        .context("binary string offset exceeds table")?;
    let end = tail
        .iter()
        .position(|c| *c == 0)
        .context("unterminated binary string")?;
    ensure!(end <= 4096, "binary string exceeds bound");
    Ok(std::str::from_utf8(&tail[..end])?.into())
}
fn basename(s: &str) -> Result<()> {
    crate::config::relative(s)?;
    ensure!(
        !s.contains(['/', '\\']) && !s.is_empty(),
        "binary dependency must be a basename"
    );
    Ok(())
}
fn observation(bytes: &[u8], arch: Architecture, format: &str, machine: u32) -> BinaryObservation {
    BinaryObservation {
        format: format.into(),
        arch,
        machine,
        interpreter: None,
        needed: vec![],
        required_versions: vec![],
        provided_versions: vec![],
        minimum_os: None,
        sdk_version: None,
        has_search_path: false,
        has_dynamic_plugins: false,
        sha256: crate::source::digest(bytes),
    }
}
/// Reads bytes only; never invokes ldd, the dynamic loader, or an executable.
pub fn observe_binary(path: &Path, os: &str, arch: Architecture) -> Result<BinaryObservation> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= MAX_BINARY,
        "binary input must be a bounded regular file"
    );
    let mut bytes = Vec::with_capacity(usize64(meta.len())?);
    File::open(path)?
        .take(MAX_BINARY + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_BINARY && bytes.len() as u64 == meta.len(),
        "binary input changed or exceeds limit"
    );
    let observed = inspect_bytes(&bytes, os, arch)?;
    if os == "linux" {
        let target = crate::catalog::TargetDescriptor {
            id: format!("compatibility-{}", arch.name()),
            os: "linux".into(),
            arch: arch.name().into(),
            cpu: "generic".into(),
            fpu: "none".into(),
            libc: "gnu".into(),
            c_abi: "sysv".into(),
            builder: "cmake".into(),
            compiler_target: String::new(),
            compile_env: BTreeMap::new(),
            minimum_kernel: None,
            minimum_libc: None,
        };
        let legacy = crate::v5::runtime::observe_binary(path, &target)?
            .context("missing ELF observation")?;
        ensure!(
            legacy.machine as u32 == observed.machine
                && legacy.needed == observed.needed
                && legacy.interpreter == observed.interpreter
                && legacy.has_search_path == observed.has_search_path
                && legacy.has_dynamic_plugins == observed.has_dynamic_plugins,
            "shared ELF observations differ from the established v5 safety reader"
        );
    }
    Ok(observed)
}
pub fn inspect_bytes(bytes: &[u8], os: &str, arch: Architecture) -> Result<BinaryObservation> {
    ensure!(
        bytes.len() as u64 <= MAX_BINARY,
        "binary input exceeds limit"
    );
    match os {
        "linux" => elf(bytes, arch),
        "windows" => pe(bytes, arch),
        "macos" => macho(bytes, arch),
        _ => bail!("unsupported binary observation OS: {os}"),
    }
}
#[derive(Clone, Copy)]
struct Load {
    address: u64,
    offset: u64,
    size: u64,
}
fn mapped<'a>(bytes: &'a [u8], loads: &[Load], address: u64, size: u64) -> Result<&'a [u8]> {
    let candidates = loads
        .iter()
        .filter_map(|l| {
            address
                .checked_sub(l.address)
                .filter(|delta| delta.checked_add(size).is_some_and(|v| v <= l.size))
                .and_then(|delta| l.offset.checked_add(delta))
        })
        .collect::<Vec<_>>();
    ensure!(
        candidates.len() == 1,
        "ELF structure is unmapped or ambiguously mapped"
    );
    range(bytes, usize64(candidates[0])?, usize64(size)?)
}
fn elf(bytes: &[u8], arch: Architecture) -> Result<BinaryObservation> {
    ensure!(
        range(bytes, 0, 7)? == b"\x7fELF\x02\x01\x01",
        "native6 requires little-endian ELF64 version 1"
    );
    let machine = u16le(bytes, 18)?;
    ensure!(
        machine
            == match arch {
                Architecture::X86_64 => 62,
                Architecture::Aarch64 => 183,
            },
        "ELF architecture differs from target"
    );
    ensure!(
        matches!(u16le(bytes, 16)?, 2 | 3),
        "ELF must be executable or shared-object format"
    );
    let mut out = observation(bytes, arch, "elf", machine.into());
    let at = usize64(u64le(bytes, 32)?)?;
    let width = u16le(bytes, 54)? as usize;
    let count = u16le(bytes, 56)? as usize;
    ensure!(
        count <= 1024 && (count == 0 || width == 56),
        "unsupported ELF program header count or width"
    );
    range(
        bytes,
        at,
        width
            .checked_mul(count)
            .context("ELF program header size overflow")?,
    )?;
    let mut loads = vec![];
    let mut dynamic = None;
    for i in 0..count {
        let header = range(bytes, at + i * width, width)?;
        let offset = u64le(header, 8)?;
        let address = u64le(header, 16)?;
        let size = u64le(header, 32)?;
        let data = range(bytes, usize64(offset)?, usize64(size)?)?;
        match u32le(header, 0)? {
            1 => loads.push(Load {
                address,
                offset,
                size,
            }),
            2 => {
                ensure!(
                    dynamic.is_none() && size <= 1024 * 1024,
                    "duplicate or oversized ELF dynamic segment"
                );
                dynamic = Some(data);
            }
            3 => {
                ensure!(
                    out.interpreter.is_none()
                        && (2..=4096).contains(&data.len())
                        && data.last() == Some(&0),
                    "invalid ELF interpreter segment"
                );
                let s = cstr(data, 0)?;
                ensure!(
                    s.len() + 1 == data.len() && s.starts_with('/'),
                    "invalid ELF interpreter path"
                );
                crate::config::relative(s.trim_start_matches('/'))?;
                out.interpreter = Some(s);
            }
            _ => {}
        }
    }
    let Some(dynamic) = dynamic else {
        return Ok(out);
    };
    ensure!(dynamic.len() % 16 == 0, "unaligned ELF dynamic segment");
    let mut tags = BTreeMap::new();
    let mut needed = vec![];
    let mut ended = false;
    for entry in dynamic.chunks_exact(16) {
        let tag = u64le(entry, 0)?;
        let value = u64le(entry, 8)?;
        match tag {
            0 => {
                ended = true;
                break;
            }
            1 => {
                ensure!(needed.len() < 256, "too many ELF dependencies");
                needed.push(value);
            }
            15 | 29 => {
                out.has_search_path = true;
            }
            0x7fff_fffd | 0x7fff_ffff | 0x6fff_fefb | 0x6fff_fefc => {
                out.has_dynamic_plugins = true;
            }
            5 | 10 | 0x6fff_fffe | 0x6fff_ffff | 0x6fff_fffc | 0x6fff_fffd => {
                ensure!(
                    tags.insert(tag, value).is_none(),
                    "duplicate ELF dynamic metadata tag"
                );
            }
            _ => {}
        }
    }
    ensure!(ended, "unterminated ELF dynamic segment");
    if needed.is_empty() && !tags.contains_key(&0x6fff_fffe) && !tags.contains_key(&0x6fff_fffc) {
        return Ok(out);
    }
    let string_size = *tags
        .get(&10)
        .context("ELF dynamic string table size is missing")?;
    ensure!(
        string_size <= 16 * 1024 * 1024,
        "oversized ELF dynamic string table"
    );
    let strings = mapped(
        bytes,
        &loads,
        *tags
            .get(&5)
            .context("ELF dynamic string table is missing")?,
        string_size,
    )?;
    for offset in needed {
        let s = cstr(strings, usize64(offset)?)?;
        basename(&s)?;
        ensure!(!out.needed.contains(&s), "duplicate ELF dependency");
        out.needed.push(s);
    }
    if let Some(address) = tags.get(&0x6fff_fffe) {
        let count = *tags
            .get(&0x6fff_ffff)
            .context("ELF version requirement count is missing")?;
        ensure!(count <= 256, "too many ELF version requirement libraries");
        let mut cursor = *address;
        let mut total = 0u64;
        for i in 0..count {
            let header = mapped(bytes, &loads, cursor, 16)?;
            ensure!(
                u16le(header, 0)? == 1,
                "unsupported ELF version requirement encoding"
            );
            let count_aux = u16le(header, 2)? as u64;
            total += count_aux;
            ensure!(
                total <= 65536 && count_aux > 0,
                "ELF version requirement count exceeds bound"
            );
            let library = cstr(strings, u32le(header, 4)? as usize)?;
            basename(&library)?;
            ensure!(
                out.needed.contains(&library),
                "ELF version requirement names a library absent from DT_NEEDED"
            );
            let first = u32le(header, 8)? as u64;
            ensure!(
                first >= 16,
                "ELF version auxiliary list overlaps its header"
            );
            let mut aux = cursor
                .checked_add(first)
                .context("ELF version offset overflow")?;
            for j in 0..count_aux {
                let entry = mapped(bytes, &loads, aux, 16)?;
                let name = cstr(strings, u32le(entry, 8)? as usize)?;
                ensure!(!name.is_empty(), "empty ELF version requirement");
                out.required_versions.push(RequiredVersion {
                    library: library.clone(),
                    name,
                });
                let next = u32le(entry, 12)? as u64;
                ensure!(
                    (j + 1 == count_aux && next == 0) || (j + 1 < count_aux && next >= 16),
                    "invalid ELF version auxiliary chain"
                );
                aux = aux
                    .checked_add(next)
                    .context("ELF version offset overflow")?;
            }
            let next = u32le(header, 12)? as u64;
            ensure!(
                (i + 1 == count && next == 0) || (i + 1 < count && next >= 16),
                "invalid ELF version requirement chain"
            );
            cursor = cursor
                .checked_add(next)
                .context("ELF version offset overflow")?;
        }
    } else {
        ensure!(
            !tags.contains_key(&0x6fff_ffff),
            "ELF version requirement count has no table"
        );
    }
    if let Some(address) = tags.get(&0x6fff_fffc) {
        let count = *tags
            .get(&0x6fff_fffd)
            .context("ELF version definition count is missing")?;
        ensure!(count <= 65536, "too many ELF version definitions");
        let mut cursor = *address;
        for i in 0..count {
            let header = mapped(bytes, &loads, cursor, 20)?;
            ensure!(
                u16le(header, 0)? == 1 && u16le(header, 6)? > 0,
                "unsupported ELF version definition"
            );
            let first = u32le(header, 12)? as u64;
            ensure!(
                first >= 20,
                "ELF version definition auxiliary overlaps header"
            );
            let aux = mapped(
                bytes,
                &loads,
                cursor
                    .checked_add(first)
                    .context("ELF version offset overflow")?,
                8,
            )?;
            let name = cstr(strings, u32le(aux, 0)? as usize)?;
            ensure!(!name.is_empty(), "empty ELF version definition");
            out.provided_versions.push(name);
            let next = u32le(header, 16)? as u64;
            ensure!(
                (i + 1 == count && next == 0) || (i + 1 < count && next >= 20),
                "invalid ELF version definition chain"
            );
            cursor = cursor
                .checked_add(next)
                .context("ELF version offset overflow")?;
        }
    } else {
        ensure!(
            !tags.contains_key(&0x6fff_fffd),
            "ELF version definition count has no table"
        );
    }
    out.required_versions.sort();
    out.required_versions.dedup();
    out.provided_versions.sort();
    out.provided_versions.dedup();
    Ok(out)
}
/// Compares numeric components, so GLIBC_2.9 is older than GLIBC_2.17.
/// GLIBC_PRIVATE, GLIBC_ABI_* and malformed suffixes fail closed.
pub fn numeric_version(value: &str) -> Result<Vec<u32>> {
    ensure!(
        !value.is_empty() && value.len() <= 64,
        "invalid numeric version"
    );
    let parts = value
        .split('.')
        .map(|part| {
            ensure!(
                !part.is_empty()
                    && part.bytes().all(|b| b.is_ascii_digit())
                    && (part == "0" || !part.starts_with('0')),
                "non-numeric or noncanonical version: {value}"
            );
            part.parse::<u32>().context("version component overflow")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        (2..=4).contains(&parts.len()),
        "unsupported numeric version component count"
    );
    Ok(parts)
}
fn version_exceeds(value: &[u32], maximum: &[u32]) -> bool {
    for i in 0..value.len().max(maximum.len()) {
        match value
            .get(i)
            .copied()
            .unwrap_or(0)
            .cmp(&maximum.get(i).copied().unwrap_or(0))
        {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    false
}
pub fn validate_linux_abi(
    binary: &BinaryObservation,
    baseline: &str,
    allowed_needed: &BTreeSet<String>,
) -> Result<()> {
    ensure!(
        binary.format == "elf",
        "Linux ABI validation requires ELF observations"
    );
    ensure!(
        !binary.has_search_path && !binary.has_dynamic_plugins,
        "broad Linux closure does not support RPATH, RUNPATH, audit, filter or auxiliary libraries"
    );
    let maximum = numeric_version(baseline)?;
    for requirement in &binary.required_versions {
        if let Some(version) = requirement.name.strip_prefix("GLIBC_") {
            let value = numeric_version(version).with_context(|| {
                format!("unsupported required glibc version: {}", requirement.name)
            })?;
            ensure!(
                !version_exceeds(&value, &maximum),
                "required {} exceeds configured glibc {baseline}; automatic baseline increases are forbidden",
                requirement.name
            );
        }
    }
    for library in &binary.needed {
        basename(library)?;
        ensure!(
            allowed_needed.contains(library),
            "undeclared ELF dependency: {library}"
        );
    }
    Ok(())
}
/// All members must come from the pinned provider inventory. This validates
/// DT_NEEDED and version-provider closure; application-driven dlopen is outside
/// the contract. Filesystem extraction/hash binding belongs to the caller.
pub fn resolve_elf_closure(
    program: &BinaryObservation,
    files: &BTreeMap<String, BinaryObservation>,
    baseline: &str,
) -> Result<BTreeSet<String>> {
    ensure!(files.len() <= 512, "ELF closure inventory exceeds bound");
    let mut providers = BTreeMap::new();
    for (name, binary) in files {
        let name = name.trim_start_matches('/');
        crate::config::relative(name)?;
        let base = name
            .rsplit('/')
            .next()
            .context("invalid ELF closure path")?;
        basename(base)?;
        ensure!(
            providers
                .insert(base.to_owned(), (name.to_owned(), binary))
                .is_none(),
            "ambiguous ELF library basename in pinned inventory: {base}"
        );
        ensure!(
            binary.format == "elf"
                && binary.arch == program.arch
                && binary.machine == program.machine,
            "ELF closure architecture differs from program"
        );
        ensure!(
            binary
                .interpreter
                .as_ref()
                .is_none_or(|value| program.interpreter.as_ref() == Some(value)),
            "ELF closure member declares another program interpreter"
        );
    }
    let allowed = providers.keys().cloned().collect::<BTreeSet<_>>();
    let mut selected = BTreeSet::new();
    let mut pending = VecDeque::from([program]);
    if let Some(interpreter) = &program.interpreter {
        let path = interpreter
            .strip_prefix('/')
            .context("ELF interpreter must be absolute")?;
        crate::config::relative(path)?;
        let provider = providers
            .get(path.rsplit('/').next().unwrap_or(""))
            .context("pinned ELF closure lacks the program interpreter")?;
        ensure!(
            provider.0 == path,
            "pinned ELF interpreter path differs from program"
        );
        selected.insert(provider.0.clone());
        pending.push_back(provider.1);
    } else {
        ensure!(
            program.needed.is_empty(),
            "dynamic ELF program lacks an interpreter"
        );
    }
    validate_linux_abi(program, baseline, &allowed)?;
    while let Some(binary) = pending.pop_front() {
        // Runtime provider libraries may be newer than the application's floor.
        // Their own imports must resolve inside this pinned userspace, while
        // the broad floor applies to the delivered application and its bundled
        // objects (which callers inspect separately).
        ensure!(
            !binary.has_search_path && !binary.has_dynamic_plugins,
            "pinned ELF closure uses unsupported search paths or loader plugins"
        );
        for library in &binary.needed {
            ensure!(
                allowed.contains(library),
                "unresolved transitive ELF dependency: {library}"
            );
        }
        for version in &binary.required_versions {
            let (_, provider) = providers
                .get(&version.library)
                .context("ELF required-version provider is unresolved")?;
            ensure!(
                provider.provided_versions.contains(&version.name),
                "pinned ELF provider {} lacks required version {}",
                version.library,
                version.name
            );
        }
        for library in &binary.needed {
            let (name, provider) = providers
                .get(library)
                .context("ELF dependency is unresolved")?;
            if selected.insert(name.clone()) {
                pending.push_back(provider);
            }
        }
        ensure!(
            selected.len() <= 512,
            "ELF dependency closure exceeds bound"
        );
    }
    Ok(selected)
}
fn pe(bytes: &[u8], arch: Architecture) -> Result<BinaryObservation> {
    ensure!(range(bytes, 0, 2)? == b"MZ", "expected PE DOS header");
    let at = u32le(bytes, 0x3c)? as usize;
    ensure!(
        (64..=1024 * 1024).contains(&at) && range(bytes, at, 4)? == b"PE\0\0",
        "invalid bounded PE signature offset"
    );
    let machine = u16le(bytes, at + 4)?;
    ensure!(
        machine
            == match arch {
                Architecture::X86_64 => 0x8664,
                Architecture::Aarch64 => 0xaa64,
            },
        "PE architecture differs from target"
    );
    ensure!(
        u16le(bytes, at + 22)? & 2 != 0,
        "PE does not declare executable code"
    );
    let count = u16le(bytes, at + 6)? as usize;
    let optional_size = u16le(bytes, at + 20)? as usize;
    ensure!(
        (112..=4096).contains(&optional_size) && count <= 96,
        "PE optional header or section count exceeds bound"
    );
    let optional = range(bytes, at + 24, optional_size)?;
    ensure!(u16le(optional, 0)? == 0x20b, "native6 requires PE32+");
    let mut out = observation(bytes, arch, "pe", machine.into());
    out.minimum_os = Some(format!("{}.{}", u16le(optional, 40)?, u16le(optional, 42)?));
    let section_at = at + 24 + optional_size;
    range(bytes, section_at, count * 40)?;
    let mut sections = vec![];
    for i in 0..count {
        let h = range(bytes, section_at + i * 40, 40)?;
        let offset = u32le(h, 20)? as u64;
        let size = u32le(h, 16)? as u64;
        range(bytes, usize64(offset)?, usize64(size)?)?;
        sections.push(Load {
            address: u32le(h, 12)? as u64,
            offset,
            size,
        });
    }
    let directories = u32le(optional, 108)? as usize;
    ensure!(
        directories <= 32 && 112 + directories * 8 <= optional.len(),
        "PE data directories exceed optional header"
    );
    for (index, stride, delayed) in [(1usize, 20usize, false), (13, 32, true)] {
        if directories <= index {
            continue;
        }
        let address = u32le(optional, 112 + index * 8)? as u64;
        let size = u32le(optional, 116 + index * 8)? as u64;
        if address == 0 && size == 0 {
            continue;
        }
        ensure!(
            address != 0 && size >= stride as u64 && size <= 1024 * 1024,
            "PE import table exceeds bound"
        );
        let entries = mapped(bytes, &sections, address, size)?;
        let mut ended = false;
        for h in entries.chunks_exact(stride) {
            if h.iter().all(|b| *b == 0) {
                ended = true;
                break;
            }
            ensure!(out.needed.len() < 256, "too many PE dependencies");
            if delayed {
                ensure!(
                    u32le(h, 0)? == 1,
                    "PE delay imports using absolute addresses are unsupported"
                );
            }
            let name_address = u32le(h, if delayed { 4 } else { 12 })? as u64;
            let string = mapped_tail(bytes, &sections, name_address, 4097)?;
            let name = cstr(string, 0)?.to_ascii_lowercase();
            basename(&name)?;
            if !out.needed.contains(&name) {
                out.needed.push(name);
            }
        }
        ensure!(ended, "unterminated PE import table");
    }
    out.needed.sort();
    Ok(out)
}
fn mapped_tail<'a>(
    bytes: &'a [u8],
    loads: &[Load],
    address: u64,
    maximum: u64,
) -> Result<&'a [u8]> {
    let candidates = loads
        .iter()
        .filter_map(|l| {
            let delta = address.checked_sub(l.address)?;
            (delta < l.size).then(|| (l.offset + delta, (l.size - delta).min(maximum)))
        })
        .collect::<Vec<_>>();
    ensure!(
        candidates.len() == 1,
        "binary string is unmapped or ambiguously mapped"
    );
    range(bytes, usize64(candidates[0].0)?, usize64(candidates[0].1)?)
}
fn packed_version(v: u32) -> String {
    format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff)
}
fn macho(bytes: &[u8], arch: Architecture) -> Result<BinaryObservation> {
    ensure!(
        range(bytes, 0, 4)? == b"\xcf\xfa\xed\xfe",
        "native6 requires a thin little-endian Mach-O 64 binary; fat and swapped binaries are unsupported"
    );
    let machine = u32le(bytes, 4)?;
    ensure!(
        machine
            == match arch {
                Architecture::X86_64 => 0x0100_0007,
                Architecture::Aarch64 => 0x0100_000c,
            },
        "Mach-O architecture differs from target"
    );
    ensure!(u32le(bytes, 12)? == 2, "Mach-O must be an executable");
    let count = u32le(bytes, 16)? as usize;
    let size = u32le(bytes, 20)? as usize;
    ensure!(
        count <= 4096 && size <= 16 * 1024 * 1024,
        "Mach-O load commands exceed bound"
    );
    let commands = range(bytes, 32, size)?;
    let mut cursor = 0usize;
    let mut out = observation(bytes, arch, "mach-o", machine);
    for _ in 0..count {
        let command = u32le(commands, cursor)?;
        let width = u32le(commands, cursor + 4)? as usize;
        ensure!(
            width >= 8 && width.is_multiple_of(8),
            "invalid Mach-O load-command width"
        );
        let value = range(commands, cursor, width)?;
        match command {
            0x0c | 0x8000_0018 | 0x8000_001f | 0x8000_0023 => {
                ensure!(
                    width >= 24 && out.needed.len() < 256,
                    "invalid or oversized Mach-O dylib command"
                );
                let at = u32le(value, 8)? as usize;
                ensure!(at >= 24, "Mach-O dylib string overlaps command header");
                let name = cstr(value, at)?;
                ensure!(!name.is_empty(), "empty Mach-O dependency");
                ensure!(!out.needed.contains(&name), "duplicate Mach-O dependency");
                out.needed.push(name);
            }
            0x0e => {
                ensure!(
                    width >= 16 && out.interpreter.is_none(),
                    "invalid or duplicate Mach-O dynamic linker"
                );
                let at = u32le(value, 8)? as usize;
                ensure!(
                    at >= 12,
                    "Mach-O dynamic linker string overlaps command header"
                );
                out.interpreter = Some(cstr(value, at)?);
            }
            0x8000_001c => {
                out.has_search_path = true;
            }
            0x32 => {
                ensure!(
                    width >= 24 && out.minimum_os.is_none() && u32le(value, 8)? == 1,
                    "unsupported platform or duplicate Mach-O minimum OS command"
                );
                let tools = u32le(value, 20)? as usize;
                ensure!(
                    tools <= 256 && 24 + tools * 8 <= width,
                    "Mach-O build-version tools exceed command"
                );
                out.minimum_os = Some(packed_version(u32le(value, 12)?));
                out.sdk_version = Some(packed_version(u32le(value, 16)?));
            }
            0x24 => {
                ensure!(
                    width == 16 && out.minimum_os.is_none(),
                    "invalid or duplicate Mach-O minimum OS command"
                );
                out.minimum_os = Some(packed_version(u32le(value, 8)?));
                out.sdk_version = Some(packed_version(u32le(value, 12)?));
            }
            _ => {}
        }
        cursor = cursor
            .checked_add(width)
            .context("Mach-O command offset overflow")?;
    }
    ensure!(cursor == size, "Mach-O load-command count and size differ");
    ensure!(
        out.minimum_os.is_some(),
        "Mach-O minimum OS observation is missing"
    );
    out.needed.sort();
    Ok(out)
}
pub fn validate_native_abi(
    binary: &BinaryObservation,
    maximum_minimum_os: &str,
    allowed_needed: &BTreeSet<String>,
) -> Result<()> {
    ensure!(
        matches!(binary.format.as_str(), "pe" | "mach-o"),
        "native SDK ABI check requires PE or Mach-O"
    );
    let observed = numeric_version(
        binary
            .minimum_os
            .as_deref()
            .context("binary lacks minimum OS observation")?,
    )?;
    ensure!(
        !version_exceeds(&observed, &numeric_version(maximum_minimum_os)?),
        "binary minimum OS exceeds the configured compatibility contract"
    );
    for dependency in &binary.needed {
        ensure!(
            allowed_needed.contains(dependency),
            "undeclared native binary dependency: {dependency}"
        );
    }
    Ok(())
}
