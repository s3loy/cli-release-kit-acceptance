//! Bounded ELF observations. ARM attributes describe a linked closure's declared
//! upper bound; they do not prove that every included instruction is reachable.
use crate::catalog::TargetDescriptor;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::Path,
};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BinaryObservation {
    pub format: String,
    pub elf_class: u8,
    pub machine: u16,
    pub flags: u32,
    pub arm_cpu_arch: Option<u64>,
    pub arm_fp_arch: Option<u64>,
    pub arm_simd_arch: Option<u64>,
    pub interpreter: Option<String>,
    pub needed: Vec<String>,
    pub has_search_path: bool,
    pub has_dynamic_plugins: bool,
}
fn u16le(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .context("truncated ELF integer")?
            .try_into()?,
    ))
}
fn u32le(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .context("truncated ELF integer")?
            .try_into()?,
    ))
}
fn uleb(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes
            .get(*cursor)
            .context("truncated ARM attribute integer")?;
        *cursor += 1;
        ensure!(shift < 63 || byte <= 1, "ARM attribute integer overflow");
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    anyhow::bail!("ARM attribute integer overflow")
}
fn ntbs<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a [u8]> {
    let n = bytes
        .get(*cursor..)
        .context("invalid ARM attribute string")?
        .iter()
        .position(|v| *v == 0)
        .context("unterminated ARM attribute string")?;
    let value = &bytes[*cursor..*cursor + n];
    *cursor += n + 1;
    Ok(value)
}
fn set(slot: &mut Option<u64>, value: u64) -> Result<()> {
    ensure!(slot.is_none(), "duplicate ARM file attribute");
    *slot = Some(value);
    Ok(())
}
fn attributes(bytes: &[u8], observed: &mut BinaryObservation) -> Result<()> {
    ensure!(
        bytes.first() == Some(&b'A'),
        "unsupported ARM attributes format"
    );
    let mut cursor = 1;
    while cursor < bytes.len() {
        let start = cursor;
        let size = u32le(bytes, start)? as usize;
        ensure!(size >= 5, "invalid ARM vendor subsection");
        let end = start
            .checked_add(size)
            .context("ARM vendor size overflow")?;
        ensure!(end <= bytes.len(), "ARM vendor subsection exceeds section");
        cursor += 4;
        let vendor = ntbs(&bytes[..end], &mut cursor)?;
        if vendor != b"aeabi" {
            cursor = end;
            continue;
        }
        while cursor < end {
            let sub = cursor;
            let tag = uleb(&bytes[..end], &mut cursor)?;
            let size = u32le(bytes, cursor)? as usize;
            cursor += 4;
            let stop = sub.checked_add(size).context("ARM scope size overflow")?;
            ensure!(
                stop >= cursor && stop <= end,
                "ARM scope exceeds vendor subsection"
            );
            if tag != 1 {
                ensure!(matches!(tag, 2 | 3), "unknown ARM attribute scope");
                cursor = stop;
                continue;
            }
            while cursor < stop {
                let tag = uleb(&bytes[..stop], &mut cursor)?;
                if matches!(tag, 4 | 5) || (tag > 32 && tag % 2 == 1) {
                    ntbs(&bytes[..stop], &mut cursor)?;
                    continue;
                }
                ensure!(
                    (6..=32).contains(&tag) || tag > 32,
                    "invalid ARM file attribute tag"
                );
                let value = uleb(&bytes[..stop], &mut cursor)?;
                match tag {
                    6 => set(&mut observed.arm_cpu_arch, value)?,
                    10 => set(&mut observed.arm_fp_arch, value)?,
                    12 => set(&mut observed.arm_simd_arch, value)?,
                    32 => {
                        ntbs(&bytes[..stop], &mut cursor)?;
                    }
                    _ => {}
                }
            }
            ensure!(cursor == stop, "ARM attribute scope boundary differs");
        }
        ensure!(cursor == end, "ARM attribute vendor boundary differs");
    }
    Ok(())
}
pub fn observe(path: &Path, target: &TargetDescriptor) -> Result<Option<BinaryObservation>> {
    if target.os != "linux" {
        return Ok(None);
    }
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= 512 * 1024 * 1024,
        "ELF input must be a bounded regular file"
    );
    let mut file = File::open(path)?;
    let mut header = [0u8; 64];
    file.read_exact(&mut header)?;
    ensure!(
        &header[..4] == b"\x7fELF" && header[5] == 1 && header[6] == 1,
        "expected little-endian ELF version 1"
    );
    let (class, machine) = match target.arch.as_str() {
        "armv6" | "armv7" => (1, 40),
        "386" | "i686" => (1, 3),
        "x86_64" => (2, 62),
        "aarch64" => (2, 183),
        _ => anyhow::bail!("unsupported ELF target architecture"),
    };
    ensure!(
        header[4] == class && u16le(&header, 18)? == machine,
        "built binary ELF class or machine differs from target"
    );
    ensure!(
        matches!(u16le(&header, 16)?, 2 | 3),
        "ELF binary must be executable or position-independent executable"
    );
    let flags = u32le(&header, if class == 1 { 36 } else { 48 })?;
    let mut observed = BinaryObservation {
        format: "elf".into(),
        elf_class: class,
        machine,
        flags,
        arm_cpu_arch: None,
        arm_fp_arch: None,
        arm_simd_arch: None,
        interpreter: None,
        needed: Vec::new(),
        has_search_path: false,
        has_dynamic_plugins: false,
    };
    if machine == 40 {
        ensure!(
            flags & 0xff00_0000 == 0x0500_0000,
            "ARM binary must declare EABI version 5"
        );
        if target.builder == "rust" {
            match target.c_abi.as_str() {
                "eabi-soft" => ensure!(
                    flags & 0x400 == 0,
                    "soft-float Rust binary declares hard-float C ABI"
                ),
                "eabi-hard" => ensure!(
                    flags & 0x400 != 0 && flags & 0x200 == 0,
                    "hard-float Rust binary lacks hard-float C ABI"
                ),
                _ => {}
            }
        }
        let offset = u32le(&header, 32)? as u64;
        let width = u16le(&header, 46)? as u64;
        let count = u16le(&header, 48)? as u64;
        ensure!(
            count <= 4096 && (count == 0 || width == 40),
            "unsupported or oversized ELF section table"
        );
        ensure!(
            offset
                .checked_add(width * count)
                .is_some_and(|n| n <= meta.len()),
            "ELF section table exceeds binary"
        );
        let mut found = false;
        for i in 0..count {
            file.seek(SeekFrom::Start(offset + i * width))?;
            let mut sh = [0u8; 40];
            file.read_exact(&mut sh)?;
            if u32le(&sh, 4)? != 0x7000_0003 {
                continue;
            }
            ensure!(!found, "duplicate ARM attributes sections");
            found = true;
            let at = u32le(&sh, 16)? as u64;
            let size = u32le(&sh, 20)? as u64;
            ensure!(
                size <= 1024 * 1024 && at.checked_add(size).is_some_and(|n| n <= meta.len()),
                "ARM attributes exceed binary or allocation limit"
            );
            file.seek(SeekFrom::Start(at))?;
            let mut bytes = vec![0; size as usize];
            file.read_exact(&mut bytes)?;
            attributes(&bytes, &mut observed)?;
        }
    }
    dynamic(&mut file, &header, class, meta.len(), &mut observed)?;
    Ok(Some(observed))
}
fn u64le(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at + 8)
            .context("truncated ELF integer")?
            .try_into()?,
    ))
}
fn dynamic(
    file: &mut File,
    header: &[u8],
    class: u8,
    length: u64,
    observed: &mut BinaryObservation,
) -> Result<()> {
    let (at, width, count) = if class == 1 {
        (
            u32le(header, 28)? as u64,
            u16le(header, 42)? as u64,
            u16le(header, 44)? as u64,
        )
    } else {
        (
            u64le(header, 32)?,
            u16le(header, 54)? as u64,
            u16le(header, 56)? as u64,
        )
    };
    ensure!(
        count <= 1024
            && (count == 0 || width == if class == 1 { 32 } else { 56 })
            && at.checked_add(width * count).is_some_and(|n| n <= length),
        "ELF program header table exceeds bounds"
    );
    let mut loads = Vec::new();
    let mut dyn_segment = None;
    for i in 0..count {
        file.seek(SeekFrom::Start(at + i * width))?;
        let mut bytes = vec![0u8; width as usize];
        file.read_exact(&mut bytes)?;
        let kind = u32le(&bytes, 0)?;
        let (offset, address, size) = if class == 1 {
            (
                u32le(&bytes, 4)? as u64,
                u32le(&bytes, 8)? as u64,
                u32le(&bytes, 16)? as u64,
            )
        } else {
            (u64le(&bytes, 8)?, u64le(&bytes, 16)?, u64le(&bytes, 32)?)
        };
        ensure!(
            offset.checked_add(size).is_some_and(|n| n <= length),
            "ELF segment exceeds binary"
        );
        match kind {
            1 => loads.push((address, offset, size)),
            2 => {
                ensure!(
                    dyn_segment.is_none() && size <= 1024 * 1024,
                    "duplicate or oversized ELF dynamic segment"
                );
                dyn_segment = Some((offset, size));
            }
            3 => {
                ensure!(
                    observed.interpreter.is_none() && (2..=4096).contains(&size),
                    "duplicate or oversized ELF interpreter"
                );
                file.seek(SeekFrom::Start(offset))?;
                let mut bytes = vec![0u8; size as usize];
                file.read_exact(&mut bytes)?;
                ensure!(
                    bytes.last() == Some(&0) && !bytes[..bytes.len() - 1].contains(&0),
                    "invalid ELF interpreter string"
                );
                observed.interpreter = Some(String::from_utf8(bytes[..bytes.len() - 1].to_vec())?);
            }
            _ => {}
        }
    }
    let Some((at, size)) = dyn_segment else {
        return Ok(());
    };
    let stride = if class == 1 { 8 } else { 16 };
    ensure!(size % stride == 0, "unaligned ELF dynamic segment");
    file.seek(SeekFrom::Start(at))?;
    let mut bytes = vec![0u8; size as usize];
    file.read_exact(&mut bytes)?;
    let mut string_address = None;
    let mut string_size = None;
    let mut needed = Vec::new();
    let mut ended = false;
    for item in bytes.chunks_exact(stride as usize) {
        let (tag, value) = if class == 1 {
            (u32le(item, 0)? as u64, u32le(item, 4)? as u64)
        } else {
            (u64le(item, 0)?, u64le(item, 8)?)
        };
        match tag {
            0 => {
                ended = true;
                break;
            }
            1 => {
                ensure!(needed.len() < 256, "too many ELF dependencies");
                needed.push(value);
            }
            5 => {
                ensure!(
                    string_address.replace(value).is_none(),
                    "duplicate ELF string table"
                );
            }
            10 => {
                ensure!(
                    string_size.replace(value).is_none(),
                    "duplicate ELF string table size"
                );
            }
            15 | 29 => observed.has_search_path = true,
            0x7fff_fffd | 0x7fff_ffff | 0x6fff_fefb | 0x6fff_fefc => {
                observed.has_dynamic_plugins = true
            }
            _ => {}
        }
    }
    ensure!(ended, "unterminated ELF dynamic segment");
    if needed.is_empty() {
        return Ok(());
    }
    let address = string_address.context("ELF dependencies lack string table")?;
    let size = string_size.context("ELF string table lacks size")?;
    ensure!(
        size <= 16 * 1024 * 1024,
        "ELF dynamic string table exceeds bound"
    );
    let candidates = loads
        .iter()
        .filter_map(|(base, offset, length)| {
            address
                .checked_sub(*base)
                .filter(|n| n.checked_add(size).is_some_and(|v| v <= *length))
                .map(|delta| *offset + delta)
        })
        .collect::<Vec<_>>();
    ensure!(
        candidates.len() == 1,
        "ELF dynamic string table is unmapped or ambiguous"
    );
    file.seek(SeekFrom::Start(candidates[0]))?;
    let mut strings = vec![0u8; size as usize];
    file.read_exact(&mut strings)?;
    for offset in needed {
        let mut at = usize::try_from(offset)?;
        let value = std::str::from_utf8(ntbs(&strings, &mut at)?)?.to_owned();
        ensure!(
            !value.is_empty()
                && !value.contains('/')
                && !value.contains('\\')
                && value != "."
                && value != "..",
            "ELF dependency must be a basename"
        );
        crate::config::relative(&value)?;
        ensure!(
            !observed.needed.contains(&value),
            "duplicate ELF dependency"
        );
        observed.needed.push(value);
    }
    Ok(())
}

/// Conservative native ARM guard. A linked FP attribute can overstate reachable
/// code; rejecting a weaker native runner is safer than assuming it is unused.
pub fn validate_native_fpu(
    target: &TargetDescriptor,
    observation: Option<&BinaryObservation>,
    cpu: &str,
) -> Result<()> {
    if !matches!(target.arch.as_str(), "armv6" | "armv7") || target.fpu == "none" {
        return Ok(());
    }
    let features = cpu
        .lines()
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| k.trim() == "Features")
        .map(|(_, v)| {
            v.split_whitespace()
                .collect::<std::collections::BTreeSet<_>>()
        })
        .collect::<Vec<_>>();
    ensure!(
        !features.is_empty(),
        "native ARM FPU feature evidence unavailable"
    );
    let fp = observation.and_then(|v| v.arm_fp_arch);
    for flags in features {
        let vfp3 = flags.contains("vfpv3")
            || flags.contains("vfpv3d16")
            || flags.contains("vfpv4")
            || flags.contains("neon");
        let full32 = flags.contains("neon")
            || ((flags.contains("vfpv3") || flags.contains("vfpv4"))
                && !flags.contains("vfpv3d16"));
        match fp {
            Some(0) => {}
            Some(1 | 2) => ensure!(flags.contains("vfp"), "native runner lacks VFPv2"),
            Some(3) => ensure!(
                vfp3 && full32,
                "ELF declares VFPv3 with D0-D31; D16-only native runtime is unqualified"
            ),
            Some(4) => ensure!(vfp3, "ELF declares VFPv3-D16"),
            Some(5) => ensure!(
                (flags.contains("vfpv4") || flags.contains("neon")) && full32,
                "ELF declares VFPv4 with D0-D31"
            ),
            Some(6) => ensure!(flags.contains("vfpv4"), "ELF declares VFPv4-D16"),
            Some(_) => {
                anyhow::bail!("native ARM FP attribute is outside supported runtime capabilities")
            }
            None if target.fpu.contains("vfpv3") => ensure!(
                vfp3 && (!target.builder.eq("rust") || full32),
                "native ARM target needs VFPv3; Rust D16-only qualification is unavailable"
            ),
            None => ensure!(flags.contains("vfp"), "native ARM target needs VFP"),
        }
        if observation
            .and_then(|v| v.arm_simd_arch)
            .is_some_and(|v| v > 0)
        {
            ensure!(
                flags.contains("neon"),
                "ELF declares NEON but native CPU does not"
            );
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn arm(fp: u8) -> Vec<u8> {
        let mut attributes = vec![b'A'];
        let values = vec![6, 10, 10, fp, 12, 0];
        let mut scope = vec![1];
        scope.extend(((5 + values.len()) as u32).to_le_bytes());
        scope.extend(values);
        attributes.extend(((4 + 6 + scope.len()) as u32).to_le_bytes());
        attributes.extend(b"aeabi\0");
        attributes.extend(scope);
        let mut bytes = vec![0u8; 64 + 40];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 1;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&40u16.to_le_bytes());
        bytes[32..36].copy_from_slice(&64u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&0x0500_0400u32.to_le_bytes());
        bytes[46..48].copy_from_slice(&40u16.to_le_bytes());
        bytes[48..50].copy_from_slice(&1u16.to_le_bytes());
        bytes[68..72].copy_from_slice(&0x7000_0003u32.to_le_bytes());
        bytes[80..84].copy_from_slice(&104u32.to_le_bytes());
        bytes[84..88].copy_from_slice(&(attributes.len() as u32).to_le_bytes());
        bytes.extend(attributes);
        bytes
    }
    #[test]
    fn actual_machine_abi_and_arm_fp_attribute_are_bound() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("binary");
        fs::write(&path, arm(3)).unwrap();
        let target = crate::catalog::resolve("linux-armv7-gnueabihf").unwrap();
        let observation = observe(&path, &target).unwrap().unwrap();
        assert_eq!(observation.arm_cpu_arch, Some(10));
        assert_eq!(observation.arm_fp_arch, Some(3));
        assert!(
            validate_native_fpu(
                &target,
                Some(&observation),
                "Features : vfp vfpv3 vfpv3d16\n"
            )
            .is_err()
        );
        validate_native_fpu(
            &target,
            Some(&observation),
            "Features : vfp vfpv3 vfpv4 neon\n",
        )
        .unwrap();
        assert!(observe(&path, &crate::catalog::resolve("linux-i686-gnu").unwrap()).is_err());
        assert!(
            observe(
                &path,
                &crate::catalog::resolve("linux-armv7-gnueabi").unwrap()
            )
            .is_err()
        );
        let mut corrupt = arm(3);
        corrupt[84..88].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&path, corrupt).unwrap();
        assert!(observe(&path, &target).is_err());
    }
    #[test]
    fn soft_float_does_not_mistake_linked_fp_attributes_for_reachable_instructions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("binary");
        let mut bytes = arm(3);
        bytes[36..40].copy_from_slice(&0x0500_0200u32.to_le_bytes());
        fs::write(&path, bytes).unwrap();
        let target = crate::catalog::resolve("linux-armv7-gnueabi").unwrap();
        let observation = observe(&path, &target).unwrap().unwrap();
        assert_eq!(observation.arm_fp_arch, Some(3));
        validate_native_fpu(&target, Some(&observation), "Features :\n").unwrap();
    }
}
