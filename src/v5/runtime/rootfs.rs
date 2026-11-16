//! The pinned ELF loader dependency closure. This is a library-loading contract,
//! not a sandbox for application file access or application-driven dlopen.
use super::{BinaryObservation, elf};
use crate::{catalog::TargetDescriptor, cohort::io, config::safe_join, source};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::Path,
};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootfsFile {
    pub sha256: String,
    pub binary: BinaryObservation,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RootfsClosure {
    pub interpreter: String,
    pub library_directories: Vec<String>,
    pub resolutions: BTreeMap<String, String>,
    pub files: BTreeMap<String, RootfsFile>,
    pub loading_contract: String,
    pub preload_file_sha256: String,
}
const CONTRACT: &str = "explicit pinned LD_LIBRARY_PATH and empty pinned /etc/ld.so.preload; no RPATH/RUNPATH/audit/filter; application dlopen and file access are outside this closure; not a sandbox";
fn dependencies(value: &BinaryObservation) -> Result<()> {
    ensure!(
        !value.has_search_path,
        "controlled rootfs does not support ELF RPATH or RUNPATH"
    );
    ensure!(
        !value.has_dynamic_plugins,
        "controlled rootfs does not support ELF audit, filter or auxiliary libraries"
    );
    ensure!(value.needed.len() <= 256, "too many ELF dependencies");
    for name in &value.needed {
        crate::config::relative(name)?;
        ensure!(
            !name.contains('/') && !name.contains('\\'),
            "ELF dependency must be a basename"
        );
    }
    Ok(())
}
fn parent(name: &str) -> String {
    name.rsplit_once('/').map(|(p, _)| p).unwrap_or(".").into()
}
fn relative_interpreter(program: &BinaryObservation) -> Result<String> {
    let name = program
        .interpreter
        .as_deref()
        .context("GNU binary must declare an ELF interpreter")?;
    let relative = name
        .strip_prefix('/')
        .context("ELF interpreter must be an absolute rootfs path")?;
    crate::config::relative(relative)?;
    Ok(relative.into())
}
pub fn prepare(
    root: &Path,
    target: &TargetDescriptor,
    program: &BinaryObservation,
) -> Result<RootfsClosure> {
    dependencies(program)?;
    let interpreter = relative_interpreter(program)?;
    let inventory = io::inventory(root)?;
    ensure!(inventory.len() <= 20_000, "rootfs inventory exceeds bound");
    let preload=inventory.get("etc/ld.so.preload").context("materialized rootfs must contain an empty regular etc/ld.so.preload to prevent host preload fallback")?;
    ensure!(
        preload.size == 0 && preload.sha256 == source::digest(b""),
        "rootfs etc/ld.so.preload must be empty"
    );
    ensure!(
        inventory.contains_key(&interpreter),
        "pinned rootfs lacks program interpreter"
    );
    let directories = inventory
        .keys()
        .map(|p| parent(p))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    ensure!(
        directories.len() <= 256,
        "rootfs has too many library search directories"
    );
    let mut closure = RootfsClosure {
        interpreter: interpreter.clone(),
        library_directories: directories,
        resolutions: BTreeMap::new(),
        files: BTreeMap::new(),
        loading_contract: CONTRACT.into(),
        preload_file_sha256: preload.sha256.clone(),
    };
    let mut pending = VecDeque::from([interpreter]);
    let mut needed = program.needed.clone();
    loop {
        for name in std::mem::take(&mut needed) {
            if closure.resolutions.contains_key(&name) {
                continue;
            }
            let found = closure
                .library_directories
                .iter()
                .map(|dir| {
                    if dir == "." {
                        name.clone()
                    } else {
                        format!("{dir}/{name}")
                    }
                })
                .find(|candidate| inventory.contains_key(candidate))
                .with_context(|| format!("pinned rootfs lacks required ELF library: {name}"))?;
            closure.resolutions.insert(name, found.clone());
            pending.push_back(found);
        }
        let Some(name) = pending.pop_front() else {
            break;
        };
        if closure.files.contains_key(&name) {
            continue;
        }
        ensure!(
            closure.files.len() < 512,
            "ELF dependency closure exceeds bound"
        );
        let filename = safe_join(root, &name)?;
        let binary = elf::observe(&filename, target)?.context("expected Linux ELF dependency")?;
        dependencies(&binary)?;
        ensure!(
            binary
                .interpreter
                .as_ref()
                .is_none_or(|value| program.interpreter.as_ref() == Some(value)),
            "ELF dependency declares another program interpreter"
        );
        needed.extend(binary.needed.iter().cloned());
        closure.files.insert(
            name,
            RootfsFile {
                sha256: source::file_digest(&filename)?,
                binary,
            },
        );
    }
    validate(&closure, target, program)?;
    Ok(closure)
}
pub fn library_path(root: &Path, closure: &RootfsClosure) -> Result<String> {
    ensure!(root.is_absolute(), "runtime rootfs path must be absolute");
    let values = closure
        .library_directories
        .iter()
        .map(|directory| {
            let value = if directory == "." {
                root.to_path_buf()
            } else {
                crate::config::relative(directory)?;
                root.join(directory)
            };
            let value = value
                .to_str()
                .context("non-UTF8 rootfs library path")?
                .to_owned();
            ensure!(
                !value.contains(':'),
                "rootfs path cannot contain LD_LIBRARY_PATH separators"
            );
            Ok(value)
        })
        .collect::<Result<Vec<_>>>()?;
    let joined = values.join(":");
    ensure!(
        !joined.is_empty() && joined.len() <= 32 * 1024,
        "rootfs library search path exceeds bound"
    );
    Ok(joined)
}
pub fn validate(
    closure: &RootfsClosure,
    target: &TargetDescriptor,
    program: &BinaryObservation,
) -> Result<()> {
    dependencies(program)?;
    ensure!(
        closure.interpreter == relative_interpreter(program)?
            && closure.loading_contract == CONTRACT
            && closure.preload_file_sha256 == source::digest(b""),
        "rootfs loader contract differs"
    );
    ensure!(
        !closure.library_directories.is_empty()
            && closure.library_directories.len() <= 256
            && closure.library_directories.windows(2).all(|p| p[0] < p[1]),
        "invalid rootfs library directory set"
    );
    for directory in &closure.library_directories {
        if directory != "." {
            crate::config::relative(directory)?;
        }
    }
    ensure!(
        !closure.files.is_empty() && closure.files.len() <= 512 && closure.resolutions.len() <= 512,
        "invalid rootfs dependency closure size"
    );
    let mut pending = VecDeque::from([closure.interpreter.clone()]);
    let mut needed = program.needed.clone();
    let mut visited = BTreeSet::new();
    let mut resolved = BTreeSet::new();
    loop {
        for name in std::mem::take(&mut needed) {
            let file = closure
                .resolutions
                .get(&name)
                .with_context(|| format!("missing rootfs dependency resolution: {name}"))?;
            crate::config::relative(file)?;
            ensure!(
                file.rsplit('/').next() == Some(name.as_str())
                    && closure.library_directories.contains(&parent(file)),
                "rootfs resolution differs from explicit library path"
            );
            resolved.insert(name);
            pending.push_back(file.clone());
        }
        let Some(name) = pending.pop_front() else {
            break;
        };
        if !visited.insert(name.clone()) {
            continue;
        }
        crate::config::relative(&name)?;
        let value = closure
            .files
            .get(&name)
            .context("missing rootfs dependency observation")?;
        ensure!(
            super::super::run::is_digest(&value.sha256),
            "invalid rootfs dependency digest"
        );
        let expected = match target.arch.as_str() {
            "armv6" | "armv7" => (1, 40),
            "i686" | "386" => (1, 3),
            "x86_64" => (2, 62),
            "aarch64" => (2, 183),
            _ => anyhow::bail!("unknown rootfs target"),
        };
        ensure!(
            (value.binary.elf_class, value.binary.machine) == expected
                && value.binary.format == "elf"
                && value
                    .binary
                    .interpreter
                    .as_ref()
                    .is_none_or(|value| program.interpreter.as_ref() == Some(value)),
            "rootfs library ELF architecture or declared interpreter differs"
        );
        if expected.1 == 40 {
            ensure!(
                value.binary.flags & 0xff00_0000 == 0x0500_0000,
                "rootfs library EABI differs"
            );
            match target.c_abi.as_str() {
                "eabi-soft" => ensure!(
                    value.binary.flags & 0x400 == 0,
                    "rootfs library hard-float ABI differs"
                ),
                "eabi-hard" => ensure!(
                    value.binary.flags & 0x400 != 0 && value.binary.flags & 0x200 == 0,
                    "rootfs library lacks hard-float ABI"
                ),
                _ => {}
            }
        }
        dependencies(&value.binary)?;
        needed.extend(value.binary.needed.iter().cloned());
    }
    ensure!(
        visited.len() == closure.files.len() && resolved.len() == closure.resolutions.len(),
        "rootfs witness contains unused files or resolutions"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    fn binary() -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 1;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&3u16.to_le_bytes());
        bytes
    }
    #[test]
    fn loader_and_needed_closure_require_pinned_files_and_reject_rpath() {
        let directory = tempfile::tempdir().unwrap();
        fs::create_dir(directory.path().join("lib")).unwrap();
        fs::create_dir(directory.path().join("etc")).unwrap();
        fs::write(directory.path().join("etc/ld.so.preload"), b"").unwrap();
        let loader = directory.path().join("lib/ld.so");
        fs::write(&loader, binary()).unwrap();
        fs::write(directory.path().join("lib/libc.so.6"), binary()).unwrap();
        let target = crate::catalog::resolve("linux-i686-gnu").unwrap();
        let mut program = elf::observe(&loader, &target).unwrap().unwrap();
        program.interpreter = Some("/lib/ld.so".into());
        program.needed = vec!["libc.so.6".into()];
        let closure = prepare(directory.path(), &target, &program).unwrap();
        assert_eq!(closure.files.len(), 2);
        assert_eq!(closure.resolutions["libc.so.6"], "lib/libc.so.6");
        validate(&closure, &target, &program).unwrap();
        let mut wrong = closure.clone();
        wrong
            .resolutions
            .insert("unused.so".into(), "lib/libc.so.6".into());
        assert!(validate(&wrong, &target, &program).is_err());
        fs::write(directory.path().join("etc/ld.so.preload"), b"external.so\n").unwrap();
        assert!(prepare(directory.path(), &target, &program).is_err());
        fs::remove_file(directory.path().join("etc/ld.so.preload")).unwrap();
        assert!(prepare(directory.path(), &target, &program).is_err());
        fs::write(directory.path().join("etc/ld.so.preload"), b"").unwrap();
        fs::remove_file(directory.path().join("lib/libc.so.6")).unwrap();
        assert!(prepare(directory.path(), &target, &program).is_err());
        fs::write(directory.path().join("lib/libc.so.6"), binary()).unwrap();
        program.has_search_path = true;
        assert!(prepare(directory.path(), &target, &program).is_err());
    }
}
