//! Explicit native or controlled-emulator runtime contracts for protocol 5.
mod elf;
mod rootfs;
#[cfg(any(windows, test))]
mod windows;
use super::model::{Emulator, RuntimeConstraint, RuntimeMode};
use crate::{catalog::TargetDescriptor, process, source, v2::model::CommandSpec};
use anyhow::{Context, Result, ensure};
pub use elf::{BinaryObservation, observe as observe_binary};
pub use rootfs::RootfsClosure;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Default)]
pub struct RuntimeTools {
    pub emulators: BTreeMap<String, PathBuf>,
    pub rootfs: BTreeMap<String, PathBuf>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEvidence {
    pub schema: u32,
    pub task: String,
    pub target: String,
    pub descriptor_id: String,
    pub constraint_id: String,
    pub mode: RuntimeMode,
    pub program_sha256: String,
    pub binary_observation: Option<BinaryObservation>,
    pub command: CommandSpec,
    pub runner_sha256: Option<String>,
    pub runner_version: Option<String>,
    pub cpu: String,
    pub fpu: String,
    pub rootfs_sha256: Option<String>,
    pub rootfs_closure: Option<RootfsClosure>,
    pub actual_argv: Vec<String>,
    pub host_os: String,
    pub host_arch: String,
    pub host_kernel_arch: String,
    pub host_cpu: String,
    pub timeout_seconds: u64,
    pub outcome: String,
    pub log_reference: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
}
pub fn emulator_name(value: Emulator) -> &'static str {
    match value {
        Emulator::QemuArm => "qemu-arm",
        Emulator::QemuI386 => "qemu-i386",
    }
}
pub fn constraint_id(value: &RuntimeConstraint) -> Result<String> {
    super::proof::content_id(b"cli-release-kit/v5-runtime-constraint/v1\0", value)
}
pub fn descriptor_id(value: &TargetDescriptor) -> Result<String> {
    super::proof::content_id(b"cli-release-kit/v5-target-descriptor/v1\0", value)
}

/// Identity of a materialized rootfs. Symlinks and special files are rejected;
/// callers must copy the loader and library link targets into regular files.
pub fn rootfs_id(root: &Path) -> Result<String> {
    let meta = fs::symlink_metadata(root)?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "rootfs must be a materialized regular directory"
    );
    #[derive(Serialize)]
    struct Entry {
        kind: &'static str,
        mode: u32,
        size: u64,
        sha256: Option<String>,
    }
    fn walk(
        root: &Path,
        dir: &Path,
        entries: &mut BTreeMap<String, Entry>,
        bytes: &mut u64,
    ) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            let name = path
                .strip_prefix(root)?
                .to_str()
                .context("non-UTF8 rootfs path")?
                .replace('\\', "/");
            crate::config::relative(&name)?;
            ensure!(
                name.len() <= 4096 && name.split('/').count() <= 32 && entries.len() < 20_000,
                "rootfs exceeds identity bounds"
            );
            let meta = fs::symlink_metadata(&path)?;
            ensure!(
                !meta.file_type().is_symlink() && (meta.is_file() || meta.is_dir()),
                "rootfs contains a symlink or special file: {name}"
            );
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode() & 0o7777
            };
            #[cfg(not(unix))]
            let mode = if meta.is_dir() { 0o755 } else { 0o644 };
            let value = if meta.is_dir() {
                Entry {
                    kind: "directory",
                    mode,
                    size: 0,
                    sha256: None,
                }
            } else {
                *bytes = bytes
                    .checked_add(meta.len())
                    .context("rootfs size overflow")?;
                ensure!(
                    meta.len() <= 512 * 1024 * 1024 && *bytes <= 4 * 1024 * 1024 * 1024,
                    "rootfs exceeds size bounds"
                );
                Entry {
                    kind: "file",
                    mode,
                    size: meta.len(),
                    sha256: Some(source::file_digest(&path)?),
                }
            };
            entries.insert(name, value);
            if meta.is_dir() {
                walk(root, &path, entries, bytes)?;
            }
        }
        Ok(())
    }
    let mut entries = BTreeMap::new();
    walk(root, root, &mut entries, &mut 0)?;
    ensure!(!entries.is_empty(), "empty runtime rootfs");
    #[cfg(unix)]
    let root_mode = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o7777
    };
    #[cfg(not(unix))]
    let root_mode = 0o755;
    entries.insert(
        ".".into(),
        Entry {
            kind: "directory",
            mode: root_mode,
            size: 0,
            sha256: None,
        },
    );
    let folded = entries
        .keys()
        .map(|v| v.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    ensure!(
        folded.len() == entries.len(),
        "case-colliding rootfs entries"
    );
    super::proof::content_id(b"cli-release-kit/v5-materialized-rootfs/v1\0", &entries)
}
fn host_platform() -> Result<(String, String)> {
    #[cfg(unix)]
    {
        let mut value = std::mem::MaybeUninit::<libc::utsname>::zeroed();
        ensure!(
            unsafe { libc::uname(value.as_mut_ptr()) } == 0,
            "runtime kernel identity unavailable"
        );
        let value = unsafe { value.assume_init() };
        let os = unsafe { std::ffi::CStr::from_ptr(value.sysname.as_ptr()) }
            .to_str()?
            .to_ascii_lowercase();
        let machine = unsafe { std::ffi::CStr::from_ptr(value.machine.as_ptr()) }.to_str()?;
        let arch = match machine {
            "arm64" | "aarch64" => "aarch64",
            "amd64" | "x86_64" => "x86_64",
            "i386" | "i486" | "i586" | "i686" => "x86",
            v if v.starts_with("arm") => "arm",
            v => v,
        };
        Ok((
            if os == "darwin" { "macos".into() } else { os },
            arch.into(),
        ))
    }
    #[cfg(windows)]
    {
        let machine =
            windows::observe().context("observe Windows native/process machine identity")?;
        ensure!(
            machine.process == std::env::consts::ARCH,
            "Windows process machine differs from running executable architecture"
        );
        Ok(("windows".into(), machine.native.into()))
    }
    #[cfg(not(any(unix, windows)))]
    {
        anyhow::bail!("runtime kernel machine observation is unsupported on this platform")
    }
}
fn host_cpu() -> String {
    #[cfg(target_os = "linux")]
    {
        fs::read_to_string("/proc/cpuinfo").unwrap_or_default()
    }
    #[cfg(target_os = "macos")]
    {
        let mut size = 0usize;
        let result = unsafe {
            libc::sysctlbyname(
                c"machdep.cpu.brand_string".as_ptr(),
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if result != 0 || size == 0 || size > 4096 {
            return String::new();
        }
        let mut bytes = vec![0u8; size];
        let result = unsafe {
            libc::sysctlbyname(
                c"machdep.cpu.brand_string".as_ptr(),
                bytes.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if result != 0 {
            return String::new();
        }
        String::from_utf8_lossy(&bytes[..size])
            .trim_end_matches('\0')
            .to_owned()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        std::env::consts::ARCH.into()
    }
}
fn emulator_fpu(cpu: &str) -> Result<&'static str> {
    match cpu {
        "arm1176,vfp=off" | "cortex-a7,vfp=off" => Ok("none"),
        "arm1176" => Ok("vfpv2"),
        "cortex-a7" => Ok("vfpv4/neon"),
        "qemu32" => Ok("x87/sse2"),
        _ => anyhow::bail!("unknown controlled CPU/FPU profile"),
    }
}
fn native_fpu(cpu: &str) -> String {
    let features = cpu
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(key, _)| matches!(key.trim(), "flags" | "Features"))
        .map(|(_, value)| value.trim())
        .collect::<BTreeSet<_>>();
    if features.is_empty() {
        format!("architectural-{}", std::env::consts::ARCH)
    } else {
        features.into_iter().collect::<Vec<_>>().join(" | ")
    }
}
fn validate_native_claim(target: &TargetDescriptor, os: &str, arch: &str, cpu: &str) -> Result<()> {
    ensure!(
        target.os == os,
        "native runtime operating system differs; choose controlled emulation or build-only"
    );
    let expected = match target.arch.as_str() {
        "armv6" | "armv7" => "arm",
        "386" | "i686" => "x86",
        value => value,
    };
    ensure!(
        arch == expected,
        "native runtime process architecture differs; implicit binfmt is not runtime evidence"
    );
    ensure!(!cpu.trim().is_empty(), "native CPU evidence unavailable");
    if target.os == "linux" {
        let words = cpu
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .collect::<BTreeSet<_>>();
        if matches!(target.arch.as_str(), "386" | "i686" | "x86_64") {
            ensure!(words.contains("sse2"), "native target requires SSE2");
        }
        if matches!(target.arch.as_str(), "armv6" | "armv7") {
            let levels = cpu
                .lines()
                .filter_map(|l| l.split_once(':'))
                .filter(|(k, _)| k.trim() == "CPU architecture")
                .map(|(_, v)| v.trim().parse::<u32>())
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("native ARM architecture evidence unavailable")?;
            ensure!(
                !levels.is_empty()
                    && levels
                        .iter()
                        .all(|level| *level >= if target.arch == "armv7" { 7 } else { 6 }),
                "native ARM CPU below target floor"
            );
            if target.fpu != "none" {
                ensure!(
                    words.contains("vfp") || words.contains("vfpv3") || words.contains("vfpv4"),
                    "native ARM FPU evidence unavailable"
                );
            }
        }
    }
    Ok(())
}
pub(crate) fn native_host(target: &TargetDescriptor) -> Result<String> {
    #[cfg(target_os = "macos")]
    {
        let mut translated = 0i32;
        let mut size = std::mem::size_of::<i32>();
        let result = unsafe {
            libc::sysctlbyname(
                c"sysctl.proc_translated".as_ptr(),
                (&mut translated as *mut i32).cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        ensure!(
            (result == 0 && translated == 0)
                || (result != 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)),
            "Rosetta or unknown process translation cannot provide native runtime evidence"
        );
    }
    let cpu = host_cpu();
    let (os, kernel_arch) = host_platform()?;
    ensure!(
        kernel_arch == std::env::consts::ARCH,
        "native process and kernel architectures differ; transparent translation is not native evidence"
    );
    validate_native_claim(target, &os, std::env::consts::ARCH, &cpu)?;
    Ok(cpu)
}
pub fn validate_evidence(
    target: &TargetDescriptor,
    constraint: &RuntimeConstraint,
    evidence: &RuntimeEvidence,
    task: &str,
    command: &CommandSpec,
    program_sha256: &str,
    timeout: u64,
) -> Result<()> {
    ensure!(
        evidence.schema == 5
            && evidence.task == task
            && evidence.target == target.id
            && evidence.descriptor_id == descriptor_id(target)?
            && evidence.constraint_id == constraint_id(constraint)?
            && evidence.mode == constraint.mode
            && evidence.program_sha256 == program_sha256
            && evidence.command == *command
            && evidence.timeout_seconds == timeout
            && evidence.outcome == "succeeded"
            && evidence.log_reference == format!("runtime/{task}.json"),
        "runtime evidence contract differs"
    );
    ensure!(
        super::run::is_digest(&evidence.stdout_sha256)
            && super::run::is_digest(&evidence.stderr_sha256)
            && !evidence.fpu.trim().is_empty(),
        "runtime output or FPU identity invalid"
    );
    if constraint.mode == RuntimeMode::Emulated {
        ensure!(
            evidence.actual_argv.len() >= 4
                && Path::new(&evidence.actual_argv[0]).is_absolute()
                && evidence.actual_argv[1] == "-cpu"
                && Some(&evidence.actual_argv[2]) == constraint.cpu.as_ref(),
            "runtime emulator command differs"
        );
    } else {
        ensure!(
            !evidence.actual_argv.is_empty() && Path::new(&evidence.actual_argv[0]).is_absolute(),
            "native command identity missing"
        );
    }
    if constraint.rootfs_sha256.is_some() {
        let closure = evidence
            .rootfs_closure
            .as_ref()
            .context("missing runtime rootfs dependency closure")?;
        rootfs::validate(
            closure,
            target,
            evidence
                .binary_observation
                .as_ref()
                .context("missing GNU binary observation")?,
        )?;
        ensure!(
            evidence.actual_argv.len() >= 8
                && evidence.actual_argv[1] == "-cpu"
                && Some(&evidence.actual_argv[2]) == constraint.cpu.as_ref()
                && evidence.actual_argv[3] == "-L"
                && evidence.actual_argv[5] == "-E"
                && evidence.actual_argv[6]
                    == format!(
                        "LD_LIBRARY_PATH={}",
                        rootfs::library_path(Path::new(&evidence.actual_argv[4]), closure)?
                    ),
            "runtime rootfs command contract differs"
        );
    } else {
        ensure!(
            evidence.rootfs_closure.is_none(),
            "unused rootfs closure evidence"
        );
    }
    match constraint.mode {
        RuntimeMode::Emulated => ensure!(
            evidence.fpu
                == emulator_fpu(constraint.cpu.as_deref().context("missing emulated CPU")?)?
                && evidence.runner_sha256 == constraint.emulator_sha256
                && evidence.rootfs_sha256 == constraint.rootfs_sha256
                && evidence.cpu == *constraint.cpu.as_ref().context("missing emulated CPU")?
                && evidence
                    .runner_version
                    .as_ref()
                    .is_some_and(|v| v.contains("qemu") || v.contains("QEMU")),
            "emulated runtime identity differs"
        ),
        RuntimeMode::Native => {
            ensure!(
                evidence.host_kernel_arch == evidence.host_arch,
                "native evidence has translated process architecture"
            );
            let arch = match target.arch.as_str() {
                "armv6" | "armv7" => "arm",
                "i686" | "386" => "x86",
                v => v,
            };
            validate_native_claim(
                target,
                &evidence.host_os,
                &evidence.host_arch,
                &evidence.host_cpu,
            )?;
            elf::validate_native_fpu(
                target,
                evidence.binary_observation.as_ref(),
                &evidence.host_cpu,
            )?;
            // The recorded feature text comes from the same CPU evidence; it
            // describes the observed runner rather than the compiler floor.
            let expected_features = evidence
                .host_cpu
                .lines()
                .filter_map(|l| l.split_once(':'))
                .filter(|(k, _)| matches!(k.trim(), "flags" | "Features"))
                .map(|(_, v)| v.trim())
                .collect::<BTreeSet<_>>();
            let actual_fpu = if expected_features.is_empty() {
                format!("architectural-{}", evidence.host_arch)
            } else {
                expected_features
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(" | ")
            };
            ensure!(
                evidence.fpu == actual_fpu,
                "native observed FPU identity differs"
            );
            ensure!(
                evidence.runner_sha256.is_none()
                    && evidence.runner_version.is_none()
                    && evidence.rootfs_sha256.is_none()
                    && evidence.host_os == target.os
                    && evidence.host_arch == arch
                    && !evidence.host_cpu.trim().is_empty()
                    && evidence.cpu == target.cpu,
                "native runtime identity differs"
            );
        }
    }
    Ok(())
}
fn native_program_candidates(
    program: &Path,
    contains_directory: bool,
    windows: bool,
) -> Vec<PathBuf> {
    if !windows {
        return vec![program.to_path_buf()];
    }
    let text = program.as_os_str().as_encoded_bytes();
    let has_exe = text.len() >= 4 && text[text.len() - 4..].eq_ignore_ascii_case(b".exe");
    if contains_directory {
        if has_exe {
            return vec![program.to_path_buf()];
        }
        let mut executable = program.as_os_str().to_os_string();
        executable.push(".exe");
        vec![PathBuf::from(executable), program.to_path_buf()]
    } else if text.contains(&b'.') {
        vec![program.to_path_buf()]
    } else {
        let mut executable = program.as_os_str().to_os_string();
        executable.push(".exe");
        vec![PathBuf::from(executable)]
    }
}
fn resolve_native_program(program: &Path, cwd: &Path, path: &std::ffi::OsStr) -> Result<PathBuf> {
    let text = program.as_os_str().to_string_lossy();
    let contains_directory = program.is_absolute()
        || program.components().count() > 1
        || text.contains('/')
        || (cfg!(windows) && text.contains('\\'));
    let candidates = native_program_candidates(program, contains_directory, cfg!(windows));
    if contains_directory {
        return candidates
            .into_iter()
            .map(|candidate| cwd.join(candidate))
            .find(|candidate| candidate.is_file())
            .context("native check executable unavailable relative to command cwd")?
            .canonicalize()
            .map_err(Into::into);
    }
    std::env::split_paths(path)
        .flat_map(|directory| {
            let directory = if directory.is_absolute() {
                directory
            } else {
                cwd.join(directory)
            };
            candidates
                .iter()
                .map(move |program| directory.join(program))
        })
        .find(|candidate| candidate.is_file())
        .context("native check executable unavailable on command PATH")?
        .canonicalize()
        .map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
pub fn execute(
    target: &TargetDescriptor,
    constraint: &RuntimeConstraint,
    tools: &RuntimeTools,
    task: &str,
    contract: &CommandSpec,
    argv: &[String],
    env: &BTreeMap<String, String>,
    cwd: &Path,
    logs: &Path,
    timeout: u64,
    target_binary: bool,
) -> Result<(String, RuntimeEvidence)> {
    let supplied = PathBuf::from(argv.first().context("empty runtime command")?);
    let program = if supplied.is_absolute() {
        if target_binary {
            supplied
        } else if constraint.mode == RuntimeMode::Native {
            resolve_native_program(&supplied, cwd, std::ffi::OsStr::new(""))?
        } else {
            supplied.canonicalize()?
        }
    } else {
        ensure!(
            constraint.mode == RuntimeMode::Native,
            "emulated runtime must execute a planned binary directly"
        );
        let path = env
            .iter()
            .rev()
            .find(|(key, _)| {
                key.as_str() == "PATH" || (cfg!(windows) && key.eq_ignore_ascii_case("PATH"))
            })
            .map(|(_, value)| std::ffi::OsString::from(value))
            .unwrap_or_else(|| std::env::var_os("PATH").unwrap_or_default());
        resolve_native_program(&supplied, cwd, &path)?
    };
    let meta = fs::symlink_metadata(&program)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "runtime program must be regular"
    );
    let program_sha256 = source::file_digest(&program)?;
    let binary_observation = if target_binary {
        observe_binary(&program, target)?
    } else {
        None
    };
    let mut actual = argv.to_vec();
    actual[0] = program.to_string_lossy().into_owned();
    let mut runner_sha256 = None;
    let mut runner_version = None;
    let mut rootfs_sha256 = None;
    let mut rootfs_closure = None;
    let cpu;
    let host = host_cpu();
    let (host_os, host_kernel_arch) = host_platform()?;
    let mut emulator_path = None;
    let mut rootfs_path = None;
    match constraint.mode {
        RuntimeMode::Native => {
            native_host(target)?;
            if target_binary {
                elf::validate_native_fpu(target, binary_observation.as_ref(), &host)?;
            }
            cpu = target.cpu.clone();
        }
        RuntimeMode::Emulated => {
            let emulator = constraint.emulator.context("missing runtime emulator")?;
            let (canonical, model) = crate::catalog::canonical_emulation(target)?;
            ensure!(
                emulator == canonical && constraint.cpu.as_deref() == Some(model),
                "emulator CPU differs from catalog"
            );
            let path = resolve_emulator(tools, emulator)?;
            let digest = source::file_digest(&path)?;
            ensure!(
                constraint.emulator_sha256.as_deref() == Some(&digest),
                "emulator SHA-256 differs from immutable runtime constraint"
            );
            let version = process::capture(
                cwd,
                &[path.to_string_lossy().into_owned(), "--version".into()],
                30,
            )?;
            ensure!(
                version.contains("qemu") || version.contains("QEMU"),
                "emulator version identity is not QEMU"
            );
            ensure!(
                source::file_digest(&path)? == digest,
                "emulator changed during version probe"
            );
            actual = vec![
                path.to_string_lossy().into_owned(),
                "-cpu".into(),
                model.into(),
            ];
            if let Some(expected) = &constraint.rootfs_sha256 {
                let root = tools
                    .rootfs
                    .get(&target.id)
                    .context("runtime rootfs path missing; pass --rootfs TARGET=PATH")?
                    .canonicalize()?;
                let observed = rootfs_id(&root)?;
                ensure!(
                    &observed == expected,
                    "runtime rootfs differs from immutable constraint"
                );
                let program = binary_observation
                    .as_ref()
                    .context("GNU controlled runtime requires a planned ELF binary")?;
                let closure = rootfs::prepare(&root, target, program)?;
                let search_path = rootfs::library_path(&root, &closure)?;
                actual.extend([
                    "-L".into(),
                    root.to_string_lossy().into_owned(),
                    "-E".into(),
                    format!("LD_LIBRARY_PATH={search_path}"),
                ]);
                rootfs_closure = Some(closure);
                rootfs_sha256 = Some(observed);
                rootfs_path = Some(root);
            }
            actual.extend(argv.to_vec());
            cpu = model.into();
            runner_sha256 = Some(digest);
            runner_version = Some(version);
            emulator_path = Some(path);
        }
    }
    ensure!(
        !env.keys()
            .any(|k| k.starts_with("QEMU_") || k.starts_with("LD_")),
        "runtime command cannot override QEMU environment"
    );
    if let Some(path) = &emulator_path {
        ensure!(
            Some(source::file_digest(path)?) == runner_sha256,
            "emulator changed before execution"
        );
    }
    let result = process::Commands::new(cwd, logs, timeout)?.run_without_core(&actual, task, env);
    // Recheck even after timeout/nonzero; a failed invocation never produces a success record.
    ensure!(
        source::file_digest(&program)? == program_sha256,
        "runtime program changed during execution"
    );
    if let Some(path) = emulator_path {
        ensure!(
            Some(source::file_digest(&path)?) == runner_sha256,
            "emulator changed during execution"
        );
    }
    if let Some(path) = rootfs_path {
        ensure!(
            Some(rootfs_id(&path)?) == rootfs_sha256,
            "rootfs changed during execution"
        );
    }
    let stdout = result?;
    let evidence = RuntimeEvidence {
        schema: 5,
        task: task.into(),
        target: target.id.clone(),
        descriptor_id: descriptor_id(target)?,
        constraint_id: constraint_id(constraint)?,
        mode: constraint.mode,
        program_sha256,
        binary_observation,
        command: contract.clone(),
        runner_sha256,
        runner_version,
        cpu: cpu.clone(),
        fpu: if constraint.mode == RuntimeMode::Native {
            native_fpu(&host)
        } else {
            emulator_fpu(&cpu)?.into()
        },
        rootfs_sha256,
        rootfs_closure,
        actual_argv: actual,
        host_os,
        host_arch: std::env::consts::ARCH.into(),
        host_kernel_arch,
        host_cpu: host,
        timeout_seconds: timeout,
        outcome: "succeeded".into(),
        log_reference: format!("runtime/{task}.json"),
        stdout_sha256: source::file_digest(&logs.join(format!("{task}.stdout")))?,
        stderr_sha256: source::file_digest(&logs.join(format!("{task}.stderr")))?,
    };
    validate_evidence(
        target,
        constraint,
        &evidence,
        task,
        contract,
        &evidence.program_sha256,
        timeout,
    )?;
    Ok((stdout, evidence))
}
/// Validate supplied runtime dependencies before resuming a completed checkpoint.
pub fn validate_tools(
    target: &TargetDescriptor,
    constraint: &RuntimeConstraint,
    tools: &RuntimeTools,
) -> Result<()> {
    if constraint.mode == RuntimeMode::Native {
        native_host(target)?;
        return Ok(());
    }
    let emulator = constraint.emulator.context("missing emulator")?;
    let path = resolve_emulator(tools, emulator)?;
    ensure!(
        constraint.emulator_sha256.as_deref() == Some(source::file_digest(&path)?.as_str()),
        "runtime emulator differs from planned SHA-256"
    );
    if let Some(digest) = &constraint.rootfs_sha256 {
        ensure!(
            tools
                .rootfs
                .get(&target.id)
                .map(|p| rootfs_id(p))
                .transpose()?
                .as_ref()
                == Some(digest),
            "runtime rootfs differs from planned identity"
        );
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeFingerprint {
    pub emulator_sha256: String,
    pub emulator_version: String,
    pub rootfs_sha256: Option<String>,
}
pub fn inspect(emulator: &Path, rootfs: Option<&Path>) -> Result<RuntimeFingerprint> {
    let path = emulator.canonicalize()?;
    let digest = source::file_digest(&path)?;
    let version = process::capture(
        &std::env::current_dir()?,
        &[path.to_string_lossy().into_owned(), "--version".into()],
        30,
    )?;
    ensure!(
        version.contains("qemu") || version.contains("QEMU"),
        "emulator version identity is not QEMU"
    );
    ensure!(
        source::file_digest(&path)? == digest,
        "emulator changed during inspection"
    );
    Ok(RuntimeFingerprint {
        emulator_sha256: digest,
        emulator_version: version,
        rootfs_sha256: rootfs.map(rootfs_id).transpose()?,
    })
}

fn resolve_emulator(tools: &RuntimeTools, emulator: Emulator) -> Result<PathBuf> {
    if let Some(path) = tools.emulators.get(emulator_name(emulator)) {
        return Ok(path.canonicalize()?);
    }
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|p| p.join(emulator_name(emulator)))
        .find(|p| p.is_file())
        .context("controlled emulator unavailable; pass --emulator NAME=PATH")?
        .canonicalize()
        .map_err(Into::into)
}
/// Inspect the declared ELF loader dependency closure without running code.
pub fn inspect_rootfs_closure(
    root: &Path,
    target: &TargetDescriptor,
    program: &Path,
) -> Result<RootfsClosure> {
    rootfs_id(root)?;
    let observation = observe_binary(program, target)?
        .context("rootfs closure inspection requires a Linux ELF program")?;
    rootfs::prepare(root, target, &observation)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn windows_native_program_candidates_match_exe_rules_without_pathext() {
        let cases = [
            ("powershell", false, vec!["powershell.exe"]),
            ("git", false, vec!["git.exe"]),
            ("git.exe", false, vec!["git.exe"]),
            ("git.EXE", false, vec!["git.EXE"]),
            ("check.cmd", false, vec!["check.cmd"]),
            (
                r".\scripts\check",
                true,
                vec![r".\scripts\check.exe", r".\scripts\check"],
            ),
            (r"scripts\check.exe", true, vec![r"scripts\check.exe"]),
            (r"scripts\check.EXE", true, vec![r"scripts\check.EXE"]),
            (
                r"scripts\check.cmd",
                true,
                vec![r"scripts\check.cmd.exe", r"scripts\check.cmd"],
            ),
            (
                r"C:\tools\check",
                true,
                vec![r"C:\tools\check.exe", r"C:\tools\check"],
            ),
        ];
        for (program, directory, expected) in cases {
            assert_eq!(
                native_program_candidates(Path::new(program), directory, true),
                expected.into_iter().map(PathBuf::from).collect::<Vec<_>>()
            );
            assert_eq!(
                native_program_candidates(Path::new(program), directory, false),
                vec![PathBuf::from(program)]
            );
        }
    }

    #[test]
    fn native_check_executable_paths_use_command_cwd_and_effective_path() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let cwd = base.join("consumer");
        fs::create_dir_all(cwd.join("scripts")).unwrap();
        fs::create_dir_all(cwd.join("bin")).unwrap();
        fs::create_dir(base.join("absolute-bin")).unwrap();
        let script = cwd.join("scripts/check.sh");
        let relative = cwd.join("bin/relative-check");
        let absolute = base.join("absolute-bin/absolute-check");
        for (path, message) in [
            (&script, "cwd script"),
            (&relative, "relative PATH"),
            (&absolute, "absolute PATH"),
        ] {
            fs::write(path, format!("#!/bin/sh\nprintf '%s\\n' '{message}'\n")).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let id = format!(
            "{}-{}{}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            if cfg!(target_os = "linux") { "-go" } else { "" }
        );
        let target = crate::catalog::resolve(&id).unwrap();
        for (label, argv0, path, expected, message) in [
            (
                "dot-relative",
                "./scripts/check.sh",
                "does-not-exist".into(),
                script.clone(),
                "cwd script",
            ),
            (
                "relative",
                "scripts/check.sh",
                "does-not-exist".into(),
                script.clone(),
                "cwd script",
            ),
            (
                "relative-path",
                "relative-check",
                "bin".into(),
                relative.clone(),
                "relative PATH",
            ),
            (
                "absolute-path",
                "absolute-check",
                base.join("absolute-bin").to_string_lossy().into_owned(),
                absolute,
                "absolute PATH",
            ),
        ] {
            let env = BTreeMap::from([("PATH".into(), path)]);
            let command = CommandSpec {
                argv: vec![argv0.into()],
                cwd: ".".into(),
                env: env.clone(),
            };
            let (stdout, evidence) = execute(
                &target,
                &RuntimeConstraint::default(),
                &RuntimeTools::default(),
                label,
                &command,
                &command.argv,
                &env,
                &cwd,
                &base.join("logs"),
                5,
                false,
            )
            .unwrap();
            assert_eq!(stdout.trim(), message);
            assert_eq!(evidence.actual_argv[0], expected.to_str().unwrap());
            assert_eq!(
                evidence.program_sha256,
                source::file_digest(&expected).unwrap()
            );
        }
        let constraint = RuntimeConstraint {
            mode: RuntimeMode::Emulated,
            ..Default::default()
        };
        let command = CommandSpec {
            argv: vec!["./scripts/check.sh".into()],
            cwd: ".".into(),
            env: BTreeMap::new(),
        };
        assert!(
            execute(
                &target,
                &constraint,
                &RuntimeTools::default(),
                "relative-emulated",
                &command,
                &command.argv,
                &BTreeMap::new(),
                &cwd,
                &base.join("emulated-logs"),
                5,
                false
            )
            .unwrap_err()
            .to_string()
            .contains("planned binary directly")
        );
    }
}
