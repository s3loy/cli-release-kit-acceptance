use crate::delivery::model::Format;
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct TargetDescriptor {
    pub id: String,
    pub os: String,
    pub arch: String,
    pub cpu: String,
    pub fpu: String,
    pub libc: String,
    pub c_abi: String,
    pub builder: String,
    pub compiler_target: String,
    pub compile_env: BTreeMap<String, String>,
    pub minimum_kernel: Option<String>,
    pub minimum_libc: Option<String>,
}
impl TargetDescriptor {
    pub fn key(&self) -> String {
        self.id.clone()
    }
    pub fn binary_name(&self, name: &str) -> String {
        format!("{name}{}", if self.os == "windows" { ".exe" } else { "" })
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum InspectionProfile {
    Archive,
    Deb,
    RpmX86_64,
    RpmAarch64,
    RpmI686,
    RpmArmSoft,
    RpmArmHard,
    Apk,
    Pacman,
    Ipk,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct PackageProfile {
    pub target: String,
    pub format: Format,
    pub nfpm_input_arch: Option<String>,
    pub package_arch: String,
    pub inspection_profile: InspectionProfile,
    pub compatibility: String,
}

pub fn resolve(id: &str) -> Result<TargetDescriptor> {
    resolve_inner(id)
        .ok_or_else(|| anyhow::anyhow!("unknown target ID: {id}; use a canonical catalog ID"))
}
#[allow(clippy::too_many_arguments)]
fn descriptor(
    id: &str,
    os: &str,
    arch: &str,
    builder: &str,
    compiler_target: &str,
    libc: &str,
    c_abi: &str,
    cpu: &str,
    fpu: &str,
    kernel: Option<&str>,
    minimum_libc: Option<&str>,
) -> TargetDescriptor {
    let mut compile_env = BTreeMap::new();
    if builder == "rust" {
        compile_env.insert("RUSTFLAGS".into(), String::new());
        compile_env.insert("CARGO_ENCODED_RUSTFLAGS".into(), String::new());
    }
    if builder == "go" {
        let (goos, goarch) = compiler_target.split_once('/').expect("catalog Go target");
        compile_env.extend([
            ("GOOS".into(), goos.into()),
            ("GOARCH".into(), goarch.into()),
            ("CGO_ENABLED".into(), "0".into()),
            ("GOENV".into(), "off".into()),
            ("GOWORK".into(), "off".into()),
            ("GOTOOLCHAIN".into(), "local".into()),
        ]);
        match arch {
            "armv6" => {
                compile_env.insert(
                    "GOARM".into(),
                    format!(
                        "6,{}",
                        if fpu == "none" {
                            "softfloat"
                        } else {
                            "hardfloat"
                        }
                    ),
                );
            }
            "armv7" => {
                compile_env.insert(
                    "GOARM".into(),
                    format!(
                        "7,{}",
                        if fpu == "none" {
                            "softfloat"
                        } else {
                            "hardfloat"
                        }
                    ),
                );
            }
            "386" => {
                compile_env.insert("GO386".into(), "sse2".into());
            }
            "x86_64" => {
                compile_env.insert("GOAMD64".into(), "v1".into());
            }
            _ => {}
        }
    }
    TargetDescriptor {
        id: id.into(),
        os: os.into(),
        arch: arch.into(),
        builder: builder.into(),
        cpu: cpu.into(),
        fpu: fpu.into(),
        libc: libc.into(),
        c_abi: c_abi.into(),
        compiler_target: compiler_target.into(),
        compile_env,
        minimum_kernel: kernel.map(str::to_owned),
        minimum_libc: minimum_libc.map(str::to_owned),
    }
}
fn resolve_inner(id: &str) -> Option<TargetDescriptor> {
    let new = match id {
        "linux-armv6-gnueabi" => Some((
            "armv6",
            "rust",
            "arm-unknown-linux-gnueabi",
            "glibc",
            "eabi-soft",
            "armv6",
            "none",
            "3.2",
            "2.17",
        )),
        "linux-armv6-gnueabihf" => Some((
            "armv6",
            "rust",
            "arm-unknown-linux-gnueabihf",
            "glibc",
            "eabi-hard",
            "armv6",
            "vfp2",
            "3.2",
            "2.17",
        )),
        "linux-armv7-gnueabi" => Some((
            "armv7",
            "rust",
            "armv7-unknown-linux-gnueabi",
            "glibc",
            "eabi-soft",
            "armv7-a",
            "none",
            "4.15",
            "2.27",
        )),
        "linux-armv7-gnueabihf" => Some((
            "armv7",
            "rust",
            "armv7-unknown-linux-gnueabihf",
            "glibc",
            "eabi-hard",
            "armv7-a",
            "vfpv3-d16",
            "3.2",
            "2.17",
        )),
        "linux-i686-gnu" => Some((
            "i686",
            "rust",
            "i686-unknown-linux-gnu",
            "glibc",
            "sysv",
            "pentium4",
            "sse2",
            "3.2",
            "2.17",
        )),
        "linux-armv6-softfloat" => Some((
            "armv6",
            "go",
            "linux/arm",
            "none",
            "not-applicable",
            "armv6",
            "none",
            "3.2",
            "",
        )),
        "linux-armv6-hardfloat" => Some((
            "armv6",
            "go",
            "linux/arm",
            "none",
            "not-applicable",
            "armv6",
            "vfp2",
            "3.2",
            "",
        )),
        "linux-armv7-softfloat" => Some((
            "armv7",
            "go",
            "linux/arm",
            "none",
            "not-applicable",
            "armv7-a",
            "none",
            "3.2",
            "",
        )),
        "linux-armv7-hardfloat" => Some((
            "armv7",
            "go",
            "linux/arm",
            "none",
            "not-applicable",
            "armv7-a",
            "vfpv3",
            "3.2",
            "",
        )),
        "linux-386-sse2" => Some((
            "386",
            "go",
            "linux/386",
            "none",
            "not-applicable",
            "pentium4",
            "sse2",
            "3.2",
            "",
        )),
        _ => None,
    };
    if let Some((arch, builder, compiler, libc, abi, cpu, fpu, kernel, libc_min)) = new {
        return Some(descriptor(
            id,
            "linux",
            arch,
            builder,
            compiler,
            libc,
            abi,
            cpu,
            fpu,
            Some(kernel),
            (!libc_min.is_empty()).then_some(libc_min),
        ));
    }
    for os in ["linux", "macos", "windows"] {
        for arch in ["aarch64", "x86_64"] {
            if os != "macos" && id == format!("{os}-{arch}") {
                let goos = if os == "macos" { "darwin" } else { os };
                let goarch = if arch == "aarch64" { "arm64" } else { "amd64" };
                return Some(descriptor(
                    id,
                    os,
                    arch,
                    "go",
                    &format!("{goos}/{goarch}"),
                    "none",
                    "not-applicable",
                    if arch == "aarch64" {
                        "armv8-a"
                    } else {
                        "x86-64-v1"
                    },
                    if arch == "aarch64" {
                        "fp-armv8"
                    } else {
                        "sse2"
                    },
                    (os == "linux").then_some("3.2"),
                    None,
                ));
            }
            for abi in ["gnu", "musl", "msvc", "darwin"] {
                let valid = match os {
                    "linux" => matches!(abi, "gnu" | "musl"),
                    "windows" => abi == "msvc",
                    "macos" => abi == "darwin",
                    _ => false,
                };
                // macOS historically shares a target ID across both builders.
                let rust_id = if os == "macos" {
                    format!("{os}-{arch}")
                } else {
                    format!("{os}-{arch}-{abi}")
                };
                if valid && id == rust_id {
                    let suffix = match os {
                        "linux" => format!("unknown-linux-{abi}"),
                        "windows" => "pc-windows-msvc".into(),
                        _ => "apple-darwin".into(),
                    };
                    return Some(descriptor(
                        id,
                        os,
                        arch,
                        if os == "macos" { "any" } else { "rust" },
                        &format!("{arch}-{suffix}"),
                        match abi {
                            "gnu" => "glibc",
                            "musl" => "musl",
                            "msvc" => "ucrt",
                            _ => "platform",
                        },
                        if os == "windows" {
                            "msvc"
                        } else if os == "macos" {
                            "platform"
                        } else {
                            "sysv"
                        },
                        if arch == "aarch64" {
                            "armv8-a"
                        } else {
                            "x86-64-v1"
                        },
                        if arch == "aarch64" {
                            "fp-armv8"
                        } else {
                            "sse2"
                        },
                        (abi == "gnu").then_some(if arch == "aarch64" { "4.1" } else { "3.2" }),
                        match abi {
                            "gnu" => Some("2.17"),
                            "musl" => Some("1.2.5"),
                            _ => None,
                        },
                    ));
                }
            }
        }
    }
    None
}
pub fn all() -> Vec<TargetDescriptor> {
    let mut ids = Vec::new();
    for os in ["linux", "macos", "windows"] {
        for arch in ["aarch64", "x86_64"] {
            ids.push(format!("{os}-{arch}"));
            match os {
                "linux" => {
                    ids.push(format!("{os}-{arch}-gnu"));
                    ids.push(format!("{os}-{arch}-musl"));
                }
                "windows" => ids.push(format!("{os}-{arch}-msvc")),
                _ => {}
            }
        }
    }
    ids.extend(
        [
            "linux-armv6-gnueabi",
            "linux-armv6-gnueabihf",
            "linux-armv7-gnueabi",
            "linux-armv7-gnueabihf",
            "linux-i686-gnu",
            "linux-armv6-softfloat",
            "linux-armv6-hardfloat",
            "linux-armv7-softfloat",
            "linux-armv7-hardfloat",
            "linux-386-sse2",
        ]
        .map(str::to_owned),
    );
    ids.into_iter()
        .map(|id| resolve(&id).expect("catalog ID"))
        .collect()
}
pub fn package_support(target: &TargetDescriptor, format: Format) -> Result<PackageProfile> {
    let logical = resolve(&target.id)?;
    ensure!(
        *target == logical
            || (logical.builder == "any"
                && ["rust", "go"]
                    .into_iter()
                    .any(|builder| specialize(&logical, builder)
                        .is_ok_and(|expected| expected == *target))),
        "target descriptor differs from catalog"
    );
    let (input, arch, inspection) = if !format.is_native() {
        (None, target.arch.clone(), InspectionProfile::Archive)
    } else {
        ensure!(
            target.os == "linux",
            "{} packages require Linux",
            format.name()
        );
        let arm = matches!(target.arch.as_str(), "armv6" | "armv7");
        let soft = arm && target.c_abi == "eabi-soft";
        let base = match target.arch.as_str() {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "i686" | "386" => "386",
            "armv6" => "arm6",
            "armv7" => "arm7",
            _ => bail!("unsupported package architecture"),
        };
        let (input, arch, inspection) = match format {
            Format::Deb => (
                if soft { "armel" } else { base },
                match base {
                    "amd64" => "amd64",
                    "arm64" => "arm64",
                    "386" => "i386",
                    _ if soft => "armel",
                    _ => "armhf",
                },
                InspectionProfile::Deb,
            ),
            Format::Rpm => {
                let (arch, profile) = if soft {
                    (
                        if base == "arm6" { "armv6l" } else { "armv7l" },
                        InspectionProfile::RpmArmSoft,
                    )
                } else {
                    match base {
                        "amd64" => ("x86_64", InspectionProfile::RpmX86_64),
                        "arm64" => ("aarch64", InspectionProfile::RpmAarch64),
                        "386" => ("i686", InspectionProfile::RpmI686),
                        "arm6" => ("armv6hl", InspectionProfile::RpmArmHard),
                        _ => ("armv7hl", InspectionProfile::RpmArmHard),
                    }
                };
                (
                    if soft {
                        arch
                    } else if base == "386" {
                        "i686"
                    } else {
                        base
                    },
                    arch,
                    profile,
                )
            }
            Format::Apk => {
                ensure!(
                    !soft,
                    "{}: APK has no cataloged soft-float ARM architecture; select an archive or deb",
                    target.id
                );
                (
                    base,
                    match base {
                        "amd64" => "x86_64",
                        "arm64" => "aarch64",
                        "386" => "x86",
                        "arm6" => "armhf",
                        _ => "armv7",
                    },
                    InspectionProfile::Apk,
                )
            }
            Format::Pacman => {
                ensure!(
                    !soft,
                    "{}: pacman has no cataloged ARMv6/v7 soft-float architecture; select an archive or deb",
                    target.id
                );
                (
                    base,
                    match base {
                        "amd64" => "x86_64",
                        "arm64" => "aarch64",
                        "386" => "i686",
                        "arm6" => "armv6h",
                        _ => "armv7h",
                    },
                    InspectionProfile::Pacman,
                )
            }
            Format::Ipk => (
                if soft { "armel" } else { base },
                match base {
                    "amd64" => "x86_64",
                    "arm64" => "arm64",
                    "386" => "i386",
                    _ if soft => "armel",
                    _ => "armhf",
                },
                InspectionProfile::Ipk,
            ),
            _ => unreachable!(),
        };
        (Some(input.into()), arch.into(), inspection)
    };
    let mut compatibility = if target.builder == "go" && arm_target_without_fpu(target) && format.is_native() {
        if format == Format::Ipk {
            "pure Go softfloat with no C ABI; generic-opkg armhf metadata targets FPU-equipped systems; firmware and device feeds require separate acceptance"
        } else {
            "pure Go softfloat with no C ABI; package metadata targets the named FPU-equipped distribution architecture"
        }
    } else if format == Format::Ipk {
        "nfpm-generic-opkg; firmware and device-specific architecture feeds require separate acceptance"
    } else {
        "catalog package metadata profile; installation compatibility requires target-environment acceptance"
    }.to_owned();
    if format == Format::Deb && arch == "armhf" {
        compatibility.push_str("; Debian armhf deployment requires ARMv7, Thumb-2 and VFPv3-D16");
        if target.arch == "armv6" {
            compatibility
                .push_str("; ARMv6 compiler output does not establish ARMv6 Debian qualification");
        }
    }
    Ok(PackageProfile {
        target: target.id.clone(),
        format,
        nfpm_input_arch: input,
        package_arch: arch,
        inspection_profile: inspection,
        compatibility,
    })
}
pub fn canonical_emulation(
    target: &TargetDescriptor,
) -> Result<(crate::v5::model::Emulator, &'static str)> {
    use crate::v5::model::Emulator;
    ensure!(target.os == "linux", "controlled emulation requires Linux");
    match target.arch.as_str() {
        "armv6" => Ok((
            Emulator::QemuArm,
            if target.fpu == "none" {
                "arm1176,vfp=off"
            } else {
                "arm1176"
            },
        )),
        "armv7" => Ok((
            Emulator::QemuArm,
            if target.fpu == "none" {
                "cortex-a7,vfp=off"
            } else {
                "cortex-a7"
            },
        )),
        "i686" | "386" => Ok((Emulator::QemuI386, "qemu32")),
        _ => bail!("controlled emulation is unavailable for {}", target.id),
    }
}

fn arm_target_without_fpu(target: &TargetDescriptor) -> bool {
    matches!(target.arch.as_str(), "armv6" | "armv7") && target.fpu == "none"
}
fn specialize(target: &TargetDescriptor, builder: &str) -> Result<TargetDescriptor> {
    ensure!(
        target.builder == builder || target.builder == "any",
        "{} builder cannot represent target {}; select appropriate product targets",
        builder,
        target.id
    );
    let mut result = target.clone();
    if target.builder == "any" {
        result.builder = builder.into();
        if builder == "go" {
            let arch = if target.arch == "aarch64" {
                "arm64"
            } else {
                "amd64"
            };
            result = descriptor(
                &target.id,
                &target.os,
                &target.arch,
                "go",
                &format!("darwin/{arch}"),
                "none",
                "not-applicable",
                &target.cpu,
                &target.fpu,
                None,
                None,
            );
        } else {
            result.libc = "libsystem".into();
            result.c_abi = "sysv".into();
            result.compile_env.insert("RUSTFLAGS".into(), String::new());
            result
                .compile_env
                .insert("CARGO_ENCODED_RUSTFLAGS".into(), String::new());
        }
    }
    Ok(result)
}
pub fn for_builder(
    target: &TargetDescriptor,
    builder: &crate::v2::model::Builder,
) -> Result<TargetDescriptor> {
    ensure!(
        *target == resolve(&target.id)?,
        "expected a logical catalog descriptor"
    );
    specialize(target, builder.name())
}
