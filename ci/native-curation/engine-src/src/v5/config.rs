use super::model::*;
use crate::{
    catalog, config as legacy,
    delivery::model::Format,
    model::{Hook, SourceIdentity},
    v2::model::Builder,
};
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeSet, fs, path::Path};

pub fn load(root: &Path) -> Result<Config> {
    let value = toml::from_str(&fs::read_to_string(legacy::safe_join(
        root,
        "release.toml",
    )?)?)
    .context("invalid schema-4 release.toml")?;
    validate(&value)?;
    Ok(value)
}

pub fn effective_formats(c: &Config, product: usize, os: &str) -> Vec<Format> {
    c.products[product]
        .packaging
        .formats
        .get(os)
        .or_else(|| c.packaging.formats.get(os))
        .cloned()
        .unwrap_or_else(|| {
            vec![if os == "windows" {
                Format::Zip
            } else {
                Format::TarGz
            }]
        })
}
pub fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn validate_runtime(
    target: &catalog::TargetDescriptor,
    runtime: &RuntimeConstraint,
) -> Result<()> {
    match runtime.mode {
        RuntimeMode::Native => ensure!(
            runtime.emulator.is_none()
                && runtime.cpu.is_none()
                && runtime.emulator_sha256.is_none()
                && runtime.rootfs_sha256.is_none(),
            "native runtime must not declare unused emulation fields"
        ),
        RuntimeMode::Emulated => {
            let (emulator, cpu) = catalog::canonical_emulation(target)?;
            ensure!(
                runtime.emulator == Some(emulator) && runtime.cpu.as_deref() == Some(cpu),
                "emulated target {} requires {:?} with CPU {cpu}",
                target.id,
                emulator
            );
            ensure!(
                runtime.emulator_sha256.as_deref().is_some_and(is_digest),
                "emulated runtime requires the exact emulator SHA-256"
            );
            if target.libc == "glibc" {
                ensure!(
                    runtime.rootfs_sha256.as_deref().is_some_and(is_digest),
                    "GNU emulation requires the matching loader and libraries rootfs SHA-256"
                );
            } else {
                ensure!(
                    runtime.rootfs_sha256.is_none(),
                    "pure Go emulation must not declare an unused rootfs"
                );
            }
        }
    }
    Ok(())
}
fn unique(values: &[String], name: &str) -> Result<()> {
    ensure!(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        "duplicate {name}"
    );
    Ok(())
}
fn argv(values: &[String]) -> Result<()> {
    ensure!(
        !values.is_empty() && values.iter().all(|v| !v.is_empty() && !v.contains('\0')),
        "expected nonempty argv without NUL bytes"
    );
    Ok(())
}
fn hook(h: &Hook) -> Result<()> {
    argv(&h.command)?;
    for (key, value) in &h.env {
        ensure!(
            !key.is_empty()
                && !key.starts_with("KIT_")
                && !legacy::secret_name(key)
                && key.bytes().enumerate().all(|(i, c)| c == b'_'
                    || c.is_ascii_alphabetic()
                    || (i > 0 && c.is_ascii_digit()))
                && !value.contains('\0'),
            "reserved, credential or invalid hook environment: {key}"
        );
    }
    Ok(())
}
pub fn validate(c: &Config) -> Result<()> {
    ensure!(c.schema == CONFIG_SCHEMA, "unsupported release.toml schema");
    ensure!(
        (1..=3600).contains(&c.timeout_seconds),
        "timeout-seconds must be 1..3600"
    );
    ensure!(
        !c.products.is_empty() && !c.targets.is_empty(),
        "declare products and targets"
    );
    let keys: Vec<_> = c.targets.iter().map(|t| t.id.clone()).collect();
    unique(&keys, "target")?;
    for selection in &c.targets {
        let target = crate::catalog::resolve(&selection.id)?;
        validate_runtime(&target, &selection.runtime)?;
    }
    unique(
        &c.products.iter().map(|p| p.id.clone()).collect::<Vec<_>>(),
        "product",
    )?;
    for p in &c.products {
        legacy::identifier(&p.id)?;
        if p.directory != "." {
            legacy::relative(&p.directory)?;
        }
        ensure!(!p.binaries.is_empty(), "product needs binaries");
        unique(&p.binaries, "binary")?;
        for b in &p.binaries {
            legacy::identifier(b)?;
        }
        unique(&p.targets, "product target")?;
        ensure!(
            p.targets.iter().all(|t| keys.contains(t)),
            "unknown product target"
        );
        argv(&p.version_args)?;
        if let Some(selected) = &p.version_binaries {
            ensure!(
                !selected.is_empty()
                    && selected.contains(&p.binaries[0])
                    && selected.iter().all(|b| p.binaries.contains(b)),
                "version-binaries must include primary and select shipped binaries"
            );
            unique(selected, "version binary")?;
            ensure!(
                selected.len() == p.binaries.len() || !p.checks.is_empty(),
                "omitting helper version checks requires product checks"
            );
        }
        match &p.build {
            Builder::Rust {
                package,
                manifest,
                features,
                ..
            } => {
                legacy::identifier(package)?;
                legacy::relative(manifest)?;
                ensure!(
                    Path::new(manifest)
                        .file_name()
                        .is_some_and(|n| n == "Cargo.toml"),
                    "Rust manifest must name Cargo.toml"
                );
                unique(features, "feature")?;
                for f in features {
                    legacy::identifier(f)?;
                }
            }
            Builder::Go {
                version,
                packages,
                ldflags,
            } => {
                ensure!(
                    !version.is_empty()
                        && version
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b)),
                    "Go application version must be explicit and safe"
                );
                ensure!(
                    packages.len() == p.binaries.len(),
                    "Go packages must correspond to binaries in order"
                );
                for path in packages {
                    if path != "." {
                        legacy::relative(path.strip_prefix("./").unwrap_or(path))?;
                    }
                }
                ensure!(
                    ldflags.iter().all(|s| !s.contains('\0')),
                    "invalid Go ldflags"
                );
            }
        }
        for h in p.prepare.iter().chain(&p.checks) {
            hook(h)?;
        }
        for selection in c
            .targets
            .iter()
            .filter(|t| p.targets.is_empty() || p.targets.contains(&t.id))
        {
            let t =
                crate::catalog::for_builder(&crate::catalog::resolve(&selection.id)?, &p.build)?;
            if selection.runtime.mode == RuntimeMode::Emulated {
                for hook in &p.checks {
                    ensure!(
                        hook.command.first().is_some_and(
                            |arg| arg == "{binary}" || arg.starts_with("{attempt}/work/run-")
                        ),
                        "emulated checks must invoke a planned binary directly; shell or script checks require native execution"
                    );
                }
            }
            let mut names: Vec<String> = p
                .binaries
                .iter()
                .map(|b| t.binary_name(b).to_ascii_lowercase())
                .collect();
            for a in &p.assets {
                legacy::relative(&a.path)?;
                legacy::relative(a.source.strip_prefix("{generated}/").unwrap_or(&a.source))?;
                names.push(a.path.to_ascii_lowercase());
            }
            unique(&names, "archive destination")?;
            for n in &names {
                ensure!(
                    !names.iter().any(|o| n.starts_with(&format!("{o}/"))),
                    "archive file/directory conflict"
                );
            }
        }
    }
    formats(&c.packaging.formats)?;
    for (pi, p) in c.products.iter().enumerate() {
        formats(&p.packaging.formats)?;
        let native_needed = c
            .targets
            .iter()
            .filter(|t| p.targets.is_empty() || p.targets.contains(&t.id))
            .any(|t| {
                effective_formats(
                    c,
                    pi,
                    &catalog::resolve(&t.id).expect("validated target").os,
                )
                .iter()
                .any(|f| f.is_native())
            });
        ensure!(
            !native_needed || p.packaging.native.is_some(),
            "native packaging for {} requires explicit description, license and maintainer",
            p.id
        );
        if let Some(native) = &p.packaging.native {
            package_name(native.name.as_deref().unwrap_or(&p.id))?;
            text(&native.description, "description")?;
            text(&native.license, "license")?;
            text(&native.maintainer, "maintainer")?;
            if let Some(homepage) = &native.homepage {
                text(homepage, "homepage")?;
            }
            for (format, dependencies) in &native.dependencies {
                ensure!(
                    format.is_native(),
                    "dependencies are only supported for native formats"
                );
                ensure!(
                    dependencies.iter().collect::<BTreeSet<_>>().len() == dependencies.len(),
                    "duplicate native dependency"
                );
                for dependency in dependencies {
                    text(dependency, "dependency")?;
                }
            }
            let payload = p
                .binaries
                .iter()
                .cloned()
                .chain(p.assets.iter().map(|a| a.path.clone()))
                .collect::<BTreeSet<_>>();
            let mut sources = BTreeSet::new();
            let mut destinations = BTreeSet::new();
            for mapping in &native.install {
                legacy::relative(&mapping.source)?;
                install_destination(&mapping.destination)?;
                ensure!(
                    payload.contains(&mapping.source),
                    "install source is not a declared payload file: {}",
                    mapping.source
                );
                ensure!(
                    sources.insert(&mapping.source),
                    "duplicate install source: {}",
                    mapping.source
                );
                ensure!(
                    destinations.insert(&mapping.destination),
                    "duplicate install destination: {}",
                    mapping.destination
                );
            }
            for path in &destinations {
                ensure!(
                    !destinations
                        .iter()
                        .any(|other| path.starts_with(&format!("{other}/"))),
                    "install file/directory conflict"
                );
            }
        }
    }
    for (pi, p) in c.products.iter().enumerate() {
        for selection in c
            .targets
            .iter()
            .filter(|t| p.targets.is_empty() || p.targets.contains(&t.id))
        {
            let target = catalog::for_builder(&catalog::resolve(&selection.id)?, &p.build)?;
            for format in effective_formats(c, pi, &target.os) {
                catalog::package_support(&target, format)?;
            }
        }
    }
    Ok(())
}

fn formats(values: &std::collections::BTreeMap<String, Vec<Format>>) -> Result<()> {
    for (os, formats) in values {
        ensure!(
            matches!(os.as_str(), "macos" | "linux" | "windows"),
            "unknown packaging OS: {os}"
        );
        ensure!(
            !formats.is_empty(),
            "packaging format list cannot be empty: {os}"
        );
        ensure!(
            formats.iter().collect::<BTreeSet<_>>().len() == formats.len(),
            "duplicate packaging format for {os}"
        );
        ensure!(
            os == "linux" || formats.iter().all(|f| !f.is_native()),
            "native packaging formats require Linux: {os}"
        );
    }
    Ok(())
}

pub fn package_name(name: &str) -> Result<()> {
    ensure!(
        (2..=120).contains(&name.len())
            && (name.as_bytes()[0].is_ascii_lowercase() || name.as_bytes()[0].is_ascii_digit())
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+.-".contains(&b)),
        "native package name must use Debian-compatible lowercase syntax: {name}"
    );
    Ok(())
}

pub fn install_destination(path: &str) -> Result<()> {
    ensure!(
        path.starts_with('/') && !path.starts_with("//"),
        "install destination must be an absolute POSIX file path: {path}"
    );
    legacy::relative(path.strip_prefix('/').unwrap())?;
    ensure!(
        path.bytes()
            .all(|b| b != b'\\' && b != 0 && !b.is_ascii_control()),
        "invalid install destination: {path}"
    );
    Ok(())
}

fn text(value: &str, name: &str) -> Result<()> {
    ensure!(
        !value.trim().is_empty() && !value.chars().any(char::is_control),
        "native {name} must be nonempty single-line text"
    );
    Ok(())
}

pub fn validate_source(root: &Path, c: &Config, source: &SourceIdentity) -> Result<()> {
    validate(c)?;
    crate::v2::contract::required(root, "release.toml", source)?;
    for p in &c.products {
        let dir = crate::v2::contract::product_root(root, &p.base())?;
        ensure!(dir.is_dir(), "product directory is absent: {}", p.directory);
        for a in &p.assets {
            if !a.source.starts_with("{generated}/") {
                crate::v2::contract::required(root, &a.source, source)?;
            }
        }
        for h in p.prepare.iter().chain(&p.checks) {
            for arg in &h.command {
                if arg.starts_with('-') || arg.contains('{') || arg.chars().any(char::is_whitespace)
                {
                    continue;
                }
                if root.join(arg).exists()
                    || arg.contains('/')
                    || [".py", ".sh", ".ps1"].iter().any(|s| arg.ends_with(s))
                {
                    crate::v2::contract::required(root, arg, source)
                        .with_context(|| format!("hook input must be tracked: {arg}"))?;
                }
            }
        }
    }
    Ok(())
}

pub fn validate_build_environment(config: &Config) -> Result<()> {
    if config
        .products
        .iter()
        .any(|p| matches!(p.build, Builder::Rust { .. }))
    {
        for (key, value) in std::env::vars_os() {
            let key = key.to_string_lossy();
            ensure!(
                !(key.starts_with("CARGO_TARGET_")
                    && key.ends_with("_RUSTFLAGS")
                    && !value.is_empty()),
                "ambient {key} must be removed; CPU and float requirements come from the target catalog"
            );
        }
    }
    Ok(())
}
