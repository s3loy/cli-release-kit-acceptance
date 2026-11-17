use super::model::{Builder, Config, Product, SCHEMA};
use crate::{
    config,
    model::{Hook, SourceIdentity},
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

pub fn product_root(root: &Path, p: &Product) -> Result<PathBuf> {
    if p.directory == "." {
        Ok(root.to_path_buf())
    } else {
        config::safe_join(root, &p.directory)
    }
}
pub fn load(root: &Path) -> Result<Config> {
    let value: Config = toml::from_str(&fs::read_to_string(config::safe_join(
        root,
        "release.toml",
    )?)?)?;
    validate(&value)?;
    Ok(value)
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
                && !config::secret_name(key)
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
    ensure!(c.schema == SCHEMA, "unsupported release.toml schema");
    ensure!(
        (1..=3600).contains(&c.timeout_seconds),
        "timeout-seconds must be 1..3600"
    );
    ensure!(
        !c.products.is_empty() && !c.targets.is_empty(),
        "declare products and targets"
    );
    let keys: Vec<_> = c.targets.iter().map(|t| t.key()).collect();
    unique(&keys, "target")?;
    for t in &c.targets {
        ensure!(
            matches!(t.os.as_str(), "macos" | "linux" | "windows")
                && matches!(t.arch.as_str(), "aarch64" | "x86_64"),
            "unsupported target: {}",
            t.key()
        );
        ensure!(
            match t.os.as_str() {
                "macos" => t.abi.is_none(),
                "windows" => t.abi.as_deref().is_none_or(|s| s == "msvc"),
                "linux" => t.abi.as_deref().is_none_or(|s| matches!(s, "gnu" | "musl")),
                _ => false,
            },
            "unsupported target ABI"
        );
    }
    unique(
        &c.products.iter().map(|p| p.id.clone()).collect::<Vec<_>>(),
        "product",
    )?;
    for p in &c.products {
        config::identifier(&p.id)?;
        if p.directory != "." {
            config::relative(&p.directory)?;
        }
        ensure!(!p.binaries.is_empty(), "product needs binaries");
        unique(&p.binaries, "binary")?;
        for b in &p.binaries {
            config::identifier(b)?;
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
                config::identifier(package)?;
                config::relative(manifest)?;
                ensure!(
                    Path::new(manifest)
                        .file_name()
                        .is_some_and(|n| n == "Cargo.toml"),
                    "Rust manifest must name Cargo.toml"
                );
                unique(features, "feature")?;
                for f in features {
                    config::identifier(f)?;
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
                        config::relative(path.strip_prefix("./").unwrap_or(path))?;
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
        for t in c
            .targets
            .iter()
            .filter(|t| p.targets.is_empty() || p.targets.contains(&t.key()))
        {
            let compatible = match p.build {
                Builder::Go { .. } => t.abi.is_none(),
                Builder::Rust { .. } => match t.os.as_str() {
                    "macos" => t.abi.is_none(),
                    "linux" => matches!(t.abi.as_deref(), Some("gnu" | "musl")),
                    "windows" => t.abi.as_deref() == Some("msvc"),
                    _ => false,
                },
            };
            ensure!(
                compatible,
                "{} builder cannot represent target {}; select appropriate product targets",
                p.build.name(),
                t.key()
            );
            let mut names: Vec<String> = p
                .binaries
                .iter()
                .map(|b| t.binary_name(b).to_ascii_lowercase())
                .collect();
            for a in &p.assets {
                config::relative(&a.path)?;
                config::relative(a.source.strip_prefix("{generated}/").unwrap_or(&a.source))?;
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
    Ok(())
}

pub fn validate_source(root: &Path, c: &Config, source: &SourceIdentity) -> Result<()> {
    validate(c)?;
    required(root, "release.toml", source)?;
    for p in &c.products {
        let dir = product_root(root, p)?;
        ensure!(dir.is_dir(), "product directory is absent: {}", p.directory);
        for a in &p.assets {
            if !a.source.starts_with("{generated}/") {
                required(root, &a.source, source)?;
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
                    required(root, arg, source)
                        .with_context(|| format!("hook input must be tracked: {arg}"))?;
                }
            }
        }
    }
    Ok(())
}
pub fn required(root: &Path, name: &str, source: &SourceIdentity) -> Result<PathBuf> {
    ensure!(
        source.files.contains_key(name),
        "required tracked input: {name}"
    );
    let path = config::safe_join(root, name)?;
    ensure!(
        fs::symlink_metadata(&path)?.is_file(),
        "required input is not a regular file: {name}"
    );
    Ok(path)
}
