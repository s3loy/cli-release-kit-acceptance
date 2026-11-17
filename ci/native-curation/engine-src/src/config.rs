use crate::model::{Config, Hook, SCHEMA};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

pub const TARGETS: &[&str] = &[
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
];

pub fn relative(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && !value.contains(['\\', ':'])
            && !value.chars().any(char::is_control)
            && value
                .split('/')
                .all(|p| !p.is_empty() && p != "." && p != ".."),
        "unsafe relative path: {value:?}"
    );
    for part in value.split('/') {
        let stem = part
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        ensure!(
            !part.ends_with(['.', ' '])
                && !part.contains(['<', '>', '"', '|', '?', '*'])
                && !matches!(
                    stem.as_str(),
                    "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                )
                && !(stem.len() == 4
                    && (stem.starts_with("COM") || stem.starts_with("LPT"))
                    && matches!(stem.as_bytes()[3], b'1'..=b'9')),
            "nonportable archive/input component: {part:?}"
        );
    }
    Ok(())
}

pub fn safe_join(root: &Path, value: &str) -> Result<PathBuf> {
    relative(value)?;
    let mut path = root.to_path_buf();
    for component in value.split('/') {
        path.push(component);
        match fs::symlink_metadata(&path) {
            Ok(meta) => ensure!(
                !meta.file_type().is_symlink(),
                "symlink input: {}",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(path)
}

pub fn identifier(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 120
            && !value.starts_with(['-', '.'])
            && value
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c)),
        "invalid identifier: {value:?}"
    );
    Ok(())
}

pub fn secret_name(name: &str) -> bool {
    name.to_ascii_uppercase().split('_').any(|part| {
        matches!(
            part,
            "TOKEN" | "SECRET" | "PASSWORD" | "CREDENTIAL" | "CREDENTIALS"
        )
    }) || name.to_ascii_uppercase().contains("PRIVATE_KEY")
}

fn hook(hook: &Hook) -> Result<()> {
    ensure!(
        !hook.command.is_empty()
            && hook
                .command
                .iter()
                .all(|s| !s.is_empty() && !s.contains('\0')),
        "hooks need a nonempty argv array"
    );
    let program = &hook.command[0];
    if program.contains('/') || program.contains('\\') {
        relative(program)?;
    }
    hook_environment(&hook.env)
}

pub(crate) fn hook_environment(
    environment: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    for (key, value) in environment {
        ensure!(
            !key.is_empty()
                && !key.to_ascii_uppercase().starts_with("KIT_")
                && !secret_name(key)
                && key.bytes().enumerate().all(|(i, c)| c == b'_'
                    || c.is_ascii_alphabetic()
                    || (i > 0 && c.is_ascii_digit()))
                && !value.contains('\0'),
            "invalid/reserved/credential hook environment key: {key}"
        );
    }
    Ok(())
}

fn unique(values: &[String], what: &str) -> Result<()> {
    ensure!(
        values.iter().collect::<BTreeSet<_>>().len() == values.len(),
        "duplicate {what}"
    );
    Ok(())
}

pub fn effective_version_binaries<'a>(
    binaries: &'a [String],
    selected: Option<&'a [String]>,
) -> &'a [String] {
    selected.unwrap_or(binaries)
}

pub fn validate(config: &Config) -> Result<()> {
    ensure!(config.schema == SCHEMA, "unsupported release.toml schema");
    ensure!(
        (1..=3600).contains(&config.timeout_seconds),
        "timeout-seconds must be 1..3600"
    );
    ensure!(!config.targets.is_empty(), "declare at least one target");
    unique(&config.targets, "target")?;
    for target in &config.targets {
        ensure!(
            TARGETS.contains(&target.as_str()),
            "unsupported target: {target}"
        );
    }
    unique(&config.generated, "generated directory")?;
    for path in &config.generated {
        relative(path)?;
        ensure!(
            path.starts_with("target/") && path.split('/').count() >= 2,
            "generated directories must be below target/"
        );
        ensure!(
            !config
                .generated
                .iter()
                .any(|other| path.starts_with(&format!("{other}/"))),
            "overlapping generated directories"
        );
    }
    for value in &config.prepare {
        hook(value)?;
    }
    ensure!(!config.products.is_empty(), "declare at least one product");
    let mut packages = BTreeSet::new();
    for product in &config.products {
        identifier(&product.package)?;
        relative(&product.manifest)?;
        ensure!(
            product.manifest == "Cargo.toml" || product.manifest.ends_with("/Cargo.toml"),
            "product manifest must name Cargo.toml"
        );
        ensure!(
            packages.insert(&product.package),
            "duplicate product: {}",
            product.package
        );
        ensure!(
            !product.binaries.is_empty(),
            "product needs selected binaries"
        );
        unique(&product.binaries, "binary")?;
        for binary in &product.binaries {
            identifier(binary)?;
        }
        if let Some(selected) = product.version_binaries.as_deref() {
            ensure!(!selected.is_empty(), "version-binaries must be nonempty");
            unique(selected, "version binary")?;
            ensure!(
                selected
                    .iter()
                    .all(|binary| product.binaries.contains(binary)),
                "version-binaries must select shipped binaries"
            );
            ensure!(
                selected.contains(&product.binaries[0]),
                "version-binaries must include the primary binary"
            );
            ensure!(
                selected.len() == product.binaries.len() || !product.checks.is_empty(),
                "omitting helper version checks requires product behavior checks"
            );
        }
        unique(&product.features, "feature")?;
        for feature in &product.features {
            identifier(feature)?;
        }
        ensure!(
            !product.version_args.is_empty()
                && product.version_args.iter().all(|s| !s.contains('\0')),
            "version-args must be a nonempty argv array"
        );
        for check in &product.checks {
            hook(check)?;
        }
        for target in &config.targets {
            let mut names = Vec::new();
            for binary in &product.binaries {
                names.push(format!(
                    "{binary}{}",
                    if target.contains("windows") {
                        ".exe"
                    } else {
                        ""
                    }
                ));
            }
            for asset in &product.assets {
                relative(&asset.source)?;
                relative(&asset.path)?;
                names.push(asset.path.clone());
            }
            let lower: Vec<_> = names.iter().map(|s| s.to_ascii_lowercase()).collect();
            unique(&lower, "archive path (case insensitive)")?;
            for path in &lower {
                ensure!(
                    !lower
                        .iter()
                        .any(|other| path.starts_with(&format!("{other}/"))),
                    "archive file/directory conflict: {path}"
                );
            }
        }
    }
    Ok(())
}

pub fn load(root: &Path) -> Result<Config> {
    let path = safe_join(root, "release.toml")?;
    let text = fs::read_to_string(path).context("read release.toml")?;
    let value: Config = toml::from_str(&text).context("parse release.toml")?;
    validate(&value)?;
    Ok(value)
}

pub fn generated(config: &Config, path: &str) -> bool {
    config
        .generated
        .iter()
        .any(|dir| path.starts_with(&format!("{dir}/")))
}

pub fn require_tracked(
    config: &Config,
    files: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    for path in ["release.toml", "Cargo.toml", "Cargo.lock"] {
        ensure!(files.contains_key(path), "required tracked input: {path}");
    }
    for product in &config.products {
        ensure!(
            files.contains_key(&product.manifest),
            "product manifest must be tracked: {}",
            product.manifest
        );
        for asset in &product.assets {
            if !generated(config, &asset.source) {
                ensure!(
                    files.contains_key(&asset.source),
                    "asset must be tracked or explicitly generated: {}",
                    asset.source
                );
            }
        }
    }
    for dir in &config.generated {
        ensure!(
            !files
                .keys()
                .any(|path| path == dir || path.starts_with(&format!("{dir}/"))),
            "generated directory contains tracked inputs: {dir}"
        );
    }
    Ok(())
}

pub fn validate_hooks(
    root: &Path,
    config: &Config,
    files: &std::collections::BTreeMap<String, String>,
) -> Result<()> {
    for name in ["release.toml", "Cargo.toml", "Cargo.lock"] {
        let path = safe_join(root, name)?;
        ensure!(
            fs::symlink_metadata(path)?.is_file(),
            "required input must be a regular file: {name}"
        );
    }
    for product in &config.products {
        safe_join(root, &product.manifest)?;
        for asset in &product.assets {
            safe_join(root, &asset.source)?;
        }
    }
    for hook in config
        .prepare
        .iter()
        .chain(config.products.iter().flat_map(|p| &p.checks))
    {
        for arg in &hook.command {
            if arg.starts_with('-') {
                continue;
            }
            let candidate = root.join(arg);
            if candidate.exists()
                || arg.contains('/')
                || [".py", ".sh", ".ps1"]
                    .iter()
                    .any(|suffix| arg.ends_with(suffix))
            {
                relative(arg)?;
                safe_join(root, arg)?;
                if !files.contains_key(arg) {
                    bail!("hook file must be tracked in source root: {arg}");
                }
            }
        }
    }
    Ok(())
}
