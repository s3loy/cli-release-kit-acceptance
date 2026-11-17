use super::model::*;
use crate::{config as legacy, v2};
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeSet, fs, path::Path};

pub fn load(root: &Path) -> Result<Config> {
    let path = legacy::safe_join(root, "release.toml")?;
    let value: Config =
        toml::from_str(&fs::read_to_string(path)?).context("invalid schema-3 release.toml")?;
    validate(&value)?;
    Ok(value)
}

pub fn base_config(c: &Config) -> v2::model::Config {
    v2::model::Config {
        schema: v2::model::SCHEMA,
        targets: c.targets.clone(),
        products: c.products.iter().map(Product::base).collect(),
        timeout_seconds: c.timeout_seconds,
    }
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

pub fn validate(c: &Config) -> Result<()> {
    ensure!(
        c.schema == CONFIG_SCHEMA,
        "unsupported release.toml schema; migrate explicitly to schema 3"
    );
    v2::contract::validate(&base_config(c))?;
    formats(&c.packaging.formats)?;
    for (pi, p) in c.products.iter().enumerate() {
        formats(&p.packaging.formats)?;
        let native_needed = c
            .targets
            .iter()
            .filter(|t| p.targets.is_empty() || p.targets.contains(&t.key()))
            .any(|t| {
                effective_formats(c, pi, &t.os)
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
    Ok(())
}
