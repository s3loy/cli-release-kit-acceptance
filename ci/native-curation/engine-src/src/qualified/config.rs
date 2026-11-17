use super::model::*;
use crate::{catalog, config as common, source};
use anyhow::{Context, Result, ensure};
use std::{collections::BTreeSet, fs, path::Path};

pub fn parse(text: &str) -> Result<Config> {
    let c: Config = toml::from_str(text).context("invalid environment-qualified release.toml")?;
    validate(&c)?;
    Ok(c)
}
pub fn load(root: &Path) -> Result<Config> {
    parse(&fs::read_to_string(common::safe_join(
        root,
        "release.toml",
    )?)?)
}
pub fn validate(c: &Config) -> Result<()> {
    ensure!(
        c.schema == CONFIG_SCHEMA,
        "unsupported qualified configuration"
    );
    ensure!(
        c.compatibility.linux.policy == "broad",
        "Linux compatibility policy must be broad; changing the baseline requires a separately reviewed profile"
    );
    ensure!(
        (1..=3600).contains(&c.timeout_seconds),
        "timeout must be 1..3600 seconds"
    );
    ensure!(
        !c.targets.is_empty() && !c.products.is_empty(),
        "declare targets and products"
    );
    ensure!(
        c.targets.iter().collect::<BTreeSet<_>>().len() == c.targets.len(),
        "duplicate target"
    );
    for id in &c.targets {
        let t = catalog::resolve(id)?;
        ensure!(
            matches!(t.arch.as_str(), "x86_64" | "aarch64")
                && matches!(t.os.as_str(), "linux" | "macos" | "windows"),
            "target {id} has no qualified native environment"
        );
        ensure!(
            t.os != "linux" || t.libc == "glibc" || t.builder == "go",
            "Linux qualification supports GNU C/Rust and pure Go"
        );
    }
    let mut ids = BTreeSet::new();
    for p in &c.products {
        common::identifier(&p.id)?;
        ensure!(ids.insert(&p.id), "duplicate product");
        if p.directory != "." {
            common::relative(&p.directory)?;
        }
        ensure!(
            !p.binaries.is_empty()
                && p.binaries.iter().collect::<BTreeSet<_>>().len() == p.binaries.len(),
            "declare unique product binaries"
        );
        for b in &p.binaries {
            common::identifier(b)?;
        }
        if let Some(selected) = &p.version_binaries {
            ensure!(
                !selected.is_empty()
                    && selected.iter().all(|b| p.binaries.contains(b))
                    && selected.iter().collect::<BTreeSet<_>>().len() == selected.len(),
                "invalid version binary selection"
            );
        }
        ensure!(!p.version_args.is_empty(), "version arguments are required");
        ensure!(
            p.targets.iter().all(|t| c.targets.contains(t)),
            "product target outside global targets"
        );
        if let Builder::Cmake(s) = &p.build {
            crate::cmake::validate(s, &p.binaries)?;
        }
        let mut input_names = BTreeSet::new();
        for input in &p.inputs {
            crate::compatibility::validate_tool_input(input)?;
            if let crate::compatibility::ToolInput::Archive { name, .. } = input {
                common::identifier(name)?;
                ensure!(
                    input_names.insert(name)
                        && ![
                            "cmake",
                            "rustc",
                            "cargo",
                            "rust-std",
                            "go",
                            "gcc10",
                            "make",
                            "nfpm",
                            "cargo-registry",
                            "go-modules",
                            "program",
                            "validation-source"
                        ]
                        .contains(&name.as_str()),
                    "duplicate or reserved dependency input name"
                );
            } else {
                anyhow::bail!("product dependencies require explicit archive inputs");
            }
        }
        for asset in &p.assets {
            if let Some(input) = asset.source.strip_prefix("input:") {
                let (name, path) = input
                    .split_once('/')
                    .context("input asset requires name/path")?;
                common::identifier(name)?;
                common::relative(path)?;
            } else {
                common::relative(&asset.source)?;
            }
            common::relative(&asset.path)?;
            ensure!(
                !p.binaries.contains(&asset.path),
                "asset collides with executable"
            );
        }
        for h in p.prepare.iter().chain(&p.checks) {
            ensure!(
                !h.command.is_empty() && h.command.iter().all(|a| !a.contains('\0')),
                "invalid hook argv"
            );
            common::hook_environment(&h.env)?;
        }
    }
    for formats in c
        .packaging
        .formats
        .values()
        .chain(c.products.iter().flat_map(|p| p.packaging.formats.values()))
    {
        ensure!(
            !formats.is_empty() && formats.iter().collect::<BTreeSet<_>>().len() == formats.len(),
            "declare unique formats"
        );
        ensure!(
            formats.iter().all(|f| matches!(
                f,
                crate::delivery::model::Format::TarGz
                    | crate::delivery::model::Format::Zip
                    | crate::delivery::model::Format::Deb
                    | crate::delivery::model::Format::Rpm
            )),
            "this compatibility increment qualifies tar.gz, ZIP, deb and rpm; other formats retain their legacy path"
        );
    }
    Ok(())
}
pub fn validate_source(
    root: &Path,
    c: &Config,
    identity: &crate::model::SourceIdentity,
) -> Result<()> {
    ensure!(
        identity.files.get("release.toml")
            == Some(&source::file_digest(&root.join("release.toml"))?),
        "configuration is outside the source identity"
    );
    for p in &c.products {
        match &p.build {
            Builder::Cmake(s) => {
                crate::cmake::source_inputs(root, &p.directory, s, &identity.files)?;
            }
            Builder::Existing(_) => {
                crate::v2::builder::resolve(root, &p.legacy(), &identity.files)?;
            }
        }
        for a in &p.assets {
            if !a.source.starts_with("input:") {
                ensure!(
                    identity.files.contains_key(&a.source),
                    "untracked asset {}",
                    a.source
                );
                common::safe_join(root, &a.source)?;
            }
        }
    }
    Ok(())
}
pub fn formats(c: &Config, p: usize, os: &str) -> Vec<crate::delivery::model::Format> {
    c.products[p]
        .packaging
        .formats
        .get(os)
        .or_else(|| c.packaging.formats.get(os))
        .cloned()
        .unwrap_or_else(|| {
            vec![if os == "windows" {
                crate::delivery::model::Format::Zip
            } else {
                crate::delivery::model::Format::TarGz
            }]
        })
}
