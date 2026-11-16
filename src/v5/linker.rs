//! Identity of the Cargo-selected linker launcher, not its transitive SDK.
use crate::v5::model::Plan;
use crate::{config::safe_join, source, v2::model::Builder};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
pub(crate) fn keys(build: usize) -> [String; 3] {
    [
        format!("linker-launcher:u{build}"),
        format!("linker-command:u{build}"),
        format!("linker-origin:u{build}"),
    ]
}
fn executable(cwd: &Path, command: &str, base: &Path) -> Result<PathBuf> {
    let path = Path::new(command);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else if path.components().count() > 1 {
        base.join(path)
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|p| p.join(command))
            .find(|p| p.is_file())
            .with_context(|| format!("selected linker launcher unavailable: {command}"))?
    };
    let path = if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    };
    let resolved = path.canonicalize()?;
    ensure!(
        fs::metadata(&resolved)?.is_file(),
        "linker launcher is not a regular file"
    );
    Ok(resolved)
}
pub(crate) fn identity(root: &Path, plan: &Plan, build: usize) -> Result<BTreeMap<String, String>> {
    let spec = &plan.builds[build];
    let product = &plan.config.products[spec.product];
    if !matches!(product.build, Builder::Rust { .. }) {
        return Ok(BTreeMap::new());
    }
    let cwd = if product.directory == "." {
        root.to_path_buf()
    } else {
        safe_join(root, &product.directory)?
    };
    let variable = format!(
        "CARGO_TARGET_{}_LINKER",
        spec.recipe
            .compiler_target
            .to_ascii_uppercase()
            .replace('-', "_")
    );
    let env = std::env::var(&variable).ok().filter(|v| !v.is_empty());
    let (command, origin, base) = if let Some(command) = env {
        (command, format!("environment:{variable}"), cwd.clone())
    } else {
        let mut selected = None;
        let mut cfg_linker = false;
        // Cargo reads from cwd upward, with the closest file taking precedence.
        let mut locations = cwd
            .ancestors()
            .take_while(|p| p.starts_with(root))
            .map(|p| p.join(".cargo"))
            .collect::<Vec<_>>();
        if let Some(home) = std::env::var_os("CARGO_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".cargo")))
        {
            let home = if home.is_absolute() {
                home
            } else {
                cwd.join(home)
            };
            if !locations.contains(&home) {
                locations.push(home);
            }
        }
        for location in locations {
            let old = location.join("config");
            let current = location.join("config.toml");
            let path = if old.exists() { old } else { current };
            if !path.exists() {
                continue;
            }
            let ancestor = location
                .parent()
                .context("Cargo configuration parent unavailable")?;
            let relative = path
                .strip_prefix(root)?
                .to_str()
                .context("non-UTF8 Cargo config path")?
                .replace('\\', "/");
            ensure!(
                plan.source.files.get(&relative) == Some(&source::file_digest(&path)?),
                "linker configuration is outside frozen source"
            );
            let config: toml::Value = toml::from_str(&fs::read_to_string(&path)?)?;
            if let Some(targets) = config.get("target").and_then(toml::Value::as_table) {
                cfg_linker |= targets
                    .iter()
                    .any(|(k, v)| k.starts_with("cfg(") && v.get("linker").is_some());
                if selected.is_none()
                    && let Some(linker) = targets
                        .get(&spec.recipe.compiler_target)
                        .and_then(|v| v.get("linker"))
                {
                    selected = Some((
                        linker
                            .as_str()
                            .context("Cargo target linker must be a string")?
                            .to_owned(),
                        format!("tracked:{relative}"),
                        ancestor.to_path_buf(),
                    ));
                }
            }
        }
        if let Some(selected) = selected {
            selected
        } else {
            ensure!(
                !cfg_linker,
                "cfg-selected Cargo linker needs an explicit CARGO_TARGET_<TRIPLE>_LINKER pin for protocol 5"
            );
            (
                if spec.descriptor.c_abi == "msvc" {
                    "link.exe"
                } else {
                    "cc"
                }
                .into(),
                "rustc-default-launcher".into(),
                cwd.clone(),
            )
        }
    };
    ensure!(
        !command.is_empty() && !command.contains('\0'),
        "invalid linker launcher command"
    );
    let path = executable(&cwd, &command, &base)?;
    let [sha_key, command_key, origin_key] = keys(build);
    Ok(BTreeMap::from([
        (sha_key, source::file_digest(&path)?),
        (command_key, command),
        (origin_key, origin),
    ]))
}
