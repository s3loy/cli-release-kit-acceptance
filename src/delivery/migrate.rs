use super::{config, model::*};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use toml_edit::{DocumentMut, Item, Table, Value, value};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationProposal {
    pub from_schema: u32,
    pub to_schema: u32,
    pub original: String,
    pub proposed: String,
    pub warnings: Vec<String>,
}

pub fn propose(root: &Path) -> Result<MigrationProposal> {
    let original = fs::read_to_string(crate::config::safe_join(root, "release.toml")?)?;
    propose_text(&original)
}

pub fn propose_text(original: &str) -> Result<MigrationProposal> {
    let mut doc = original
        .parse::<DocumentMut>()
        .context("invalid release.toml")?;
    let from_schema = doc["schema"]
        .as_integer()
        .context("release.toml needs an integer schema")?;
    ensure!(
        matches!(from_schema, 1 | 2),
        "migration accepts only release.toml schema 1 or 2"
    );
    let warnings = Vec::new();
    if from_schema == 2 {
        let old: crate::v2::model::Config = toml::from_str(original)?;
        crate::v2::contract::validate(&old)?;
    } else {
        let old: crate::model::Config = toml::from_str(original)?;
        crate::config::validate(&old)?;
        // Generated v1 hooks can write shared source-root directories. Their
        // transformation requires a user-reviewed hook change, not a field rename.
        ensure!(
            old.generated.is_empty(),
            "schema-1 generated directories require manual hook and {{generated}} asset migration before a schema-3 proposal"
        );
        ensure!(
            old.prepare.is_empty(),
            "schema-1 global prepare hooks require manual migration to per-product, per-target hooks before a schema-3 proposal"
        );
        let targets = old
            .targets
            .iter()
            .map(|target| {
                let (arch, os, abi) = match target.as_str() {
                    "x86_64-apple-darwin" => ("x86_64", "macos", None),
                    "aarch64-apple-darwin" => ("aarch64", "macos", None),
                    "x86_64-pc-windows-msvc" => ("x86_64", "windows", Some("msvc")),
                    "aarch64-pc-windows-msvc" => ("aarch64", "windows", Some("msvc")),
                    "x86_64-unknown-linux-gnu" => ("x86_64", "linux", Some("gnu")),
                    "aarch64-unknown-linux-gnu" => ("aarch64", "linux", Some("gnu")),
                    "x86_64-unknown-linux-musl" => ("x86_64", "linux", Some("musl")),
                    "aarch64-unknown-linux-musl" => ("aarch64", "linux", Some("musl")),
                    _ => bail!("unsupported legacy target: {target}"),
                };
                let mut entry = toml_edit::InlineTable::new();
                entry.insert("os", Value::from(os));
                entry.insert("arch", Value::from(arch));
                if let Some(abi) = abi {
                    entry.insert("abi", Value::from(abi));
                }
                Ok(Value::InlineTable(entry))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut array = toml_edit::Array::new();
        for target in targets {
            array.push(target);
        }
        replace_value(&mut doc["targets"], Value::Array(array))?;
        let prepare = doc.remove("prepare");
        doc.remove("generated");
        let products = doc["products"]
            .as_array_of_tables_mut()
            .context("schema-1 products must use [[products]] tables")?;
        for product in products.iter_mut() {
            let package = product
                .remove("package")
                .context("legacy product package missing")?;
            product.insert("id", package.clone());
            let mut build = Table::new();
            build["kind"] = value("rust");
            build.insert("package", package);
            for key in ["manifest", "features", "default-features"] {
                if let Some(item) = product.remove(key) {
                    build.insert(key, item);
                }
            }
            product.insert("build", Item::Table(build));
            if let Some(prepare) = &prepare {
                product.insert("prepare", prepare.clone());
            }
        }
    }
    replace_value(&mut doc["schema"], Value::from(i64::from(CONFIG_SCHEMA)))?;
    let proposed = doc.to_string();
    let converted: Config =
        toml::from_str(&proposed).context("migration proposal is not schema-3 TOML")?;
    config::validate(&converted)?;
    Ok(MigrationProposal {
        from_schema: from_schema as u32,
        to_schema: CONFIG_SCHEMA,
        original: original.into(),
        proposed,
        warnings,
    })
}

fn replace_value(item: &mut Item, mut replacement: Value) -> Result<()> {
    let old = item.as_value().context("expected TOML value")?;
    *replacement.decor_mut() = old.decor().clone();
    *item = Item::Value(replacement);
    Ok(())
}
