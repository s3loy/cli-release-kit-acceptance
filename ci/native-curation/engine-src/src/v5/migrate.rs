use super::{config, model::*};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use toml_edit::{DocumentMut, Item, Value};

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
    propose_text(&fs::read_to_string(crate::config::safe_join(
        root,
        "release.toml",
    )?)?)
}
pub fn propose_text(original: &str) -> Result<MigrationProposal> {
    let mut doc = original
        .parse::<DocumentMut>()
        .context("invalid release.toml")?;
    let from_schema = doc["schema"]
        .as_integer()
        .context("release.toml needs an integer schema")?;
    ensure!(
        matches!(from_schema, 1..=3),
        "migration accepts only release.toml schema 1, 2 or 3"
    );
    let (old, mut warnings) = if from_schema == 3 {
        let old: crate::delivery::model::Config = toml::from_str(original)?;
        crate::delivery::config::validate(&old)?;
        (old, Vec::new())
    } else {
        let intermediate = crate::delivery::migrate::propose_text(original)?;
        doc = intermediate.proposed.parse()?;
        (
            toml::from_str::<crate::delivery::model::Config>(&intermediate.proposed)?,
            intermediate.warnings,
        )
    };
    let targets = old
        .targets
        .iter()
        .map(|target| TargetSelection::native(target.key()))
        .collect();
    let converted = Config {
        schema: CONFIG_SCHEMA,
        targets,
        products: old.products,
        packaging: old.packaging,
        timeout_seconds: old.timeout_seconds,
    };
    config::validate(&converted)?;
    replace_value(&mut doc["schema"], Value::from(i64::from(CONFIG_SCHEMA)))?;
    // Replacing only the target entries preserves product filters, builder options,
    // hook argument bytes and packaging metadata in the source document.
    let mut array = toml_edit::Array::new();
    for target in &converted.targets {
        let mut entry = toml_edit::InlineTable::new();
        entry.insert("id", Value::from(target.id.clone()));
        array.push(Value::InlineTable(entry));
    }
    if doc["targets"].is_value() {
        replace_value(&mut doc["targets"], Value::Array(array))?;
    } else {
        doc["targets"] = Item::Value(Value::Array(array));
    }
    let proposed = doc.to_string();
    ensure!(
        toml::from_str::<Config>(&proposed)? == converted,
        "migration proposal changes configured behavior"
    );
    warnings.push("Migration explicitly selects native runtime for every existing target; controlled emulation requires separate constraints.".into());
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
pub fn apply(root: &Path, proposal: &MigrationProposal) -> Result<PathBuf> {
    let path = crate::config::safe_join(root, "release.toml")?;
    ensure!(
        fs::read_to_string(&path)? == proposal.original,
        "release.toml changed after migration proposal"
    );
    ensure!(
        propose_text(&proposal.original)? == *proposal,
        "migration proposal differs from canonical conversion"
    );
    let backup = crate::config::safe_join(
        root,
        &format!("release.toml.schema-{}.backup", proposal.from_schema),
    )?;
    let mut saved = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&backup)
        .context("migration backup already exists or cannot be created")?;
    saved.write_all(proposal.original.as_bytes())?;
    saved.sync_all()?;
    let temporary = crate::config::safe_join(root, "release.toml.schema-4.tmp")?;
    let original_permissions = fs::metadata(&path)?.permissions();
    let mut replacement = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    if let Err(error) = (|| -> Result<()> {
        replacement.set_permissions(original_permissions)?;
        replacement.write_all(proposal.proposed.as_bytes())?;
        replacement.sync_all()?;
        ensure!(
            fs::read_to_string(&path)? == proposal.original,
            "release.toml changed during migration"
        );
        fs::rename(&temporary, &path)?;
        Ok(())
    })() {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(path)
}
