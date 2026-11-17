use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA: u32 = 1;
// Persisted records retain this producer namespace across public package renames.
pub const IMPLEMENTATION: &str = concat!("cli-release-kit-engine/", env!("CARGO_PKG_VERSION"));

fn default_timeout() -> u64 {
    1200
}
fn default_true() -> bool {
    true
}
fn version_args() -> Vec<String> {
    vec!["--version".into()]
}
fn default_manifest() -> String {
    "Cargo.toml".into()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    pub schema: u32,
    pub targets: Vec<String>,
    pub products: Vec<Product>,
    #[serde(default)]
    pub generated: Vec<String>,
    #[serde(default)]
    pub prepare: Vec<Hook>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Product {
    pub package: String,
    #[serde(default = "default_manifest")]
    pub manifest: String,
    pub binaries: Vec<String>,
    #[serde(default)]
    pub assets: Vec<Asset>,
    #[serde(default)]
    pub features: Vec<String>,
    #[serde(default = "default_true")]
    pub default_features: bool,
    #[serde(default)]
    pub checks: Vec<Hook>,
    #[serde(default = "version_args")]
    pub version_args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_binaries: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub source: String,
    pub path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Hook {
    pub command: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub commit: String,
    pub tree: String,
    pub files: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlannedProduct {
    pub package: String,
    pub manifest: String,
    pub version: String,
    pub binaries: Vec<String>,
    pub assets: Vec<Asset>,
    pub features: Vec<String>,
    pub default_features: bool,
    pub checks: Vec<Hook>,
    pub version_args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_binaries: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Output {
    pub product: String,
    pub target: String,
    pub filename: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: u32,
    pub id: String,
    pub implementation: String,
    pub source: SourceIdentity,
    pub config: Config,
    pub products: Vec<PlannedProduct>,
    pub outputs: Vec<Output>,
    pub tasks: Vec<Task>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub id: String,
    pub kind: String,
    pub depends_on: Vec<String>,
    pub command: Vec<String>,
    pub runtime: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub path: String,
    pub sha256: String,
    pub executable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub filename: String,
    pub sha256: String,
    pub members: Vec<Member>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: u32,
    pub implementation: String,
    pub plan_id: String,
    pub status: String,
    pub publication_ready: bool,
    pub toolchain: BTreeMap<String, String>,
    pub artifacts: Vec<Artifact>,
    pub error: Option<String>,
}
