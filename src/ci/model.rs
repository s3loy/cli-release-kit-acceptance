use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA: u32 = 1;
pub const CONTRACT: u32 = 1;

fn legacy_protocol() -> u32 {
    3
}

fn is_legacy_protocol(value: &u32) -> bool {
    *value == 3
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    pub schema: u32,
    #[serde(
        default = "legacy_protocol",
        skip_serializing_if = "is_legacy_protocol"
    )]
    pub execution_protocol: u32,
    pub engine: Engine,
    pub installs: BTreeMap<String, Install>,
    pub coordinator: Runner,
    pub workers: BTreeMap<String, Worker>,
    pub trusted: Trusted,
    pub delivery: Delivery,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Engine {
    pub version: String,
    pub source_id: String,
    pub contract: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Install {
    pub url: String,
    pub sha256: String,
    pub format: String,
    pub member: Option<String>,
    pub auth_secret: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Runner {
    pub runs_on: Vec<String>,
    pub host: String,
    pub rust_version: Option<String>,
    #[serde(default)]
    pub rust_host: Option<String>,
    pub go_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nfpm: Option<ToolPin>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub emulators: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rootfs: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ToolPin {
    pub version: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Worker {
    pub runner: Runner,
    pub targets: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Trusted {
    pub branch: String,
    pub environment: String,
    pub signing_secret: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Delivery {
    pub repository: String,
    pub environment: String,
    pub token_secret: Option<String>,
    pub policy: String,
    #[serde(default)]
    pub create_tag_if_missing: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Schedule {
    pub id: String,
    pub schema: u32,
    pub config_id: String,
    pub plan_id: String,
    pub source_commit: String,
    pub engine_source_id: String,
    pub jobs: BTreeMap<String, Vec<usize>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobRole {
    Worker,
    Rebuild,
}
