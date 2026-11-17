use crate::{
    model::{Artifact, SourceIdentity},
    v2::model::{Config, Resolution, Task, TaskResult, Unit},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA: u32 = 3;
pub const ENGINE_SOURCE_ID: &str = env!("KIT_ENGINE_SOURCE_ID");

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: u32,
    pub id: String,
    pub implementation: String,
    pub engine_source_id: String,
    pub source: SourceIdentity,
    pub config: Config,
    pub resolved: Vec<Resolution>,
    pub units: Vec<Unit>,
    pub tasks: Vec<Task>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CandidateRef {
    pub bundle_id: String,
    pub digests: BTreeMap<usize, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub schema: u32,
    pub id: String,
    pub plan_id: String,
    pub units: Vec<usize>,
    pub retry_safe_units: Vec<usize>,
    pub skip_runtime: bool,
    pub trusted_key: Option<String>,
    pub candidate: Option<CandidateRef>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub public_key: String,
    pub signature: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnitRecord {
    pub schema: u32,
    pub id: String,
    pub plan_id: String,
    pub assignment_id: String,
    pub engine_source_id: String,
    pub unit: usize,
    pub invocation: String,
    pub status: String,
    pub toolchain: BTreeMap<String, String>,
    pub tasks: Vec<TaskResult>,
    pub artifact: Artifact,
    pub candidate_match: Option<bool>,
    pub proof: Option<Proof>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub id: String,
    pub status: String,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
    pub tasks: Vec<TaskResult>,
    pub toolchain: BTreeMap<String, String>,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunReceipt {
    pub schema: u32,
    pub plan_id: String,
    pub assignment_id: String,
    pub engine_source_id: String,
    pub status: String,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub finished_at_ms: Option<u64>,
    pub invocations: Vec<Invocation>,
    pub units: BTreeMap<usize, String>,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub sha256: String,
    pub size: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub schema: u32,
    pub id: String,
    pub plan_id: String,
    pub engine_source_id: String,
    pub assignment: Assignment,
    pub units: Vec<usize>,
    pub files: BTreeMap<String, FileEntry>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct TrustedKey {
    pub public_key: String,
    #[serde(default)]
    pub products: Vec<String>,
    #[serde(default)]
    pub targets: Vec<String>,
    pub source_commit: Option<String>,
    pub engine_source_id: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Policy {
    pub schema: u32,
    pub trusted_keys: Vec<TrustedKey>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub unit: usize,
    pub bundle_id: String,
    pub record_id: String,
    pub filename: String,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collection {
    pub schema: u32,
    pub id: String,
    pub plan_id: String,
    pub engine_source_id: String,
    pub policy_id: String,
    pub status: String,
    pub publication_ready: bool,
    pub selections: Vec<Selection>,
    pub bundles: Vec<String>,
}
