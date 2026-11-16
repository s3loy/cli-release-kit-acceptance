use crate::cohort::model::FileEntry;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    pub id: u64,
    pub full_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub id: u64,
    pub login: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub name: String,
    pub size: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: u32,
    pub id: String,
    pub implementation: String,
    pub engine_source_id: String,
    pub collection_id: String,
    pub policy_id: String,
    pub source_commit: String,
    pub repository: Repository,
    pub tag: String,
    pub create_tag_if_missing: bool,
    pub title: String,
    pub notes: String,
    pub prerelease: bool,
    pub assets: Vec<Asset>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub operation: String,
    pub asset: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub at_ms: u64,
    pub operation: String,
    pub outcome: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: u32,
    pub plan_id: String,
    pub correlation: String,
    pub status: String,
    pub release_id: Option<u64>,
    pub pending: Option<Intent>,
    pub confirmed_assets: std::collections::BTreeMap<String, u64>,
    pub events: Vec<Event>,
    pub updated_at_ms: u64,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Release {
    pub id: u64,
    pub tag_name: String,
    pub draft: bool,
    pub prerelease: bool,
    pub name: Option<String>,
    pub body: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RemoteAsset {
    pub id: u64,
    pub name: String,
    pub state: String,
    pub size: u64,
    pub digest: Option<String>,
}

/// Internal stop reasons; receipt status does not depend on human-readable text.
#[derive(Debug)]
pub(super) enum DraftFailure {
    Conflict(String),
    NeedsDecision(String),
}
impl DraftFailure {
    pub(super) fn status(&self) -> &'static str {
        match self {
            Self::Conflict(_) => "conflict",
            Self::NeedsDecision(_) => "needs-decision",
        }
    }
}
impl std::fmt::Display for DraftFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::Conflict(message) | Self::NeedsDecision(message) => message,
        };
        write!(formatter, "{}: {message}", self.status())
    }
}
impl std::error::Error for DraftFailure {}

/// Domain operations used by the draft state machine. No publish/delete API exists.
pub trait Api {
    fn repository(&mut self, repo: &str) -> Result<Repository>;
    fn commit_exists(&mut self, repo: &str, commit: &str) -> Result<()>;
    /// Resolve an exact lightweight or annotated tag to its final commit.
    fn tag(&mut self, repo: &str, tag: &str) -> Result<Option<String>>;
    fn create_tag(&mut self, repo: &str, tag: &str, commit: &str) -> Result<()>;
    fn releases(&mut self, repo: &str) -> Result<Vec<Release>>;
    fn release(&mut self, repo: &str, id: u64) -> Result<Release>;
    fn create_draft(&mut self, plan: &Plan, body: &str) -> Result<Release>;
    fn assets(&mut self, repo: &str, release: u64) -> Result<Vec<RemoteAsset>>;
    fn upload(
        &mut self,
        repo: &str,
        release: u64,
        asset: &Asset,
        path: &Path,
    ) -> Result<RemoteAsset>;
    fn download_digest(&mut self, repo: &str, asset: u64, expected_size: u64) -> Result<FileEntry>;
}
