use crate::model::{Artifact, Asset, Hook, SourceIdentity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA: u32 = 2;
fn directory() -> String {
    ".".into()
}
fn timeout() -> u64 {
    1200
}
fn yes() -> bool {
    true
}
fn manifest() -> String {
    "Cargo.toml".into()
}
fn version_args() -> Vec<String> {
    vec!["--version".into()]
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    pub schema: u32,
    pub targets: Vec<Target>,
    pub products: Vec<Product>,
    #[serde(default = "timeout")]
    pub timeout_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Target {
    pub os: String,
    pub arch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abi: Option<String>,
}
impl Target {
    pub fn key(&self) -> String {
        format!(
            "{}-{}{}",
            self.os,
            self.arch,
            self.abi
                .as_ref()
                .map(|s| format!("-{s}"))
                .unwrap_or_default()
        )
    }
    pub fn binary_name(&self, name: &str) -> String {
        format!("{name}{}", if self.os == "windows" { ".exe" } else { "" })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Product {
    pub id: String,
    #[serde(default = "directory")]
    pub directory: String,
    pub binaries: Vec<String>,
    pub build: Builder,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub assets: Vec<Asset>,
    #[serde(default)]
    pub prepare: Vec<Hook>,
    #[serde(default)]
    pub checks: Vec<Hook>,
    #[serde(default = "version_args")]
    pub version_args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_binaries: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Builder {
    Rust {
        package: String,
        #[serde(default = "manifest")]
        manifest: String,
        #[serde(default)]
        features: Vec<String>,
        #[serde(default = "yes", rename = "default-features")]
        default_features: bool,
    },
    Go {
        version: String,
        packages: Vec<String>,
        #[serde(default)]
        ldflags: Vec<String>,
    },
}
impl Builder {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Rust { .. } => "rust",
            Self::Go { .. } => "go",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Resolution {
    pub version: String,
    pub manifest: String,
    pub workspace_manifest: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BinaryOutput {
    pub source: String,
    pub path: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Recipe {
    pub commands: Vec<CommandSpec>,
    pub binaries: Vec<BinaryOutput>,
    pub compiler_target: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Unit {
    pub id: String,
    pub product: usize,
    pub target: usize,
    pub filename: String,
    pub recipe: Recipe,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Task {
    pub id: String,
    pub depends_on: Vec<String>,
    pub runtime: bool,
    pub action: Action,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Action {
    Probe {
        key: String,
        command: CommandSpec,
    },
    Prepare {
        unit: usize,
        command: CommandSpec,
    },
    Build {
        unit: usize,
        command: CommandSpec,
    },
    Archive {
        unit: usize,
    },
    Version {
        unit: usize,
        binary: String,
        command: CommandSpec,
    },
    Check {
        unit: usize,
        command: CommandSpec,
    },
    Seal,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: u32,
    pub id: String,
    pub implementation: String,
    pub source: SourceIdentity,
    pub config: Config,
    pub resolved: Vec<Resolution>,
    pub units: Vec<Unit>,
    pub tasks: Vec<Task>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TaskState {
    Pending,
    Running,
    Succeeded,
    Failed,
    Blocked,
    Skipped,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TaskResult {
    pub id: String,
    pub state: TaskState,
    pub elapsed_ms: u64,
    pub error: Option<String>,
    pub log: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: u32,
    pub implementation: String,
    pub plan_id: String,
    pub status: String,
    pub publication_ready: bool,
    pub started_at_ms: u64,
    pub updated_at_ms: u64,
    pub finished_at_ms: Option<u64>,
    pub toolchain: BTreeMap<String, String>,
    pub tasks: Vec<TaskResult>,
    pub artifacts: Vec<Artifact>,
    pub error: Option<String>,
}
