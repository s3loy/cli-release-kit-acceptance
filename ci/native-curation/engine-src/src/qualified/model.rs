use crate::{
    cmake,
    compatibility::Profile,
    delivery::model::{PackageSpec, PackagingDefaults, PayloadManifest, ProductPackaging},
    model::{Asset, Hook, SourceIdentity},
    v2,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const CONFIG_SCHEMA: u32 = 5;
pub const SCHEMA: u32 = 6;
fn directory() -> String {
    ".".into()
}
fn timeout() -> u64 {
    2400
}
fn version_args() -> Vec<String> {
    vec!["--version".into()]
}
fn broad() -> String {
    "broad".into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Builder {
    Existing(v2::model::Builder),
    Cmake(cmake::Spec),
}
impl Builder {
    pub fn name(&self) -> &str {
        match self {
            Self::Existing(b) => b.name(),
            Self::Cmake(_) => "cmake",
        }
    }
}
impl Serialize for Builder {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Existing(b) => b.serialize(serializer),
            Self::Cmake(spec) => {
                let mut v = serde_json::to_value(spec).map_err(serde::ser::Error::custom)?;
                v.as_object_mut()
                    .ok_or_else(|| serde::ser::Error::custom("invalid CMake spec"))?
                    .insert("kind".into(), "cmake".into());
                v.serialize(serializer)
            }
        }
    }
}
impl<'de> Deserialize<'de> for Builder {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let mut value = serde_json::Value::deserialize(d)?;
        if value.get("kind").and_then(|v| v.as_str()) == Some("cmake") {
            value.as_object_mut().unwrap().remove("kind");
            serde_json::from_value(value)
                .map(Self::Cmake)
                .map_err(serde::de::Error::custom)
        } else {
            serde_json::from_value(value)
                .map(Self::Existing)
                .map_err(serde::de::Error::custom)
        }
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
    pub inputs: Vec<crate::compatibility::ToolInput>,
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
    #[serde(default)]
    pub version_binaries: Option<Vec<String>>,
    #[serde(default)]
    pub packaging: ProductPackaging,
}
impl Product {
    pub fn legacy(&self) -> v2::model::Product {
        v2::model::Product {
            id: self.id.clone(),
            directory: self.directory.clone(),
            binaries: self.binaries.clone(),
            build: match &self.build {
                Builder::Existing(b) => b.clone(),
                Builder::Cmake(s) => v2::model::Builder::Go {
                    version: s.version.clone(),
                    packages: vec![".".into(); self.binaries.len()],
                    ldflags: vec![],
                },
            },
            targets: self.targets.clone(),
            assets: self.assets.clone(),
            prepare: self.prepare.clone(),
            checks: self.checks.clone(),
            version_args: self.version_args.clone(),
            version_binaries: self.version_binaries.clone(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct LinuxPolicy {
    #[serde(default = "broad")]
    pub policy: String,
}
impl Default for LinuxPolicy {
    fn default() -> Self {
        Self { policy: broad() }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Compatibility {
    #[serde(default)]
    pub linux: LinuxPolicy,
    #[serde(default)]
    pub windows: WindowsPolicy,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WindowsPolicy {
    #[serde(default)]
    pub crt: crate::compatibility::windows_crt::WindowsRuntimeMode,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    pub schema: u32,
    pub targets: Vec<String>,
    pub products: Vec<Product>,
    #[serde(default)]
    pub packaging: PackagingDefaults,
    #[serde(default)]
    pub compatibility: Compatibility,
    #[serde(default = "timeout")]
    pub timeout_seconds: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Recipe {
    Fixed { recipe: v2::model::Recipe },
    Cmake { spec: cmake::Spec },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Build {
    pub id: String,
    pub product: usize,
    pub target: String,
    pub profile: Profile,
    pub recipe: Recipe,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Validation {
    pub id: String,
    pub package: usize,
    pub environment: String,
    pub kind: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: u32,
    pub id: String,
    pub implementation: String,
    pub engine_source_id: String,
    pub source: SourceIdentity,
    pub source_epoch: u64,
    pub config: Config,
    pub ci_config: Option<String>,
    pub resolved: Vec<v2::model::Resolution>,
    pub builds: Vec<Build>,
    pub packages: Vec<PackageSpec>,
    pub validations: Vec<Validation>,
    pub runtimes: BTreeMap<String, crate::compatibility::RuntimeProfile>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PayloadRecord {
    pub build_id: String,
    pub files: PayloadManifest,
    pub witness: Option<cmake::Witness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmake_inputs: Option<super::cmake_boundary::CmakeBoundary>,
    pub observations: Vec<crate::compatibility::BinaryObservation>,
    pub environment: EnvironmentObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_runtime: Option<crate::compatibility::windows_crt::RuntimeWitness>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum EnvironmentObservation {
    Container {
        host: crate::compatibility::HostIdentity,
        image: crate::compatibility::ContainerImageObservation,
    },
    NativeSdk {
        sdk: crate::compatibility::NativeSdkObservation,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageRecord {
    pub package_id: String,
    pub filename: String,
    pub sha256: String,
    pub size: u64,
    pub payload_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ValidationRecord {
    pub id: String,
    pub package_sha256: String,
    pub environment_id: String,
    pub command_log: String,
    pub evidence_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    pub stage: String,
    pub message: String,
    pub invocation: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: u32,
    pub plan_id: String,
    pub source_commit: String,
    pub selected: Vec<usize>,
    pub payloads: BTreeMap<usize, PayloadRecord>,
    pub packages: BTreeMap<usize, PackageRecord>,
    pub validations: BTreeMap<String, ValidationRecord>,
    pub failures: Vec<Failure>,
    pub complete: bool,
    pub publication_ready: bool,
}
