use crate::{
    catalog::TargetDescriptor,
    delivery::model::{PackageSpec, PackagingDefaults, Product},
    model::SourceIdentity,
    v2,
};
use serde::{Deserialize, Serialize};

pub const CONFIG_SCHEMA: u32 = 4;
pub const SCHEMA: u32 = 5;
fn timeout() -> u64 {
    1200
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    pub schema: u32,
    pub targets: Vec<TargetSelection>,
    pub products: Vec<Product>,
    #[serde(default)]
    pub packaging: PackagingDefaults,
    #[serde(default = "timeout")]
    pub timeout_seconds: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct TargetSelection {
    pub id: String,
    #[serde(default)]
    pub runtime: RuntimeConstraint,
}
impl TargetSelection {
    pub fn native(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            runtime: RuntimeConstraint::default(),
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeMode {
    #[default]
    Native,
    Emulated,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Emulator {
    QemuArm,
    QemuI386,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct RuntimeConstraint {
    #[serde(default)]
    pub mode: RuntimeMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emulator: Option<Emulator>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emulator_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rootfs_sha256: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildSpec {
    pub id: String,
    pub product: usize,
    pub target: usize,
    pub recipe: v2::model::Recipe,
    pub descriptor: TargetDescriptor,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: u32,
    pub id: String,
    pub implementation: String,
    pub engine_source_id: String,
    pub source: SourceIdentity,
    pub config: Config,
    pub resolved: Vec<v2::model::Resolution>,
    pub targets: Vec<TargetDescriptor>,
    pub builds: Vec<BuildSpec>,
    pub packages: Vec<PackageSpec>,
    pub package_profiles: Vec<crate::catalog::PackageProfile>,
    pub tasks: Vec<v2::model::Task>,
    pub source_epoch: u64,
}
