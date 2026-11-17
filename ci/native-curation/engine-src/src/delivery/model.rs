use crate::{
    model::{Asset, Hook, SourceIdentity},
    v2,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const CONFIG_SCHEMA: u32 = 3;
pub const SCHEMA: u32 = 4;
pub const NFPM_VERSION: &str = "2.49.0";

fn directory() -> String {
    ".".into()
}
fn timeout() -> u64 {
    1200
}
fn version_args() -> Vec<String> {
    vec!["--version".into()]
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Format {
    #[serde(rename = "tar.gz")]
    TarGz,
    #[serde(rename = "zip")]
    Zip,
    #[serde(rename = "deb")]
    Deb,
    #[serde(rename = "rpm")]
    Rpm,
    #[serde(rename = "apk")]
    Apk,
    #[serde(rename = "pacman")]
    Pacman,
    #[serde(rename = "ipk")]
    Ipk,
}
impl Format {
    pub fn extension(self) -> &'static str {
        match self {
            Self::TarGz => "tar.gz",
            Self::Zip => "zip",
            Self::Deb => "deb",
            Self::Rpm => "rpm",
            Self::Apk => "apk",
            Self::Pacman => "pkg.tar.zst",
            Self::Ipk => "ipk",
        }
    }
    pub fn nfpm_name(self) -> Option<&'static str> {
        match self {
            Self::TarGz | Self::Zip => None,
            Self::Deb => Some("deb"),
            Self::Rpm => Some("rpm"),
            Self::Apk => Some("apk"),
            Self::Pacman => Some("archlinux"),
            Self::Ipk => Some("ipk"),
        }
    }
    pub fn is_native(self) -> bool {
        self.nfpm_name().is_some()
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Pacman => "pacman",
            _ => self.extension(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Config {
    pub schema: u32,
    pub targets: Vec<v2::model::Target>,
    pub products: Vec<Product>,
    #[serde(default)]
    pub packaging: PackagingDefaults,
    #[serde(default = "timeout")]
    pub timeout_seconds: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct PackagingDefaults {
    #[serde(default)]
    pub formats: BTreeMap<String, Vec<Format>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Product {
    pub id: String,
    #[serde(default = "directory")]
    pub directory: String,
    pub binaries: Vec<String>,
    pub build: v2::model::Builder,
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
    #[serde(default)]
    pub packaging: ProductPackaging,
}
impl Product {
    pub fn base(&self) -> v2::model::Product {
        v2::model::Product {
            id: self.id.clone(),
            directory: self.directory.clone(),
            binaries: self.binaries.clone(),
            build: self.build.clone(),
            targets: self.targets.clone(),
            assets: self.assets.clone(),
            prepare: self.prepare.clone(),
            checks: self.checks.clone(),
            version_args: self.version_args.clone(),
            version_binaries: self.version_binaries.clone(),
        }
    }
    pub fn from_base(value: v2::model::Product) -> Self {
        Self {
            id: value.id,
            directory: value.directory,
            binaries: value.binaries,
            build: value.build,
            targets: value.targets,
            assets: value.assets,
            prepare: value.prepare,
            checks: value.checks,
            version_args: value.version_args,
            version_binaries: value.version_binaries,
            packaging: ProductPackaging::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct ProductPackaging {
    #[serde(default)]
    pub formats: BTreeMap<String, Vec<Format>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<NativeMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct NativeMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub description: String,
    pub license: String,
    pub maintainer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(default)]
    pub dependencies: BTreeMap<Format, Vec<String>>,
    #[serde(default)]
    pub install: Vec<InstallMapping>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallMapping {
    pub source: String,
    pub destination: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackendConstraint {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageMetadata {
    pub name: String,
    pub version: String,
    pub release: u32,
    pub arch: String,
    pub description: Option<String>,
    pub license: Option<String>,
    pub maintainer: Option<String>,
    pub homepage: Option<String>,
    pub dependencies: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildSpec {
    pub id: String,
    pub product: usize,
    pub target: usize,
    pub recipe: v2::model::Recipe,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageSpec {
    pub id: String,
    pub build: usize,
    pub format: Format,
    pub filename: String,
    pub metadata: PackageMetadata,
    pub native_version: Option<String>,
    pub install: Vec<InstallMapping>,
    pub source_epoch: u64,
    pub backend: Option<BackendConstraint>,
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
    pub source_epoch: u64,
    pub builds: Vec<BuildSpec>,
    pub packages: Vec<PackageSpec>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PayloadEntry {
    pub size: u64,
    pub sha256: String,
    pub mode: u32,
}

pub type PayloadManifest = BTreeMap<String, PayloadEntry>;
