use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Architecture {
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "aarch64")]
    Aarch64,
}
impl Architecture {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "x86_64" | "amd64" => Ok(Self::X86_64),
            "aarch64" | "arm64" => Ok(Self::Aarch64),
            _ => bail!("unsupported native6 architecture: {value}"),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
    pub fn platform(self) -> &'static str {
        match self {
            Self::X86_64 => "linux/amd64",
            Self::Aarch64 => "linux/arm64",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ImagePin {
    pub name: String,
    pub discovery_reference: String,
    pub reference: String,
    pub platform: String,
    pub index_digest: String,
    pub manifest_digest: String,
    pub config_digest: String,
    pub compressed_layer_bytes: u64,
    pub created: Option<String>,
    pub registry: String,
    #[serde(default)]
    pub metadata_verified_at: Option<String>,
    #[serde(default)]
    pub qualification: Option<String>,
}
pub(crate) fn digest(value: &str) -> Result<()> {
    let hash = value
        .strip_prefix("sha256:")
        .context("expected sha256 digest")?;
    ensure!(
        hash.len() == 64
            && hash
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "invalid lowercase SHA256 digest"
    );
    Ok(())
}
impl ImagePin {
    pub fn validate(&self, arch: Architecture) -> Result<()> {
        digest(&self.index_digest)?;
        digest(&self.manifest_digest)?;
        digest(&self.config_digest)?;
        ensure!(
            self.platform == arch.platform(),
            "image platform differs from native target"
        );
        let (repository, actual) = self
            .reference
            .rsplit_once('@')
            .context("container image must use a digest reference")?;
        ensure!(
            !repository.is_empty()
                && !repository.contains(char::is_whitespace)
                && !repository.contains('@')
                && actual == self.manifest_digest,
            "image reference differs from pinned single-platform manifest"
        );
        Ok(())
    }
}

/// Image-contained tools are pinned by the complete image manifest. Archive
/// tools are pinned by their own bytes, independently of a requested version.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ArchiveLinkPolicy {
    #[default]
    Materialize,
    PreserveVerified,
}
impl ArchiveLinkPolicy {
    pub fn is_materialize(&self) -> bool {
        *self == Self::Materialize
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ToolInput {
    ImageContained {
        name: String,
        path: String,
        manifest_digest: String,
    },
    Archive {
        name: String,
        version: String,
        url: String,
        sha256: String,
        filename: String,
        #[serde(default, skip_serializing_if = "ArchiveLinkPolicy::is_materialize")]
        link_policy: ArchiveLinkPolicy,
    },
    /// A pinned file retained without archive interpretation or execution.
    Raw {
        name: String,
        version: String,
        url: String,
        sha256: String,
        filename: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeSdkExpectation {
    pub sdk_id: String,
    pub sdk_version: String,
    pub sdk_content_sha256: String,
    #[serde(default)]
    pub roots: BTreeMap<String, String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    /// Full absolute tool paths mapped to SHA256 values, supplied by reviewed CI configuration.
    pub tool_sha256: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeSdkObservation {
    pub sdk_id: String,
    pub sdk_version: String,
    pub sdk_content_sha256: String,
    #[serde(default)]
    pub roots: BTreeMap<String, String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    pub tool_sha256: BTreeMap<String, String>,
    pub tool_versions: BTreeMap<String, String>,
    pub host_os: String,
    pub host_arch: Architecture,
}
// Saved SDK paths describe the target platform, independent of the host that
// plans or verifies them. Filesystem canonicalization belongs to the native
// runner; verbatim/device and UNC namespaces require a separate contract.
fn absolute_sdk_path(path: &str) -> bool {
    if path.is_empty()
        || path.len() > 32768
        || path.chars().any(char::is_control)
        || path.starts_with("//")
        || path.starts_with("\\")
    {
        return false;
    }
    if let Some(body) = path.strip_prefix('/') {
        return !body.contains('\\')
            && (body.is_empty()
                || body
                    .split('/')
                    .all(|part| !part.is_empty() && part != "." && part != ".."));
    }
    let bytes = path.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || !matches!(bytes[2], b'/' | b'\\')
    {
        return false;
    }
    let body = &path[3..];
    if body.is_empty() {
        return true;
    }
    let separator = bytes[2] as char;
    let other_separator = if separator == '/' { '\\' } else { '/' };
    !body.contains(other_separator)
        && body.split(separator).all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.ends_with(['.', ' '])
                && !part.contains([':', '<', '>', '"', '|', '?', '*'])
        })
}

impl NativeSdkExpectation {
    pub fn roots_digest(roots: &BTreeMap<String, String>) -> Result<String> {
        let mut bytes = b"relship/native-sdk-roots/v1\0".to_vec();
        bytes.extend(serde_json::to_vec(roots)?);
        Ok(crate::source::digest(&bytes))
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.sdk_id.is_empty() && !self.sdk_version.is_empty(),
            "native SDK requires an explicit identity and version"
        );
        digest(&format!("sha256:{}", self.sdk_content_sha256))?;
        ensure!(
            !self.roots.is_empty() && self.roots.len() <= 32,
            "native SDK requires reviewed SDK root tree identities"
        );
        for (path, sha) in &self.roots {
            ensure!(
                absolute_sdk_path(path),
                "native SDK root path must be absolute and normalized"
            );
            digest(&format!("sha256:{sha}"))?;
        }
        ensure!(
            self.sdk_content_sha256 == Self::roots_digest(&self.roots)?,
            "native SDK content digest differs from canonical root identities"
        );
        const ALLOWED: &[&str] = &[
            "INCLUDE",
            "LIB",
            "LIBPATH",
            "PATH",
            "SDKROOT",
            "DEVELOPER_DIR",
            "MACOSX_DEPLOYMENT_TARGET",
            "CC",
            "AR",
            "LD",
        ];
        for (name, value) in &self.environment {
            ensure!(
                ALLOWED.contains(&name.as_str())
                    && !crate::config::secret_name(name)
                    && value.len() <= 32768
                    && !value.contains(['\n', '\r', '\0']),
                "unsupported or unsafe native SDK environment entry"
            );
        }
        ensure!(
            !self.tool_sha256.is_empty() && self.tool_sha256.len() <= 128,
            "native SDK requires pinned compiler tool bytes"
        );
        for (path, sha) in &self.tool_sha256 {
            ensure!(absolute_sdk_path(path), "native tool path must be absolute");
            digest(&format!("sha256:{sha}"))?;
        }
        Ok(())
    }
    pub fn verify(
        &self,
        observed: &NativeSdkObservation,
        os: &str,
        arch: Architecture,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            observed.host_os == os && observed.host_arch == arch,
            "native SDK observation comes from another host OS or architecture"
        );
        ensure!(
            observed.sdk_id == self.sdk_id
                && observed.sdk_version == self.sdk_version
                && observed.sdk_content_sha256 == self.sdk_content_sha256
                && observed.tool_sha256 == self.tool_sha256
                && observed.roots == self.roots
                && observed.environment == self.environment,
            "observed native SDK or tool identity differs from the saved expectation; changed roots: {}",
            self.roots
                .keys()
                .chain(observed.roots.keys())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .filter(|path| self.roots.get(*path) != observed.roots.get(*path))
                .take(8)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        );
        ensure!(
            self.tool_sha256.keys().all(|p| observed
                .tool_versions
                .get(p)
                .is_some_and(|v| !v.trim().is_empty())),
            "native tool version observation is missing"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Environment {
    LinuxContainer {
        image: ImagePin,
        tools: Vec<ToolInput>,
    },
    NativeSdk {
        os: String,
        arch: Architecture,
        sdk: NativeSdkExpectation,
        tools: Vec<ToolInput>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub os: String,
    pub arch: Architecture,
    pub minimum_libc: Option<String>,
    pub minimum_os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub windows_runtime: Option<super::windows_crt::WindowsRuntimePolicy>,
    pub environment: Environment,
    pub qualification: String,
}
impl Profile {
    pub fn linux_glibc217(arch: Architecture) -> Result<Self> {
        resolve_native6("linux", arch, None)
    }
    pub fn linux_pure_go(arch: Architecture) -> Result<Self> {
        let mut profile = Self::linux_glibc217(arch)?;
        profile.id = format!("linux-{}-pure-go", arch.name());
        profile.minimum_libc = None;
        profile.qualification = "Pinned build userspace for pure Go. Produced ELF must be static, with no interpreter or DT_NEEDED; no minimum libc is claimed. Target runtime evidence is still required.".into();
        profile.validate()?;
        Ok(profile)
    }
    pub fn identity(&self) -> Result<String> {
        self.validate()?;
        let mut bytes = b"relship/compatibility-profile/v1\0".to_vec();
        bytes.extend(serde_json::to_vec(self)?);
        Ok(crate::source::digest(&bytes))
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.id.is_empty(), "compatibility profile lacks an ID");
        match &self.environment {
            Environment::LinuxContainer { image, tools } => {
                ensure!(
                    self.os == "linux",
                    "container compatibility profile must target Linux"
                );
                if self.id.ends_with("-pure-go") {
                    ensure!(
                        self.minimum_libc.is_none(),
                        "pure Go profile must not claim a minimum libc requirement"
                    );
                } else {
                    ensure!(
                        self.minimum_libc.as_deref() == Some("2.17"),
                        "GNU Linux profile must retain glibc 2.17; automatic baseline increases or omission are forbidden"
                    );
                }
                image.validate(self.arch)?;
                for tool in tools {
                    validate_tool(tool, Some(&image.manifest_digest))?;
                }
            }
            Environment::NativeSdk {
                os,
                arch,
                sdk,
                tools,
            } => {
                ensure!(
                    matches!(os.as_str(), "macos" | "windows")
                        && *os == self.os
                        && *arch == self.arch,
                    "native SDK target differs from profile"
                );
                sdk.validate()?;
                if let Some(runtime) = &self.windows_runtime {
                    ensure!(
                        self.os == "windows",
                        "Windows runtime policy requires Windows"
                    );
                    runtime.validate(sdk)?;
                }
                for tool in tools {
                    validate_tool(tool, None)?;
                }
            }
        }
        Ok(())
    }
}
/// Basic input validation is independent of the environment that binds an
/// image-contained executable to a selected manifest.
pub fn validate_tool_input(tool: &ToolInput) -> Result<()> {
    match tool {
        ToolInput::ImageContained {
            name,
            path,
            manifest_digest,
        } => {
            crate::config::relative(name)?;
            ensure!(
                !name.contains('/')
                    && path.starts_with('/')
                    && !path.contains(['\\', '\n', '\r', '\0'])
                    && !path.split('/').any(|part| part == "." || part == ".."),
                "image-contained tool requires a name and normalized absolute Linux path"
            );
            digest(manifest_digest)?;
        }
        ToolInput::Archive {
            name,
            version,
            url,
            sha256,
            filename,
            ..
        }
        | ToolInput::Raw {
            name,
            version,
            url,
            sha256,
            filename,
        } => {
            crate::config::relative(name)?;
            ensure!(
                !name.contains('/')
                    && !version.trim().is_empty()
                    && !version.chars().any(char::is_control),
                "invalid pinned input name or version"
            );
            super::acquire::validate_download_url(url)?;
            crate::config::relative(filename)?;
            ensure!(
                !filename.contains('/'),
                "downloaded input filename must be a basename"
            );
            digest(&format!("sha256:{sha256}"))?;
        }
    }
    Ok(())
}
fn validate_tool(tool: &ToolInput, image: Option<&String>) -> Result<()> {
    validate_tool_input(tool)?;
    if let ToolInput::ImageContained {
        manifest_digest, ..
    } = tool
    {
        ensure!(
            image == Some(manifest_digest),
            "image tool must be bound to the selected environment manifest"
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProfile {
    pub id: String,
    pub arch: Architecture,
    pub glibc_version: String,
    pub image: ImagePin,
    pub qualification: String,
}
fn images(arch: Architecture) -> Result<Vec<ImagePin>> {
    let json = match arch {
        Architecture::X86_64 => include_str!("x86_64-image-pins.json"),
        Architecture::Aarch64 => include_str!("arm64-image-pins.json"),
    };
    let values: Vec<ImagePin> = serde_json::from_str(json)?;
    for pin in &values {
        pin.validate(arch)?;
    }
    Ok(values)
}
pub fn builtin_runtime_profiles(arch: Architecture) -> Result<Vec<RuntimeProfile>> {
    let images = images(arch)?;
    [ ("runtime217", "2.17"), ("runtime231", "2.31"), ("runtime239", "2.39") ].into_iter().map(|(name, version)| {
        Ok(RuntimeProfile { id: format!("linux-{}-glibc-{version}", arch.name()), arch, glibc_version: version.into(), image: images.iter().find(|p| p.name == name).context("missing curated runtime image")?.clone(), qualification: "Pinned userspace input; execution evidence is required. A container does not qualify host kernel or hardware.".into() })
    }).collect()
}
pub fn cmake_tool(os: &str, arch: Architecture) -> Result<ToolInput> {
    let (suffix, hash) = match (os, arch) {
        ("linux", Architecture::X86_64) => (
            "linux-x86_64.tar.gz",
            "0dc2e9a6860f06bf10bd8fadc03e35d9eeb4df46e33763a7e480e987758f385c",
        ),
        ("linux", Architecture::Aarch64) => (
            "linux-aarch64.tar.gz",
            "83f8fd91d2038a56556e1400390fcfe42f79602940c494f6c6f1cdae7f9e7f40",
        ),
        ("macos", _) => (
            "macos-universal.tar.gz",
            "799af7fd545db9bf1b9cfe72f8095880e727a2d4e0df0e3dffc3bc7b95c2d3b0",
        ),
        ("windows", Architecture::X86_64) => (
            "windows-x86_64.zip",
            "0c4baa40f28b3f8225eb3fdf6946c987b4fe901403b4eaf2fbbd9378100aaa0c",
        ),
        ("windows", Architecture::Aarch64) => (
            "windows-arm64.zip",
            "e4160c1842dea858ad376ff2ec17587104515b51714eca5963b8bdd798105553",
        ),
        _ => bail!("unsupported CMake native6 OS: {os}"),
    };
    let filename = format!("cmake-3.31.12-{suffix}");
    Ok(ToolInput::Archive {
        name: "cmake".into(),
        version: "3.31.12".into(),
        url: format!("https://github.com/Kitware/CMake/releases/download/v3.31.12/{filename}"),
        sha256: hash.into(),
        filename,
        link_policy: if os == "macos" {
            ArchiveLinkPolicy::PreserveVerified
        } else {
            ArchiveLinkPolicy::Materialize
        },
    })
}
/// Native macOS and Windows resolution requires an explicit SDK byte identity.
/// Runner labels and a version request cannot stand in for that identity.
pub fn resolve_native6(
    os: &str,
    arch: Architecture,
    sdk: Option<NativeSdkExpectation>,
) -> Result<Profile> {
    let tools = vec![cmake_tool(os, arch)?];
    let profile = if os == "linux" {
        ensure!(sdk.is_none(), "Linux uses the pinned container SDK");
        let image = images(arch)?
            .into_iter()
            .find(|p| p.name == "build217")
            .context("missing curated build image")?;
        let mut tools = tools;
        tools.push(ToolInput::ImageContained {
            name: "gcc10".into(),
            path: "/opt/rh/devtoolset-10/root/usr/bin/gcc".into(),
            manifest_digest: image.manifest_digest.clone(),
        });
        tools.push(ToolInput::ImageContained {
            name: "make".into(),
            path: "/usr/bin/make".into(),
            manifest_digest: image.manifest_digest.clone(),
        });
        Profile { id: format!("native6-linux-{}-glibc-2.17-v1", arch.name()), os: os.into(), arch, minimum_libc: Some("2.17".into()), minimum_os: None, windows_runtime: None, environment: Environment::LinuxContainer { image, tools }, qualification: "Pinned build input. Each produced artifact still requires ABI, closure and runtime validation; ARM64 is not qualified by x86_64 experiment results.".into() }
    } else {
        ensure!(
            matches!(os, "windows" | "macos"),
            "unsupported native6 OS: {os}"
        );
        let sdk = sdk.context("native SDK is not pinned: provide reviewed SDK content and compiler hashes; runner labels are insufficient")?;
        Profile { id: format!("native6-{os}-{}-v1", arch.name()), os: os.into(), arch, minimum_libc: None, minimum_os: None, windows_runtime: None, environment: Environment::NativeSdk { os: os.into(), arch, sdk, tools }, qualification: "Pinned native SDK expectation; actual SDK/tool observations and target runtime evidence are required.".into() }
    };
    profile.validate()?;
    Ok(profile)
}

#[derive(Deserialize)]
struct LanguageTools {
    os: String,
    arch: Architecture,
    language: String,
    tools: Vec<ToolInput>,
}
pub fn language_tools(kind: &str, arch: Architecture) -> Result<Vec<ToolInput>> {
    language_tools_for("linux", kind, arch)
}
pub fn language_tools_for(os: &str, kind: &str, arch: Architecture) -> Result<Vec<ToolInput>> {
    if kind == "cmake" || kind == "c" {
        return Ok(vec![cmake_tool(os, arch)?]);
    }
    let values: Vec<LanguageTools> =
        serde_json::from_str(include_str!("pins/language-tools.json"))?;
    let tools = values
        .into_iter()
        .find(|v| v.os == os && v.arch == arch && v.language == kind)
        .with_context(|| {
            format!(
                "unsupported pinned language tool request: {kind}/{os}/{}",
                arch.name()
            )
        })?
        .tools;
    for tool in &tools {
        validate_tool(tool, None)?;
    }
    Ok(tools)
}
/// Verify frozen primary registry responses without downloading image layers.
pub fn verify_registry_metadata(
    pin: &ImagePin,
    index: &[u8],
    manifest: &[u8],
    config: &[u8],
) -> Result<()> {
    for (bytes, expected) in [
        (index, &pin.index_digest),
        (manifest, &pin.manifest_digest),
        (config, &pin.config_digest),
    ] {
        ensure!(
            bytes.len() <= 1024 * 1024
                && format!("sha256:{}", crate::source::digest(bytes)) == *expected,
            "frozen registry response digest differs from image pin"
        );
    }
    let index: serde_json::Value = serde_json::from_slice(index)?;
    let manifest: serde_json::Value = serde_json::from_slice(manifest)?;
    let config: serde_json::Value = serde_json::from_slice(config)?;
    ensure!(
        manifest["config"]["digest"].as_str() == Some(&pin.config_digest),
        "registry manifest config differs from pinned config"
    );
    let arch = Architecture::parse(
        config["architecture"]
            .as_str()
            .context("registry config lacks architecture")?,
    )?;
    pin.validate(arch)?;
    ensure!(
        config["os"].as_str() == Some("linux"),
        "registry image config is not Linux"
    );
    if let Some(entries) = index["manifests"].as_array() {
        ensure!(
            entries
                .iter()
                .filter(|m| m["digest"].as_str() == Some(&pin.manifest_digest)
                    && m["platform"]["os"].as_str() == Some("linux")
                    && m["platform"]["architecture"]
                        .as_str()
                        .is_some_and(|a| Architecture::parse(a).ok() == Some(arch)))
                .count()
                == 1,
            "registry index lacks one matching single-platform manifest"
        );
    } else {
        ensure!(
            pin.index_digest == pin.manifest_digest,
            "non-index registry response differs from manifest"
        );
    }
    Ok(())
}
