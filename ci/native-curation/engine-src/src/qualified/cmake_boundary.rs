use super::model::{Plan, Recipe};
use crate::compatibility::{Environment, ToolInput};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CmakeBoundary {
    pub inputs: BTreeMap<String, String>,
    pub selection: crate::cmake::InputSelection,
}

// Recorded paths belong to the execution host. In particular, Path::components
// on a Unix verifier cannot interpret Windows drives or backslash separators.
#[derive(Clone, Debug)]
struct AbsolutePath {
    prefix: String,
    parts: Vec<String>,
    windows: bool,
}

impl AbsolutePath {
    fn parse(value: &str, windows: bool) -> Result<Self> {
        ensure!(
            !value.is_empty()
                && value.len() <= 32768
                && !value.chars().any(char::is_control)
                && !value.starts_with(['\\'])
                && !value.starts_with("//"),
            "CMake boundary path must be an absolute normalized path"
        );
        let normalized = if windows {
            value.replace('\\', "/")
        } else {
            ensure!(
                !value.contains('\\'),
                "CMake boundary path contains a foreign separator"
            );
            value.to_owned()
        };
        let (prefix, body) = if windows {
            let bytes = normalized.as_bytes();
            ensure!(
                bytes.len() >= 3
                    && bytes[0].is_ascii_alphabetic()
                    && bytes[1] == b':'
                    && bytes[2] == b'/',
                "Windows CMake boundary path requires an absolute drive path"
            );
            (normalized[..2].to_owned(), &normalized[3..])
        } else {
            (
                String::new(),
                normalized
                    .strip_prefix('/')
                    .context("CMake boundary path must be absolute")?,
            )
        };
        let parts = if body.is_empty() {
            vec![]
        } else {
            ensure!(
                body.split('/')
                    .all(|part| !part.is_empty() && part != "." && part != ".."),
                "CMake boundary path must not contain empty, dot or parent components"
            );
            if windows {
                crate::config::relative(body)?;
            }
            body.split('/').map(str::to_owned).collect()
        };
        Ok(Self {
            prefix,
            parts,
            windows,
        })
    }

    fn from_path(path: &Path, windows: bool) -> Result<Self> {
        Self::parse(
            path.to_str().context("non-UTF8 CMake boundary path")?,
            windows,
        )
    }

    fn same_text(&self, left: &str, right: &str) -> bool {
        if self.windows {
            left.eq_ignore_ascii_case(right)
        } else {
            left == right
        }
    }

    fn beneath(&self, root: &Self) -> bool {
        self.windows == root.windows
            && self.same_text(&self.prefix, &root.prefix)
            && self.parts.len() >= root.parts.len()
            && self
                .parts
                .iter()
                .zip(&root.parts)
                .all(|(left, right)| self.same_text(left, right))
    }

    fn same(&self, other: &Self) -> bool {
        self.parts.len() == other.parts.len() && self.beneath(other)
    }

    fn truncate(&self, length: usize) -> Self {
        Self {
            prefix: self.prefix.clone(),
            parts: self.parts[..length].to_vec(),
            windows: self.windows,
        }
    }

    fn join(&self, parts: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        let mut path = self.clone();
        path.parts
            .extend(parts.into_iter().map(|part| part.as_ref().to_owned()));
        path
    }

    fn path_buf(&self) -> PathBuf {
        PathBuf::from(format!("{}/{}", self.prefix, self.parts.join("/")))
    }
}

fn input_names(tools: &[ToolInput], product: &[ToolInput]) -> Result<BTreeMap<String, bool>> {
    let mut expected = BTreeMap::new();
    for input in tools.iter().chain(product) {
        let (name, raw) = match input {
            ToolInput::Archive { name, .. } => (name, false),
            ToolInput::Raw { name, .. } => (name, true),
            ToolInput::ImageContained { .. } => continue,
        };
        crate::config::identifier(name)?;
        ensure!(
            expected.insert(name.clone(), raw).is_none(),
            "duplicate CMake dependency input name"
        );
    }
    Ok(expected)
}

fn product_parts(directory: &str) -> Result<Vec<&str>> {
    if directory == "." {
        Ok(vec![])
    } else {
        crate::config::relative(directory)?;
        Ok(directory.split('/').collect())
    }
}

/// Derive configure-input roots without consulting the recorded host filesystem.
/// The plan supplies SDK authority; recorded dependency paths only select roots
/// within the acquisition namespace derived from the same build invocation.
pub fn roots(
    plan: &Plan,
    bi: usize,
    reported_source: &Path,
    reported_build: &Path,
    inputs: &BTreeMap<String, String>,
) -> Result<Vec<PathBuf>> {
    let build = plan
        .builds
        .get(bi)
        .context("unknown CMake boundary build")?;
    ensure!(
        matches!(build.recipe, Recipe::Cmake { .. }),
        "CMake boundary requires a CMake build"
    );
    let product = plan
        .config
        .products
        .get(build.product)
        .context("unknown CMake boundary product")?;
    let tools = match &build.profile.environment {
        Environment::LinuxContainer { tools, .. } | Environment::NativeSdk { tools, .. } => tools,
    };
    let expected = input_names(tools, &product.inputs)?;
    ensure!(
        inputs.keys().eq(expected.keys()),
        "CMake boundary dependency input names differ from the plan"
    );
    let directory = product_parts(&product.directory)?;
    match &build.profile.environment {
        Environment::LinuxContainer { .. } => {
            ensure!(
                build.profile.os == "linux",
                "container CMake boundary requires Linux"
            );
            let source = AbsolutePath::parse("/source", false)?;
            ensure!(
                AbsolutePath::from_path(reported_source, false)?.same(&source.join(&directory))
                    && AbsolutePath::from_path(reported_build, false)?
                        .same(&AbsolutePath::parse("/work/build", false)?),
                "container CMake source or build path differs from the planned mount layout"
            );
            let mut allowed = ["/source", "/work", "/usr", "/opt", "/lib", "/lib64"]
                .into_iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>();
            for (name, path) in inputs {
                ensure!(
                    path == &format!("/inputs/{name}"),
                    "container CMake dependency input path differs from its planned mount"
                );
                allowed.push(PathBuf::from(path));
            }
            Ok(allowed)
        }
        Environment::NativeSdk { sdk, os, .. } => {
            ensure!(
                os == &build.profile.os && matches!(os.as_str(), "macos" | "windows"),
                "native CMake boundary requires a matching supported host OS"
            );
            sdk.validate()?;
            crate::config::identifier(&build.id)?;
            let windows = os == "windows";
            if windows {
                let mut names = std::collections::BTreeSet::new();
                ensure!(
                    expected
                        .keys()
                        .all(|name| names.insert(name.to_ascii_lowercase())),
                    "case-aliased Windows CMake dependency input names"
                );
            }
            let recorded_build = AbsolutePath::from_path(reported_build, windows)?;
            let count = recorded_build.parts.len();
            ensure!(
                count >= 6,
                "native CMake build path omits its owned invocation"
            );
            let tail = &recorded_build.parts[count - 6..];
            ensure!(
                recorded_build.same_text(&tail[0], "invocations")
                    && tail[1].len() == 32
                    && tail[1]
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    && recorded_build.same_text(&tail[2], &format!("build-{bi}"))
                    && recorded_build.same_text(&tail[3], "owned")
                    && recorded_build.same_text(&tail[4], "work")
                    && recorded_build.same_text(&tail[5], "build"),
                "native CMake build path differs from its owned invocation layout"
            );
            let output = recorded_build.truncate(count - 6);
            let unit = recorded_build.truncate(count - 3);
            let checkout = unit.join(["source"]);
            ensure!(
                AbsolutePath::from_path(reported_source, windows)?.same(&checkout.join(&directory)),
                "native CMake source path belongs to another checkout or build unit"
            );
            let mut allowed = vec![checkout.path_buf(), unit.join(["owned", "work"]).path_buf()];
            for path in sdk.roots.keys().chain(sdk.tool_sha256.keys()) {
                AbsolutePath::parse(path, windows)?;
                allowed.push(PathBuf::from(path));
            }
            for (name, path) in inputs {
                let actual = AbsolutePath::parse(path, windows)?;
                let tree = output.join(["inputs", &build.id, name, "tree"]);
                ensure!(
                    actual.beneath(&tree),
                    "native CMake dependency input escapes its planned acquisition namespace"
                );
                let root = &actual.parts[tree.parts.len()..];
                ensure!(
                    root.len() <= 1 && (!expected[name] || root.is_empty()),
                    "native CMake dependency input root differs from the acquisition layout"
                );
                if let Some(component) = root.first() {
                    crate::config::relative(component)?;
                    ensure!(component.len() <= 4096, "CMake archive root exceeds bound");
                }
                allowed.push(PathBuf::from(path));
            }
            Ok(allowed)
        }
    }
}
