use super::{config, model::*};
use crate::{
    catalog,
    compatibility::{Architecture, Environment, Profile},
    delivery::{
        model::{
            BackendConstraint, Format, InstallMapping, NFPM_VERSION, PackageMetadata, PackageSpec,
        },
        native,
    },
    model::{IMPLEMENTATION, SourceIdentity},
    source, v2,
};
use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

pub fn content_id<T: serde::Serialize>(domain: &[u8], value: &T) -> Result<String> {
    let mut bytes = domain.to_vec();
    bytes.extend(serde_json::to_vec(value)?);
    Ok(source::digest(&bytes))
}
pub fn id(p: &Plan) -> Result<String> {
    let mut p = p.clone();
    p.id.clear();
    content_id(b"relship/qualified-plan/v1\0", &p)
}
pub fn load(path: &Path) -> Result<Plan> {
    crate::cohort::io::read_json(path)
}
pub fn descriptor(id: &str, b: &Builder) -> Result<catalog::TargetDescriptor> {
    let t = catalog::resolve(id)?;
    match b {
        Builder::Existing(legacy) => catalog::for_builder(&t, legacy),
        Builder::Cmake(_) => {
            ensure!(
                matches!(t.arch.as_str(), "x86_64" | "aarch64")
                    && ((t.os == "linux" && t.libc == "glibc")
                        || t.os == "macos"
                        || (t.os == "windows" && t.c_abi == "msvc")),
                "CMake requires a native GNU, Darwin or MSVC target"
            );
            let mut t = t;
            t.builder = "cmake".into();
            t.compile_env.clear();
            Ok(t)
        }
    }
}
pub fn host_key(build: &Build) -> String {
    format!("{}-{}", build.profile.os, build.profile.arch.name())
}
pub fn create(root: &Path) -> Result<Plan> {
    let c = config::load(root)?;
    let identity = source::snapshot_plain(root)?;
    config::validate_source(root, &c, &identity)?;
    let ci_config = if identity.files.contains_key("release-ci.toml") {
        Some(fs::read_to_string(crate::config::safe_join(
            root,
            "release-ci.toml",
        )?)?)
    } else {
        None
    };
    let resolved = c
        .products
        .iter()
        .map(|p| match &p.build {
            Builder::Existing(_) => v2::builder::resolve(root, &p.legacy(), &identity.files),
            Builder::Cmake(s) => Ok(v2::model::Resolution {
                version: s.version.clone(),
                manifest: if p.directory == "." {
                    "CMakeLists.txt".into()
                } else {
                    format!("{}/CMakeLists.txt", p.directory)
                },
                workspace_manifest: None,
            }),
        })
        .collect::<Result<Vec<_>>>()?;
    let epoch = source::git(root, &["show", "-s", "--format=%ct", &identity.commit])?
        .trim()
        .parse()?;
    ensure!(
        source::snapshot_plain(root)? == identity,
        "source changed during planning"
    );
    assemble(c, identity, resolved, epoch, ci_config)
}
pub fn assemble(
    c: Config,
    identity: SourceIdentity,
    resolved: Vec<v2::model::Resolution>,
    epoch: u64,
    ci_config: Option<String>,
) -> Result<Plan> {
    assemble_with_engine(
        c,
        identity,
        resolved,
        epoch,
        ci_config,
        crate::cohort::model::ENGINE_SOURCE_ID,
    )
}
fn assemble_with_engine(
    c: Config,
    identity: SourceIdentity,
    resolved: Vec<v2::model::Resolution>,
    epoch: u64,
    ci_config: Option<String>,
    engine: &str,
) -> Result<Plan> {
    ensure!(
        crate::v5::config::is_digest(engine),
        "invalid engine identity"
    );
    config::validate(&c)?;
    ensure!(
        resolved.len() == c.products.len(),
        "resolved product count differs"
    );
    ensure!(
        identity.commit.len() == 40 && identity.tree.len() == 40,
        "invalid source identity"
    );
    let ci = ci_config
        .as_deref()
        .map(toml::from_str::<crate::ci::model::Config>)
        .transpose()?;
    if let Some(text) = &ci_config {
        ensure!(
            identity.files.get("release-ci.toml") == Some(&source::digest(text.as_bytes())),
            "CI context is not bound to source files"
        );
    }
    if let Some(ci) = &ci {
        crate::ci::config::validate(ci)?;
        ensure!(
            ci.execution_protocol == SCHEMA,
            "qualified plan requires matching CI execution protocol"
        );
    }
    let mut builds = vec![];
    let mut packages = vec![];
    let mut validations = vec![];
    let mut runtimes = BTreeMap::new();
    let mut filenames = BTreeSet::new();
    for (pi, p) in c.products.iter().enumerate() {
        let r = &resolved[pi];
        ensure!(!r.version.is_empty(), "missing application version");
        for target in c
            .targets
            .iter()
            .filter(|t| p.targets.is_empty() || p.targets.contains(t))
        {
            let t = descriptor(target, &p.build)?;
            let arch = Architecture::parse(&t.arch)?;
            let mut profile = if let Some(custom) = ci.as_ref().and_then(|ci| {
                ci.environments
                    .get(target)
                    .or_else(|| ci.environments.get(&format!("{}-{}", t.os, t.arch)))
            }) {
                custom.clone()
            } else if t.os == "linux" {
                Profile::linux_glibc217(arch)?
            } else {
                anyhow::bail!(
                    "{}@{} requires a reviewed native SDK environment in release-ci.toml.environments; runner labels do not pin an SDK",
                    p.id,
                    target
                )
            };
            if t.os == "linux" && p.build.name() == "go" {
                profile.id = format!("linux-{}-pure-go", arch.name());
                profile.minimum_libc = None;
            } else if t.os == "linux" {
                ensure!(
                    profile.minimum_libc.as_deref() == Some("2.17"),
                    "GNU products require the glibc 2.17 profile"
                );
            }
            if t.os == "windows" {
                let runtime = profile.windows_runtime.get_or_insert_with(Default::default);
                runtime.mode = c.compatibility.windows.crt;
            }
            profile.validate()?;
            ensure!(
                profile.os == t.os && profile.arch == arch,
                "environment differs from target"
            );
            if let Environment::LinuxContainer { tools, .. } = &mut profile.environment {
                for tool in crate::compatibility::language_tools(p.build.name(), arch)? {
                    if !tools.contains(&tool) {
                        tools.push(tool);
                    }
                }
            }
            if let Some(ci) = &ci {
                let host = format!("{}-{}", t.os, t.arch);
                let runner = ci
                    .workers
                    .values()
                    .find(|w| w.runner.host == host)
                    .map(|w| &w.runner);
                if let Some(runner) = runner {
                    let request = if p.build.name() == "rust" {
                        runner.rust_version.as_deref().map(|v| (v, "1.96.0"))
                    } else if p.build.name() == "go" {
                        runner.go_version.as_deref().map(|v| (v, "1.27.4"))
                    } else {
                        None
                    };
                    if let Some((requested, pinned)) = request {
                        ensure!(
                            requested == pinned,
                            "requested compiler {requested} is unavailable in the qualified profile ({pinned}); no substitution is allowed"
                        );
                    }
                }
            }
            if let Environment::LinuxContainer { image, tools } = &mut profile.environment {
                if p.build.name() != "go" {
                    tools.push(crate::compatibility::ToolInput::ImageContained {
                        name: "sdk-python".into(),
                        path: "/opt/python/cp311-cp311/bin/python3".into(),
                        manifest_digest: image.manifest_digest.clone(),
                    });
                    for input in crate::compatibility::perl::inputs(arch)? {
                        if !tools.contains(&input) {
                            tools.push(input);
                        }
                    }
                } else {
                    tools.retain(|input|matches!(input,crate::compatibility::ToolInput::Archive{name,..} if name=="go"));
                }
            }
            let recipe = match &p.build {
                Builder::Cmake(s) => {
                    let spec = s.clone();
                    if t.os == "windows" {
                        use crate::compatibility::windows_crt::WindowsRuntimeMode as Mode;
                        if let Some(explicit) =
                            spec.cache_variables.get("CMAKE_MSVC_RUNTIME_LIBRARY")
                        {
                            let expected = match c.compatibility.windows.crt {
                                Mode::FollowProject => None,
                                Mode::Static => Some("MultiThreaded"),
                                Mode::Dynamic => Some("MultiThreadedDLL"),
                            };
                            if let Some(expected) = expected {
                                ensure!(
                                    explicit == expected,
                                    "explicit CMake CRT differs from selected policy"
                                );
                            }
                        }
                    }
                    Recipe::Cmake { spec }
                }
                Builder::Existing(_) => {
                    let mut product = crate::delivery::model::Product::from_base(p.legacy());
                    product.packaging = p.packaging.clone();
                    let mut recipe = crate::v5::plan::recipe(&product, r, &t, "{work}/build")?;
                    match &profile.environment {
                        Environment::NativeSdk { sdk, .. } => {
                            let selected = super::toolchain::native_selection(
                                sdk,
                                p.build.name(),
                                &t.compiler_target,
                            )?;
                            for command in &mut recipe.commands {
                                command.argv[0] = selected.program.clone();
                                command.env.extend(selected.environment.clone());
                            }
                        }
                        Environment::LinuxContainer { .. } => {
                            for command in &mut recipe.commands {
                                command.argv[0] = if p.build.name() == "rust" {
                                    "/work/sdk/bin/cargo"
                                } else {
                                    "/inputs/go/bin/go"
                                }
                                .into();
                            }
                        }
                    }
                    if t.os == "windows" && p.build.name() == "rust" {
                        use crate::compatibility::windows_crt::WindowsRuntimeMode as Mode;
                        let feature = match c.compatibility.windows.crt {
                            Mode::FollowProject => None,
                            Mode::Static => Some("+crt-static"),
                            Mode::Dynamic => Some("-crt-static"),
                        };
                        if let Some(feature) = feature {
                            for command in &mut recipe.commands {
                                let encoded = command
                                    .env
                                    .entry("CARGO_ENCODED_RUSTFLAGS".into())
                                    .or_default();
                                if !encoded.is_empty() {
                                    encoded.push('\u{1f}');
                                }
                                encoded.push_str(&format!("-C\u{1f}target-feature={feature}"));
                            }
                        }
                    }
                    Recipe::Fixed { recipe }
                }
            };
            let build_id = content_id(
                b"relship/qualified-build/v1\0",
                &(engine, &identity, p, &t, r, &profile, &recipe),
            )?;
            let bi = builds.len();
            builds.push(Build {
                id: build_id.clone(),
                product: pi,
                target: target.clone(),
                profile: profile.clone(),
                recipe,
            });
            let runtime = if t.os == "linux" {
                let list = crate::compatibility::builtin_runtime_profiles(arch)?;
                for x in &list {
                    runtimes.insert(x.id.clone(), x.clone());
                }
                list.iter().map(|x| x.id.clone()).collect::<Vec<_>>()
            } else {
                vec![profile.id.clone()]
            };
            for format in config::formats(&c, pi, &t.os) {
                ensure!(
                    !format.is_native() || t.os == "linux",
                    "native package format requires Linux"
                );
                let pkg_profile = catalog::package_support(&catalog::resolve(target)?, format)?;
                let n = p.packaging.native.as_ref();
                if format.is_native() {
                    ensure!(
                        n.is_some(),
                        "native package needs description/license/maintainer metadata"
                    );
                    native::validate_version(format, &r.version)?;
                }
                let name = n
                    .and_then(|n| n.name.clone())
                    .unwrap_or_else(|| p.id.clone());
                crate::config::identifier(&name)?;
                let metadata = PackageMetadata {
                    name: name.clone(),
                    version: r.version.clone(),
                    release: 1,
                    arch: pkg_profile.package_arch,
                    description: n.map(|n| n.description.clone()),
                    license: n.map(|n| n.license.clone()),
                    maintainer: n.map(|n| n.maintainer.clone()),
                    homepage: n.and_then(|n| n.homepage.clone()),
                    dependencies: n
                        .and_then(|n| n.dependencies.get(&format))
                        .cloned()
                        .unwrap_or_default(),
                };
                let filename = format!(
                    "{}-{}-{}.{}",
                    p.id,
                    crate::delivery::plan::filename_version(&r.version),
                    target,
                    format.extension()
                );
                crate::config::relative(&filename)?;
                ensure!(
                    filename.len() <= 240 && filenames.insert(filename.to_ascii_lowercase()),
                    "unsafe or duplicate package filename"
                );
                let mut install = vec![];
                for (src, binary) in p
                    .binaries
                    .iter()
                    .map(|b| (t.binary_name(b), true))
                    .chain(p.assets.iter().map(|a| (a.path.clone(), false)))
                {
                    let destination = if format.is_native() {
                        n.and_then(|n| n.install.iter().find(|m| m.source == src))
                            .map(|m| m.destination.trim_start_matches('/').to_owned())
                            .unwrap_or_else(|| {
                                if binary {
                                    format!("usr/bin/{src}")
                                } else {
                                    format!("usr/share/{name}/{src}")
                                }
                            })
                    } else {
                        src.clone()
                    };
                    crate::config::relative(&destination)?;
                    install.push(InstallMapping {
                        source: src,
                        destination,
                    });
                }
                let mut pkg = PackageSpec {
                    id: String::new(),
                    build: bi,
                    format,
                    filename,
                    metadata,
                    native_version: if format.is_native() {
                        Some(native::version_for(format, &r.version, 1)?)
                    } else {
                        None
                    },
                    install,
                    source_epoch: epoch,
                    backend: format.is_native().then(|| BackendConstraint {
                        name: "nfpm".into(),
                        version: NFPM_VERSION.into(),
                    }),
                };
                pkg.id = content_id(b"relship/qualified-package/v1\0", &(&build_id, &pkg))?;
                let index = packages.len();
                for env in &runtime {
                    // Distribution installation checks have their own applicability.
                    let kind = match format {
                        Format::Deb => {
                            if !env.ends_with("2.31") && !env.ends_with("2.39") {
                                continue;
                            }
                            "install-deb"
                        }
                        Format::Rpm => {
                            if !env.ends_with("2.17") {
                                continue;
                            }
                            "install-rpm"
                        }
                        _ => "runtime",
                    };
                    let id = content_id(
                        b"relship/qualified-validation/v1\0",
                        &(&pkg.id, env, kind, &p.checks, &p.version_args),
                    )?;
                    validations.push(Validation {
                        id,
                        package: index,
                        environment: env.clone(),
                        kind: kind.into(),
                    });
                }
                packages.push(pkg);
            }
        }
    }
    ensure!(!builds.is_empty(), "qualified plan has no build units");
    let mut p = Plan {
        schema: SCHEMA,
        id: String::new(),
        implementation: IMPLEMENTATION.into(),
        engine_source_id: engine.into(),
        source: identity,
        source_epoch: epoch,
        config: c,
        ci_config,
        resolved,
        builds,
        packages,
        validations,
        runtimes,
    };
    p.id = id(&p)?;
    Ok(p)
}
pub fn shape(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == SCHEMA && p.implementation == IMPLEMENTATION && p.id == id(p)?,
        "qualified plan identity mismatch"
    );
    let expected = assemble_with_engine(
        p.config.clone(),
        p.source.clone(),
        p.resolved.clone(),
        p.source_epoch,
        p.ci_config.clone(),
        &p.engine_source_id,
    )?;
    ensure!(
        p.builds == expected.builds
            && p.packages == expected.packages
            && p.validations == expected.validations
            && p.runtimes == expected.runtimes,
        "saved environment, recipe or validation graph differs from canonical inputs"
    );
    Ok(())
}
pub fn validate_offline(p: &Plan) -> Result<()> {
    shape(p)
}
pub fn validate_saved(root: &Path, p: &Plan) -> Result<()> {
    shape(p)?;
    ensure!(
        p.engine_source_id == crate::cohort::model::ENGINE_SOURCE_ID,
        "execution requires the planned engine source"
    );
    ensure!(
        config::load(root)? == p.config && source::snapshot_plain(root)? == p.source,
        "source/configuration changed since planning"
    );
    config::validate_source(root, &p.config, &p.source)
}
