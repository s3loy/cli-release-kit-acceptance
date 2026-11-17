use super::{config, model::*};
use crate::{
    catalog,
    delivery::{
        model::{
            BackendConstraint, Format, InstallMapping, NFPM_VERSION, PackageMetadata, PackageSpec,
            PackagingDefaults, Product,
        },
        native,
    },
    model::{IMPLEMENTATION, SourceIdentity},
    source,
    v2::{
        self,
        model::{Action, BinaryOutput, Builder, CommandSpec, Recipe, Resolution, Task},
    },
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

pub const ENGINE_SOURCE_ID: &str = env!("KIT_ENGINE_SOURCE_ID");
fn domain_id<T: serde::Serialize>(domain: &[u8], value: &T) -> Result<String> {
    let mut bytes = domain.to_vec();
    bytes.extend(serde_json::to_vec(value)?);
    Ok(source::digest(&bytes))
}
pub fn id(plan: &Plan) -> Result<String> {
    let mut semantic = plan.clone();
    semantic.id.clear();
    domain_id(b"cli-release-kit/plan/v5\0", &semantic)
}
fn commit_epoch(root: &Path, commit: &str) -> Result<u64> {
    source::git(root, &["show", "-s", "--format=%ct", commit])?
        .trim()
        .parse()
        .context("source commit timestamp must be an unsigned Unix epoch")
}
pub fn create(root: &Path) -> Result<Plan> {
    let config = config::load(root)?;
    config::validate_build_environment(&config)?;
    let identity = source::snapshot_plain(root)?;
    config::validate_source(root, &config, &identity)?;
    let resolved = config
        .products
        .iter()
        .map(|p| v2::builder::resolve(root, &p.base(), &identity.files))
        .collect::<Result<Vec<_>>>()?;
    let epoch = commit_epoch(root, &identity.commit)?;
    ensure!(
        source::snapshot_plain(root)? == identity,
        "source changed during planning"
    );
    assemble(config, identity, resolved, epoch)
}
fn command(argv: Vec<String>, env: BTreeMap<String, String>) -> CommandSpec {
    CommandSpec {
        argv,
        env,
        cwd: ".".into(),
    }
}
fn context(
    p: &Product,
    r: &Resolution,
    t: &catalog::TargetDescriptor,
    u: usize,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("KIT_PROJECT_DIR".into(), "{project}".into()),
        (
            "KIT_PRODUCT_DIR".into(),
            if p.directory == "." {
                "{project}".into()
            } else {
                format!("{{project}}/{}", p.directory)
            },
        ),
        ("KIT_PRODUCT".into(), p.id.clone()),
        ("KIT_VERSION".into(), r.version.clone()),
        ("KIT_TARGET".into(), t.id.clone()),
        (
            "KIT_GENERATED_DIR".into(),
            format!("{{attempt}}/work/generated-{u}"),
        ),
        (
            "KIT_ARCHIVE_DIR".into(),
            format!("{{attempt}}/work/run-{u}"),
        ),
        (
            "KIT_BINARY".into(),
            format!("{{attempt}}/work/run-{u}/{}", t.binary_name(&p.binaries[0])),
        ),
    ])
}
pub fn recipe(
    p: &Product,
    r: &Resolution,
    t: &catalog::TargetDescriptor,
    build_dir: &str,
) -> Result<Recipe> {
    ensure!(
        *t == catalog::for_builder(&catalog::resolve(&t.id)?, &p.build)?,
        "build target descriptor differs from catalog"
    );
    match &p.build {
        Builder::Rust {
            package,
            manifest,
            features,
            default_features,
        } => {
            let mut argv = vec![
                "cargo".into(),
                "build".into(),
                "--locked".into(),
                "--release".into(),
                "--manifest-path".into(),
                manifest.clone(),
                "--package".into(),
                package.clone(),
                "--target".into(),
                t.compiler_target.clone(),
                "--target-dir".into(),
                build_dir.into(),
            ];
            for bin in &p.binaries {
                argv.extend(["--bin".into(), bin.clone()]);
            }
            if !default_features {
                argv.push("--no-default-features".into());
            }
            if !features.is_empty() {
                argv.extend(["--features".into(), features.join(",")]);
            }
            Ok(Recipe {
                commands: vec![CommandSpec {
                    argv,
                    cwd: p.directory.clone(),
                    env: t.compile_env.clone(),
                }],
                binaries: p
                    .binaries
                    .iter()
                    .map(|bin| {
                        let path = t.binary_name(bin);
                        BinaryOutput {
                            source: format!("{build_dir}/{}/release/{path}", t.compiler_target),
                            path,
                        }
                    })
                    .collect(),
                compiler_target: t.compiler_target.clone(),
            })
        }
        Builder::Go {
            packages, ldflags, ..
        } => {
            ensure!(
                packages.len() == p.binaries.len(),
                "Go packages must correspond positionally to binaries"
            );
            let mut commands = Vec::new();
            let mut binaries = Vec::new();
            for (bin, package) in p.binaries.iter().zip(packages) {
                let path = t.binary_name(bin);
                let output = format!("{build_dir}/{path}");
                let mut argv = vec![
                    "go".into(),
                    "build".into(),
                    "-mod=readonly".into(),
                    "-trimpath".into(),
                    "-o".into(),
                    output.clone(),
                ];
                if !ldflags.is_empty() {
                    argv.extend([
                        "-ldflags".into(),
                        ldflags
                            .iter()
                            .map(|f| f.replace("{version}", &r.version))
                            .collect::<Vec<_>>()
                            .join(" "),
                    ]);
                }
                argv.push(package.clone());
                commands.push(CommandSpec {
                    argv,
                    cwd: p.directory.clone(),
                    env: t.compile_env.clone(),
                });
                binaries.push(BinaryOutput {
                    source: output,
                    path,
                });
            }
            Ok(Recipe {
                commands,
                binaries,
                compiler_target: t.compiler_target.clone(),
            })
        }
    }
}
fn package_install(
    p: &Product,
    t: &catalog::TargetDescriptor,
    format: Format,
    name: &str,
) -> Result<Vec<InstallMapping>> {
    let files = p
        .binaries
        .iter()
        .map(|b| (t.binary_name(b), true))
        .chain(p.assets.iter().map(|a| (a.path.clone(), false)));
    let overrides = p
        .packaging
        .native
        .as_ref()
        .map(|n| n.install.as_slice())
        .unwrap_or_default();
    let mut result = Vec::new();
    for (source, binary) in files {
        let destination = if format.is_native() {
            overrides
                .iter()
                .find(|m| m.source == source)
                .map(|m| m.destination.trim_start_matches('/').to_owned())
                .unwrap_or_else(|| {
                    if binary {
                        format!("usr/bin/{source}")
                    } else {
                        format!("usr/share/{name}/{source}")
                    }
                })
        } else {
            source.clone()
        };
        crate::config::relative(&destination)?;
        result.push(InstallMapping {
            source,
            destination,
        });
    }
    result.sort_by(|a, b| a.source.cmp(&b.source));
    let paths: Vec<_> = result
        .iter()
        .map(|m| m.destination.to_ascii_lowercase())
        .collect();
    ensure!(
        paths.iter().collect::<BTreeSet<_>>().len() == paths.len(),
        "package install destinations collide"
    );
    for path in &paths {
        ensure!(
            !paths
                .iter()
                .any(|other| path.starts_with(&format!("{other}/"))),
            "package install file/directory conflict"
        );
    }
    Ok(result)
}
pub fn assemble(
    config: Config,
    identity: SourceIdentity,
    resolved: Vec<Resolution>,
    source_epoch: u64,
) -> Result<Plan> {
    assemble_with_engine_identity(config, identity, resolved, source_epoch, ENGINE_SOURCE_ID)
}

pub fn assemble_with_engine_identity(
    config: Config,
    identity: SourceIdentity,
    resolved: Vec<Resolution>,
    source_epoch: u64,
    engine_source_id: &str,
) -> Result<Plan> {
    ensure!(
        config::is_digest(engine_source_id),
        "invalid engine source identity"
    );
    config::validate(&config)?;
    ensure!(
        resolved.len() == config.products.len(),
        "resolved product set differs from configuration"
    );
    let targets = config
        .targets
        .iter()
        .map(|t| catalog::resolve(&t.id))
        .collect::<Result<Vec<_>>>()?;
    let products: Vec<_> = config.products.iter().map(Product::base).collect();
    let mut tasks = Vec::new();
    let mut probes = Vec::new();
    let mut terminal = Vec::new();
    for (i, (key, command)) in v2::builder::probes(&products).into_iter().enumerate() {
        let task_id = format!("probe-{i}");
        tasks.push(Task {
            id: task_id.clone(),
            depends_on: vec![],
            runtime: false,
            action: Action::Probe { key, command },
        });
        probes.push(task_id);
    }
    let mut builds = Vec::new();
    let mut packages = Vec::new();
    let mut package_profiles = Vec::new();
    let mut filenames = BTreeSet::new();
    for (pi, p) in config.products.iter().enumerate() {
        for (ti, selection) in config
            .targets
            .iter()
            .enumerate()
            .filter(|(_, t)| p.targets.is_empty() || p.targets.contains(&t.id))
        {
            let u = builds.len();
            let r = &resolved[pi];
            let t = catalog::for_builder(&targets[ti], &p.build)?;
            let recipe = recipe(p, r, &t, &format!("{{attempt}}/work/build-{u}"))?;
            let build_id = domain_id(
                b"cli-release-kit/build/v5\0",
                &(
                    engine_source_id,
                    &identity,
                    p,
                    &t,
                    &selection.runtime,
                    r,
                    &recipe,
                ),
            )?;
            let env = context(p, r, &t, u);
            let mut last = probes.clone();
            for (i, hook) in p.prepare.iter().enumerate() {
                let task_id = format!("u{u}-prepare-{i}");
                let mut extra = hook.env.clone();
                extra.extend(env.clone());
                tasks.push(Task {
                    id: task_id.clone(),
                    depends_on: last,
                    runtime: false,
                    action: Action::Prepare {
                        unit: u,
                        command: command(hook.command.clone(), extra),
                    },
                });
                last = vec![task_id];
            }
            ensure!(!recipe.commands.is_empty(), "build recipe has no commands");
            for (i, command) in recipe.commands.iter().enumerate() {
                let task_id = format!("u{u}-build-{i}");
                tasks.push(Task {
                    id: task_id.clone(),
                    depends_on: last,
                    runtime: false,
                    action: Action::Build {
                        unit: u,
                        command: command.clone(),
                    },
                });
                last = vec![task_id];
            }
            let task_id = format!("u{u}-archive");
            tasks.push(Task {
                id: task_id.clone(),
                depends_on: last,
                runtime: false,
                action: Action::Archive { unit: u },
            });
            last = vec![task_id];
            for (i, binary) in crate::config::effective_version_binaries(
                &p.binaries,
                p.version_binaries.as_deref(),
            )
            .iter()
            .enumerate()
            {
                let task_id = format!("u{u}-version-{i}");
                let mut argv = vec![format!(
                    "{{attempt}}/work/run-{u}/{}",
                    t.binary_name(binary)
                )];
                argv.extend(p.version_args.clone());
                tasks.push(Task {
                    id: task_id.clone(),
                    depends_on: last,
                    runtime: true,
                    action: Action::Version {
                        unit: u,
                        binary: binary.clone(),
                        command: command(argv, env.clone()),
                    },
                });
                last = vec![task_id];
            }
            for (i, hook) in p.checks.iter().enumerate() {
                if selection.runtime.mode == RuntimeMode::Emulated {
                    let executable = hook.command.first().context("check command is empty")?;
                    ensure!(
                        executable == "{binary}"
                            || p.binaries.iter().any(|b| executable
                                == &format!("{{attempt}}/work/run-{u}/{}", t.binary_name(b))),
                        "emulated check must invoke this build's planned binary directly"
                    );
                }
                let task_id = format!("u{u}-check-{i}");
                let mut extra = hook.env.clone();
                extra.extend(env.clone());
                tasks.push(Task {
                    id: task_id.clone(),
                    depends_on: last,
                    runtime: true,
                    action: Action::Check {
                        unit: u,
                        command: command(hook.command.clone(), extra),
                    },
                });
                last = vec![task_id];
            }
            terminal.extend(last);
            builds.push(BuildSpec {
                id: build_id,
                product: pi,
                target: ti,
                recipe,
                descriptor: t.clone(),
            });
            for format in config::effective_formats(&config, pi, &t.os) {
                if format.is_native() {
                    ensure!(
                        r.version.len() <= 128,
                        "native package version exceeds 128 bytes"
                    );
                    semver::Version::parse(r.version.strip_prefix('v').unwrap_or(&r.version))
                        .context("native package version must be SemVer")?;
                }
                let profile = catalog::package_support(&t, format)?;
                let native = if format.is_native() {
                    p.packaging.native.as_ref()
                } else {
                    None
                };
                let name = native
                    .and_then(|n| n.name.as_deref())
                    .unwrap_or(&p.id)
                    .to_owned();
                let metadata = PackageMetadata {
                    name: name.clone(),
                    version: r.version.clone(),
                    release: 1,
                    arch: profile.package_arch.clone(),
                    description: native.map(|n| n.description.clone()),
                    license: native.map(|n| n.license.clone()),
                    maintainer: native.map(|n| n.maintainer.clone()),
                    homepage: native.and_then(|n| n.homepage.clone()),
                    dependencies: native
                        .and_then(|n| n.dependencies.get(&format))
                        .cloned()
                        .unwrap_or_default(),
                };
                let filename = format!(
                    "{}-{}-{}.{}",
                    p.id,
                    crate::delivery::plan::filename_version(&r.version),
                    t.id,
                    format.extension()
                );
                crate::config::relative(&filename)?;
                ensure!(
                    filename.len() <= 240
                        && filename
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                    "planned package filename is not publication-safe"
                );
                ensure!(
                    filenames.insert(filename.to_ascii_lowercase()),
                    "planned package filenames collide"
                );
                let mut spec = PackageSpec {
                    id: String::new(),
                    build: u,
                    format,
                    filename,
                    metadata,
                    native_version: if format.is_native() {
                        Some(native::version_for(format, &r.version, 1)?)
                    } else {
                        None
                    },
                    install: package_install(p, &t, format, &name)?,
                    source_epoch,
                    backend: format.is_native().then(|| BackendConstraint {
                        name: "nfpm".into(),
                        version: NFPM_VERSION.into(),
                    }),
                };
                spec.id = domain_id(
                    b"cli-release-kit/package/v5\0",
                    &(&builds[u].id, &spec, &profile),
                )?;
                packages.push(spec);
                package_profiles.push(profile);
            }
        }
    }
    ensure!(!builds.is_empty() && !packages.is_empty(), "plan is empty");
    tasks.push(Task {
        id: "seal".into(),
        depends_on: terminal,
        runtime: false,
        action: Action::Seal,
    });
    let mut plan = Plan {
        schema: SCHEMA,
        id: String::new(),
        implementation: IMPLEMENTATION.into(),
        engine_source_id: engine_source_id.into(),
        source: identity,
        config,
        resolved,
        targets,
        builds,
        packages,
        package_profiles,
        tasks,
        source_epoch,
    };
    plan.id = id(&plan)?;
    Ok(plan)
}
pub fn shape(plan: &Plan) -> Result<()> {
    ensure!(
        plan.schema == SCHEMA
            && plan
                .implementation
                .strip_prefix("cli-release-kit-engine/")
                .is_some_and(|version| semver::Version::parse(version).is_ok())
            && config::is_digest(&plan.engine_source_id),
        "unsupported protocol-5 plan or engine source identity"
    );
    ensure!(plan.id == id(plan)?, "protocol-5 plan identity mismatch");
    let expected = assemble_with_engine_identity(
        plan.config.clone(),
        plan.source.clone(),
        plan.resolved.clone(),
        plan.source_epoch,
        &plan.engine_source_id,
    )?;
    ensure!(
        plan.targets == expected.targets
            && plan.builds == expected.builds
            && plan.packages == expected.packages
            && plan.package_profiles == expected.package_profiles
            && plan.tasks == expected.tasks,
        "saved descriptors, recipes, packages or task graph differ from canonical protocol-5 contract"
    );
    Ok(())
}
pub fn validate_saved(root: &Path, plan: &Plan) -> Result<()> {
    shape(plan)?;
    ensure!(
        config::load(root)? == plan.config,
        "release.toml changed since planning"
    );
    ensure!(
        source::snapshot_plain(root)? == plan.source,
        "source identity changed since planning"
    );
    ensure!(
        commit_epoch(root, &plan.source.commit)? == plan.source_epoch,
        "source commit timestamp differs from plan"
    );
    config::validate_source(root, &plan.config, &plan.source)?;
    for (p, r) in plan.config.products.iter().zip(&plan.resolved) {
        v2::builder::validate_offline_source(root, &p.base(), r, &plan.source.files, false)?;
    }
    Ok(())
}
pub fn load(path: &Path) -> Result<Plan> {
    v2::plan::read_json(path)
}
pub fn initialize(
    root: &Path,
    directory: &str,
    kind: &str,
    version: Option<&str>,
) -> Result<PathBuf> {
    let path = crate::config::safe_join(root, "release.toml")?;
    ensure!(!path.exists(), "release.toml already exists");
    let products = v2::builder::discover(root, directory, kind, version)?;
    let target =
        v2::builder::native_target_at(&v2::contract::product_root(root, &products[0])?, kind)?;
    let config = Config {
        schema: CONFIG_SCHEMA,
        targets: vec![TargetSelection::native(target.key())],
        products: products.into_iter().map(Product::from_base).collect(),
        packaging: PackagingDefaults::default(),
        timeout_seconds: 1200,
    };
    config::validate(&config)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?
        .write_all(toml::to_string_pretty(&config)?.as_bytes())?;
    Ok(path)
}
