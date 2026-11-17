use super::{config, model::*};
use crate::{
    model::{IMPLEMENTATION, SourceIdentity},
    source, v2,
};
use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
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
    domain_id(b"cli-release-kit/delivery-plan/v1\0", &semantic)
}

pub fn create(root: &Path) -> Result<Plan> {
    let config = config::load(root)?;
    let identity = source::snapshot_plain(root)?;
    let base = config::base_config(&config);
    v2::contract::validate_source(root, &base, &identity)?;
    let resolved = base
        .products
        .iter()
        .map(|p| v2::builder::resolve(root, p, &identity.files))
        .collect::<Result<Vec<_>>>()?;
    let epoch = commit_epoch(root, &identity.commit)?;
    ensure!(
        source::snapshot_plain(root)? == identity,
        "source changed during planning"
    );
    assemble(config, identity, resolved, epoch)
}

fn commit_epoch(root: &Path, commit: &str) -> Result<u64> {
    source::git(root, &["show", "-s", "--format=%ct", commit])?
        .trim()
        .parse()
        .context("source commit timestamp must be an unsigned Unix epoch")
}

pub fn build_view(plan: &Plan) -> Result<v2::model::Plan> {
    let mut base = v2::plan::assemble(
        config::base_config(&plan.config),
        plan.source.clone(),
        plan.resolved.clone(),
    )?;
    base.id = v2::plan::id(&base)?;
    Ok(base)
}

fn native_version(version: &str) -> Result<()> {
    ensure!(
        version.len() <= 128,
        "native package version exceeds 128 bytes"
    );
    semver::Version::parse(version.strip_prefix('v').unwrap_or(version))
        .with_context(|| format!("native package version must be SemVer: {version}"))?;
    Ok(())
}

pub fn filename_version(version: &str) -> String {
    let mut result = String::new();
    for byte in version.bytes() {
        if byte.is_ascii_alphanumeric() || b".-".contains(&byte) {
            result.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(&mut result, "_{byte:02x}").expect("write to String");
        }
    }
    result
}

fn package_arch(format: Format, target: &v2::model::Target) -> String {
    match (format, target.arch.as_str()) {
        (Format::Deb, "x86_64") => "amd64",
        (Format::Deb | Format::Ipk, "aarch64") => "arm64",
        _ => target.arch.as_str(),
    }
    .into()
}

fn package_install(
    p: &Product,
    t: &v2::model::Target,
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
    let paths = result
        .iter()
        .map(|m| m.destination.to_ascii_lowercase())
        .collect::<Vec<_>>();
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
    resolved: Vec<v2::model::Resolution>,
    source_epoch: u64,
) -> Result<Plan> {
    config::validate(&config)?;
    let base = v2::plan::assemble(
        config::base_config(&config),
        identity.clone(),
        resolved.clone(),
    )?;
    let mut builds = Vec::new();
    let mut packages = Vec::new();
    let mut filenames = BTreeSet::new();
    for unit in &base.units {
        let product = &config.products[unit.product];
        let target = &config.targets[unit.target];
        let resolution = &resolved[unit.product];
        let build_id = domain_id(
            b"cli-release-kit/delivery-build/v1\0",
            &(
                &identity,
                &base.config.products[unit.product],
                target,
                resolution,
                &unit.recipe,
            ),
        )?;
        let build = builds.len();
        builds.push(BuildSpec {
            id: build_id,
            product: unit.product,
            target: unit.target,
            recipe: unit.recipe.clone(),
        });
        for format in config::effective_formats(&config, unit.product, &target.os) {
            if format.is_native() {
                native_version(&resolution.version)?;
            }
            let native = if format.is_native() {
                product.packaging.native.as_ref()
            } else {
                None
            };
            let name = native
                .and_then(|n| n.name.as_deref())
                .unwrap_or(&product.id)
                .to_owned();
            let metadata = PackageMetadata {
                name: name.clone(),
                version: resolution.version.clone(),
                release: 1,
                arch: package_arch(format, target),
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
                product.id,
                filename_version(&resolution.version),
                target.key(),
                format.extension()
            );
            crate::config::relative(&filename)?;
            ensure!(
                filename.len() <= 240,
                "planned package filename exceeds 240 bytes"
            );
            ensure!(
                filename
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "planned package filename is not publication-safe"
            );
            ensure!(
                filenames.insert(filename.to_ascii_lowercase()),
                "planned package filenames collide"
            );
            let install = package_install(product, target, format, &name)?;
            let backend = format.is_native().then(|| BackendConstraint {
                name: "nfpm".into(),
                version: NFPM_VERSION.into(),
            });
            let mut spec = PackageSpec {
                id: String::new(),
                build,
                format,
                filename,
                metadata,
                native_version: if format.is_native() {
                    Some(super::native::version_for(format, &resolution.version, 1)?)
                } else {
                    None
                },
                install,
                source_epoch,
                backend,
            };
            spec.id = domain_id(
                b"cli-release-kit/delivery-package/v1\0",
                &(&builds[build].id, &spec),
            )?;
            packages.push(spec);
        }
    }
    let mut plan = Plan {
        schema: SCHEMA,
        id: String::new(),
        implementation: IMPLEMENTATION.into(),
        engine_source_id: ENGINE_SOURCE_ID.into(),
        source: identity,
        config,
        resolved,
        source_epoch,
        builds,
        packages,
    };
    plan.id = id(&plan)?;
    Ok(plan)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn shape(plan: &Plan) -> Result<()> {
    ensure!(
        plan.schema == SCHEMA
            && plan.implementation == IMPLEMENTATION
            && is_digest(&plan.engine_source_id),
        "unsupported delivery plan protocol or engine source identity"
    );
    ensure!(plan.id == id(plan)?, "delivery plan identity mismatch");
    let expected = assemble(
        plan.config.clone(),
        plan.source.clone(),
        plan.resolved.clone(),
        plan.source_epoch,
    )?;
    ensure!(
        plan.builds == expected.builds && plan.packages == expected.packages,
        "saved build or package recipes differ from canonical contract"
    );
    ensure!(
        !plan.builds.is_empty() && !plan.packages.is_empty(),
        "delivery plan is empty"
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
    let base = config::base_config(&plan.config);
    v2::contract::validate_source(root, &base, &plan.source)?;
    for (product, resolution) in base.products.iter().zip(&plan.resolved) {
        v2::builder::validate_offline_source(root, product, resolution, &plan.source.files, false)?;
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
        targets: vec![target],
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
