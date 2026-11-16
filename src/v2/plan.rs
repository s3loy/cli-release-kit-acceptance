use super::{builder, contract, model::*};
use crate::{config, model::IMPLEMENTATION, source};
use anyhow::{Result, ensure};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

pub fn id(plan: &Plan) -> Result<String> {
    let mut semantic = plan.clone();
    semantic.id.clear();
    Ok(source::digest(&serde_json::to_vec(&semantic)?))
}

pub fn create(root: &Path) -> Result<Plan> {
    let config = contract::load(root)?;
    let identity = source::snapshot_plain(root)?;
    contract::validate_source(root, &config, &identity)?;
    let resolved = config
        .products
        .iter()
        .map(|p| builder::resolve(root, p, &identity.files))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        source::snapshot_plain(root)? == identity,
        "source changed during planning"
    );
    let mut plan = assemble(config, identity, resolved)?;
    plan.id = id(&plan)?;
    Ok(plan)
}

fn command(argv: Vec<String>, env: BTreeMap<String, String>) -> CommandSpec {
    CommandSpec {
        argv,
        env,
        cwd: ".".into(),
    }
}
fn context(p: &Product, r: &Resolution, t: &Target, u: usize) -> BTreeMap<String, String> {
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
        ("KIT_TARGET".into(), t.key()),
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
pub(crate) fn assemble(
    config: Config,
    identity: crate::model::SourceIdentity,
    resolved: Vec<Resolution>,
) -> Result<Plan> {
    ensure!(
        config.products.len() == resolved.len(),
        "resolved product set differs from configuration"
    );
    let mut tasks = Vec::new();
    let mut probes = Vec::new();
    let mut units = Vec::new();
    for (i, (key, command)) in builder::probes(&config.products).into_iter().enumerate() {
        let task_id = format!("probe-{i}");
        tasks.push(Task {
            id: task_id.clone(),
            depends_on: vec![],
            runtime: false,
            action: Action::Probe { key, command },
        });
        probes.push(task_id);
    }
    let mut terminal = Vec::new();
    for (pi, p) in config.products.iter().enumerate() {
        for (ti, t) in config
            .targets
            .iter()
            .enumerate()
            .filter(|(_, t)| p.targets.is_empty() || p.targets.contains(&t.key()))
        {
            let u = units.len();
            let r = &resolved[pi];
            let recipe = builder::recipe(p, r, t, &format!("{{attempt}}/work/build-{u}"))?;
            let suffix = if t.os == "windows" { "zip" } else { "tar.gz" };
            let filename = format!("{}-{}-{}.{suffix}", p.id, r.version, t.key());
            config::relative(&filename)?;
            let mut last = probes.clone();
            let env = context(p, r, t, u);
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
            for (i, build) in recipe.commands.iter().enumerate() {
                let task_id = format!("u{u}-build-{i}");
                tasks.push(Task {
                    id: task_id.clone(),
                    depends_on: last,
                    runtime: false,
                    action: Action::Build {
                        unit: u,
                        command: build.clone(),
                    },
                });
                last = vec![task_id];
            }
            let archive_id = format!("u{u}-archive");
            tasks.push(Task {
                id: archive_id.clone(),
                depends_on: last,
                runtime: false,
                action: Action::Archive { unit: u },
            });
            last = vec![archive_id];
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
            units.push(Unit {
                id: format!("{}-{}", p.id, t.key()),
                product: pi,
                target: ti,
                filename,
                recipe,
            });
        }
    }
    ensure!(!units.is_empty(), "no selected build units");
    tasks.push(Task {
        id: "seal".into(),
        depends_on: terminal,
        runtime: false,
        action: Action::Seal,
    });
    Ok(Plan {
        schema: SCHEMA,
        id: String::new(),
        implementation: IMPLEMENTATION.into(),
        source: identity,
        config,
        resolved,
        units,
        tasks,
    })
}

pub fn validate_saved(root: &Path, plan: &Plan) -> Result<()> {
    ensure!(
        plan.schema == SCHEMA && plan.implementation == IMPLEMENTATION,
        "unsupported plan schema/implementation"
    );
    ensure!(plan.id == id(plan)?, "plan identity mismatch");
    ensure!(
        contract::load(root)? == plan.config,
        "release.toml changed since planning"
    );
    ensure!(
        source::snapshot_plain(root)? == plan.source,
        "source identity changed since planning"
    );
    contract::validate_source(root, &plan.config, &plan.source)?;
    ensure!(
        plan.config.products.len() == plan.resolved.len(),
        "resolved product set mismatch"
    );
    for (p, r) in plan.config.products.iter().zip(&plan.resolved) {
        builder::validate_offline(root, p, r, &plan.source.files)?;
    }
    let expected = assemble(
        plan.config.clone(),
        plan.source.clone(),
        plan.resolved.clone(),
    )?;
    ensure!(
        plan.units == expected.units && plan.tasks == expected.tasks,
        "saved plan recipes or task graph differ from consumer contract"
    );
    Ok(())
}

pub fn load(path: &Path) -> Result<Plan> {
    read_json(path)
}
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    crate::cohort::io::read_json(path)
}

pub fn initialize(
    root: &Path,
    directory: &str,
    kind: &str,
    version: Option<&str>,
) -> Result<PathBuf> {
    let path = config::safe_join(root, "release.toml")?;
    ensure!(!path.exists(), "release.toml already exists");
    let products = builder::discover(root, directory, kind, version)?;
    let config = Config {
        schema: SCHEMA,
        targets: vec![builder::native_target_at(
            &contract::product_root(root, &products[0])?,
            kind,
        )?],
        products,
        timeout_seconds: 1200,
    };
    contract::validate(&config)?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?
        .write_all(toml::to_string_pretty(&config)?.as_bytes())?;
    Ok(path)
}
