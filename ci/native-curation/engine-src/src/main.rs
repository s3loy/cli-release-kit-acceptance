use anyhow::{Context, Result, ensure};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use relship::{
    ci, cohort, config, delivery, execute, github, model::IMPLEMENTATION, plan, process, source,
    v2, v5, verify,
};
use std::{
    fs::{self, OpenOptions},
    io::{IsTerminal, Write},
    path::{Path, PathBuf},
};

mod interactive {
    include!("interactive.rs");
}
mod delivery_cli {
    include!("delivery_cli.rs");
}
mod qualified_cli {
    include!("qualified_cli.rs");
}

mod catalog_cli {
    include!("catalog_cli.rs");
}

#[derive(clap::Args, Default)]
struct RuntimeArgs {
    /// Supply a pinned QEMU executable as qemu-arm=PATH or qemu-i386=PATH.
    #[arg(long = "emulator", value_name = "NAME=PATH")]
    emulators: Vec<String>,
    /// Supply a materialized, pinned runtime rootfs as TARGET_ID=PATH.
    #[arg(long = "rootfs", value_name = "TARGET_ID=PATH")]
    rootfs: Vec<String>,
}

#[derive(Subcommand)]
enum RuntimeCommand {
    /// Inspect a QEMU executable and optional materialized rootfs for configuration pins.
    Inspect {
        #[arg(long)]
        emulator: PathBuf,
        #[arg(long)]
        rootfs: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Parser)]
#[command(
    name = env!("CARGO_BIN_NAME"),
    version,
    about = "Release planning and artifact verification for Rust, Go and CMake C CLIs"
)]
struct Cli {
    #[arg(long, global = true, default_value = ".")]
    project: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Open the integrated terminal menu.
    Menu,
    /// Review and edit project settings in the terminal.
    Settings,
    /// List canonical target IDs, compiler profiles and package support.
    Targets {
        #[arg(long, value_parser = ["rust", "go", "cmake"])]
        builder: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Inspect controlled runtime inputs without changing project configuration.
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommand,
    },
    /// Review an explicit configuration upgrade; --apply saves a backup and replacement.
    Migrate {
        #[arg(long, value_parser = clap::value_parser!(u32).range(4..=5))]
        schema: u32,
        #[arg(long)]
        apply: bool,
    },
    /// Generate, inspect and execute reviewed consumer CI contracts.
    Ci {
        #[command(subcommand)]
        command: CiCommand,
    },
    /// Inspect this executable without source, tools or credentials.
    BuildInfo {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        expect_version: Option<String>,
        #[arg(long)]
        expect_source_id: Option<String>,
        #[arg(long)]
        expect_contract: Option<u32>,
    },
    /// Prepare and recover a GitHub draft; final publication is manual.
    Github {
        /// Select a stored gh account without changing its global active login.
        #[arg(long, global = true)]
        account: Option<String>,
        #[command(subcommand)]
        command: GithubCommand,
    },
    /// Discover workspace binaries and create release.toml without overwriting.
    Init {
        /// Select a built-in Rust or Go adapter for a multi-product configuration.
        #[arg(long, value_parser = ["rust", "go", "cmake"])]
        builder: Option<String>,
        #[arg(long, default_value = ".")]
        directory: String,
        /// Go application version; never inferred from the Go toolchain version.
        #[arg(long)]
        app_version: Option<String>,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=5))]
        schema: Option<u32>,
        /// Map a delivered command to its declared CMake executable target.
        #[arg(long = "cmake-target", value_name = "BINARY=TARGET")]
        cmake_target: Vec<String>,
        #[arg(long)]
        configure_preset: Option<String>,
        #[arg(long)]
        generator: Option<String>,
    },
    /// Inspect the release configuration and local toolchains; accepts work in progress.
    Doctor,
    /// Resolve a source-bound, immutable plan before any build.
    Plan {
        /// Select the execution contract; must match the configuration capabilities.
        #[arg(long, value_parser = clap::value_parser!(u32).range(2..=6))]
        protocol: Option<u32>,
        /// Save JSON to a fresh file; defaults to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Execute a saved plan in a fresh attempt directory.
    #[command(alias = "build")]
    Rehearse {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Produce build-only evidence which offline verify will reject.
        #[arg(long)]
        skip_runtime: bool,
        /// Exact nFPM executable for native Linux packages.
        #[arg(long)]
        nfpm: Option<PathBuf>,
        #[command(flatten)]
        runtime: RuntimeArgs,
    },
    /// Inspect the last recorded attempt state without compilers or source checkout.
    Status {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Check saved inputs, receipt and exact artifact bytes without compilers/network.
    Verify {
        #[arg(long)]
        output: PathBuf,
        /// Explicit trusted-key policy required for any merged worker collection.
        #[arg(long)]
        policy: Option<PathBuf>,
    },
    /// Derive a reviewable subset of planned worker builds and packages.
    Assign {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long = "unit")]
        units: Vec<String>,
        #[arg(long = "retry-safe-unit")]
        retry_safe: Vec<String>,
        #[arg(long)]
        skip_runtime: bool,
        #[arg(long)]
        output: PathBuf,
    },
    /// Execute an assignment in a fresh, isolated worker attempt.
    Worker {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        assignment: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        nfpm: Option<PathBuf>,
        #[command(flatten)]
        runtime: RuntimeArgs,
    },
    /// Continue an attempt, rechecking and reusing completed unit checkpoints.
    Resume {
        #[arg(long)]
        output: PathBuf,
        #[arg(long = "allow-retry")]
        allow_retry: Vec<String>,
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        nfpm: Option<PathBuf>,
        #[command(flatten)]
        runtime: RuntimeArgs,
    },
    /// Export completed worker units as a bounded, portable result bundle.
    Export {
        #[arg(long)]
        attempt: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Receive a bundle as candidate data without executing supplied content.
    Import {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Generate a local signing key and its public policy-registration material.
    Keygen {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Build approved source afresh and sign its completed units.
    Rebuild {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long = "unit")]
        units: Vec<String>,
        #[arg(long = "retry-safe-unit")]
        retry_safe: Vec<String>,
        #[arg(long)]
        candidate: Option<PathBuf>,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        skip_runtime: bool,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        nfpm: Option<PathBuf>,
        #[command(flatten)]
        runtime: RuntimeArgs,
    },
    /// Merge exactly one policy-authorized result for every planned unit.
    Merge {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long = "result", required = true)]
        results: Vec<PathBuf>,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum CiRole {
    Worker,
    Rebuild,
}

#[derive(Subcommand)]
enum CiCommand {
    /// Inspect explicitly selected app-local Windows CRT libraries and licenses.
    InspectWindowsRuntime {
        #[arg(long)]
        sdk: PathBuf,
        #[arg(long, value_parser = ["x86_64", "aarch64"])]
        arch: String,
        #[arg(long = "directory")]
        directories: Vec<PathBuf>,
        #[arg(long = "license")]
        licenses: Vec<PathBuf>,
        #[arg(long, default_value = "follow-project", value_parser = ["follow-project", "static", "dynamic"])]
        mode: String,
    },
    /// Inspect explicit native SDK roots and tools for a reviewed environment.
    InspectSdk {
        #[arg(long)]
        id: String,
        #[arg(long)]
        version: String,
        #[arg(long = "root", required = true)]
        roots: Vec<PathBuf>,
        #[arg(long = "tool", required = true)]
        tools: Vec<PathBuf>,
    },
    /// Execute an approved native profile without signing material.
    QualifiedRun {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        profile: String,
        #[arg(long)]
        expected_source: String,
        #[arg(long, value_parser=["candidate","rebuild"])]
        role: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        resume: bool,
    },
    /// Verify API-bound rebuilt results on a fresh runner, then seal them.
    Seal {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        expected_source: String,
        #[arg(long)]
        run_id: u64,
        #[arg(long)]
        run_attempt: u64,
        #[arg(long)]
        results: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        key: PathBuf,
    },
    /// Verify a sealed qualified collection without source, tools or network.
    VerifySeal {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        public_key: String,
    },
    /// Write reviewed workflow and bootstrap files without publishing them.
    Generate {
        #[arg(long, default_value = "release-ci.toml")]
        config: PathBuf,
        #[arg(long, default_value = ".github")]
        output: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Detect generated-file drift without changing files.
    Check {
        #[arg(long, default_value = "release-ci.toml")]
        config: PathBuf,
        #[arg(long, default_value = ".github")]
        output: PathBuf,
    },
    /// Bind every planned unit to exactly one reviewed worker profile.
    Schedule {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        expected_source: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Revalidate a schedule and run one statically selected CI role.
    RunJob {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        schedule: PathBuf,
        #[arg(long)]
        profile: String,
        #[arg(long, value_enum)]
        role: CiRole,
        #[arg(long)]
        expected_source: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        key: Option<PathBuf>,
        #[arg(long)]
        candidate: Option<PathBuf>,
    },
    /// Save a complete delivery collection and stopped attempt for explicit restore.
    PackState {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        collection: PathBuf,
        #[arg(long)]
        attempt: PathBuf,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        run_attempt: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Restore a specific saved delivery state after its previous writer stops.
    RestoreState {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        run_attempt: String,
        #[arg(long)]
        old_writer_stopped: bool,
        #[arg(long)]
        expected_source: Option<String>,
        #[arg(long)]
        expected_tag: Option<String>,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum GithubCommand {
    /// Inspect stored accounts or check credential identity and repository access.
    Auth {
        #[command(subcommand)]
        command: GithubAuthCommand,
    },
    /// Create a reviewable draft plan using read-only remote queries.
    Plan {
        #[arg(long)]
        collection: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        repo: String,
        #[arg(long)]
        tag: String,
        /// Allow stage to create a missing lightweight tag at the bound commit.
        #[arg(long)]
        create_tag_if_missing: bool,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        notes_file: Option<PathBuf>,
        #[arg(long)]
        prerelease: bool,
        #[arg(long)]
        output: PathBuf,
    },
    /// Execute a saved draft plan into a fresh local attempt.
    Stage {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        collection: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Reconcile remote state and continue unfinished uploads.
    Resume {
        #[arg(long)]
        collection: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        output: PathBuf,
        /// Explicitly retry an uncertain draft creation after operator review.
        #[arg(long)]
        retry_create_draft: bool,
    },
    /// Recheck exact remote tag, draft and asset bytes without remote writes.
    Verify {
        #[arg(long)]
        collection: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Read the last saved snapshot without source, token, tools or network.
    Status {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum GithubAuthCommand {
    /// List stored github.com accounts without exposing credentials.
    Accounts {
        #[arg(long)]
        json: bool,
    },
    /// Check identity; --repo also supports repository-scoped CI/App credentials.
    Status {
        #[arg(long)]
        repo: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None => {
            if interactive_terminal() {
                interactive::run(cli.project, interactive::Entry::Home)
            } else {
                Cli::command().print_help()?;
                println!();
                Ok(())
            }
        }
        Some(command @ (Command::Menu | Command::Settings)) => {
            ensure!(
                interactive_terminal(),
                "interactive mode requires terminal input, output and error streams; use an explicit subcommand for automation"
            );
            let entry = if matches!(command, Command::Settings) {
                interactive::Entry::Settings
            } else {
                interactive::Entry::Home
            };
            interactive::run(cli.project, entry)
        }
        Some(command) => run_command(&cli.project, command),
    }
}

fn interactive_terminal() -> bool {
    std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal()
        && std::env::var_os("TERM").is_none_or(|value| value != "dumb")
}

fn run_command(project: &Path, command: Command) -> Result<()> {
    let source_free = matches!(
        &command,
        Command::Status { .. }
            | Command::Keygen { .. }
            | Command::BuildInfo { .. }
            | Command::Targets { .. }
            | Command::Runtime { .. }
    ) || matches!(
        &command,
        Command::Ci {
            command: CiCommand::Seal { .. }
                | CiCommand::VerifySeal { .. }
                | CiCommand::InspectSdk { .. }
                | CiCommand::InspectWindowsRuntime { .. }
        }
    ) || matches!(
        &command,
        Command::Github {
            command: GithubCommand::Status { .. } | GithubCommand::Auth { .. },
            ..
        }
    );
    let source_free = source_free
        || match &command {
            Command::Verify { output, .. }
            | Command::Export {
                attempt: output, ..
            } => json_schema(&output.join("plan.json")).is_ok_and(|schema| schema == 6),
            _ => false,
        };
    let root = if source_free {
        project.to_path_buf()
    } else {
        source::root(project)?
    };
    eprintln!(
        "engine: {}/{}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION")
    );
    if qualified_cli::supports(&root, &command)? {
        return qualified_cli::run(&root, command);
    }
    if catalog_cli::supports(&root, &command)? {
        return catalog_cli::run(&root, command);
    }
    if let Some(runtime) = catalog_cli::runtime_args(&command) {
        ensure!(
            runtime.emulators.is_empty() && runtime.rootfs.is_empty(),
            "--emulator and --rootfs require execution protocol 5"
        );
    }
    if delivery_cli::supports(&root, &command)? {
        return delivery_cli::run(&root, command);
    }
    match command {
        Command::Targets { .. } | Command::Runtime { .. } | Command::Migrate { .. } => {
            unreachable!("catalog dispatch handled above")
        }
        Command::Menu | Command::Settings => {
            anyhow::bail!("interactive commands cannot be dispatched as build actions")
        }
        Command::Ci { command } => run_ci(&root, command)?,
        Command::BuildInfo {
            json,
            expect_version,
            expect_source_id,
            expect_contract,
        } => {
            let version = env!("CARGO_PKG_VERSION");
            let source_id = cohort::model::ENGINE_SOURCE_ID;
            ensure!(
                expect_version
                    .as_deref()
                    .is_none_or(|expected| expected == version),
                "engine version does not match the installation profile"
            );
            ensure!(
                expect_source_id
                    .as_deref()
                    .is_none_or(|expected| expected == source_id),
                "engine source identity does not match the installation profile"
            );
            ensure!(
                expect_contract.is_none_or(|expected| expected == ci::model::CONTRACT),
                "engine does not support the required CI contract"
            );
            let info = serde_json::json!({
                "schema": 1,
                "package": env!("CARGO_PKG_NAME"),
                "version": version,
                "engine_source_id": source_id,
                "target": env!("KIT_ENGINE_TARGET"),
                "ci_contracts": [ci::model::CONTRACT]
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                println!(
                    "relship {version} ({})\nsource: {source_id}\nCI contract: 1",
                    env!("KIT_ENGINE_TARGET")
                );
            }
        }
        Command::Github { command, account } => run_github(&root, command, account.as_deref())?,
        Command::Init {
            builder,
            directory,
            app_version,
            schema,
            ..
        } => {
            let use_v2 = schema == Some(2)
                || builder.is_some()
                || directory != "."
                || (root.join("go.mod").exists() && !root.join("Cargo.toml").exists());
            ensure!(
                schema != Some(1) || !use_v2,
                "schema 1 only supports the root Cargo workspace"
            );
            let path = if use_v2 {
                let kind = match builder.as_deref() {
                    Some(kind) => kind,
                    None => {
                        let dir = if directory == "." {
                            root.clone()
                        } else {
                            config::safe_join(&root, &directory)?
                        };
                        match (dir.join("Cargo.toml").exists(), dir.join("go.mod").exists()) {
                            (true, false) => "rust",
                            (false, true) => "go",
                            _ => anyhow::bail!("select --builder rust or go for this directory"),
                        }
                    }
                };
                v2::plan::initialize(&root, &directory, kind, app_version.as_deref())?
            } else {
                ensure!(
                    app_version.is_none(),
                    "--app-version requires the Go adapter"
                );
                plan::initialize(&root)?
            };
            println!("created {}; review and commit the contract", path.display());
        }
        Command::Doctor => {
            if config_schema(&root)? == 2 {
                let config = v2::contract::load(&root)?;
                let mut tools = std::collections::BTreeMap::new();
                for (key, spec) in v2::builder::probes(&config.products) {
                    let cwd = if spec.cwd == "." {
                        root.clone()
                    } else {
                        config::safe_join(&root, &spec.cwd)?
                    };
                    tools.insert(key, process::capture_spec(&cwd, &spec.argv, &spec.env, 60)?);
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "schema": 2, "execution_protocols": [2, 3],
                        "implementation": IMPLEMENTATION, "targets": config.targets,
                        "toolchain": tools, "publication_ready": false,
                        "available": ["source-bound-plan", "rust-build", "go-build", "task-status", "tar.gz", "zip", "offline-verify"],
                        "protocol_3_available": ["worker-assignments", "worker-transfer", "unit-resume", "candidate-import", "trusted-rebuild", "ed25519-signing", "policy-merge", "github-draft"],
                        "unavailable": ["native-packages", "release-publish", "github-oidc", "go-workspaces", "cgo"]
                    }))?
                );
                return Ok(());
            }
            let config = config::load(&root)?;
            let cargo = process::capture(&root, &["cargo".into(), "--version".into()], 60)?;
            let metadata = process::capture(
                &root,
                &[
                    "cargo".into(),
                    "metadata".into(),
                    "--locked".into(),
                    "--no-deps".into(),
                    "--format-version".into(),
                    "1".into(),
                ],
                1200,
            )?;
            let metadata: serde_json::Value = serde_json::from_str(&metadata)?;
            ensure!(
                std::path::Path::new(
                    metadata["workspace_root"]
                        .as_str()
                        .context("missing workspace root")?
                )
                .canonicalize()?
                    == root,
                "project must be Cargo workspace root"
            );
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "implementation": IMPLEMENTATION,
                    "schema": config.schema,
                    "host": plan::host(&root)?,
                    "targets": config.targets,
                    "cargo": cargo.trim(),
                    "publication_ready": false,
                    "available": ["local-plan", "cargo-build", "tar.gz", "zip", "sha256", "offline-verify"],
                    "unavailable": ["native-packages", "worker-transfer", "resume", "publication", "signing"]
                }))?
            );
        }
        Command::Plan { output, protocol } => {
            let protocol = protocol.unwrap_or(2);
            let (bytes, plan_id) = if protocol == 3 {
                ensure!(
                    config_schema(&root)? == 2,
                    "protocol 3 requires a schema 2 consumer configuration"
                );
                let saved = cohort::plan::create(&root)?;
                (serde_json::to_vec_pretty(&saved)?, saved.id)
            } else if config_schema(&root)? == 2 {
                let saved = v2::plan::create(&root)?;
                (serde_json::to_vec_pretty(&saved)?, saved.id)
            } else {
                let saved = plan::create(&root)?;
                (serde_json::to_vec_pretty(&saved)?, saved.id)
            };
            if let Some(path) = output {
                let path = std::path::absolute(path)?;
                if let Ok(relative) = path.strip_prefix(&root) {
                    let name = relative.to_str().context("non-UTF8 output path")?;
                    ensure!(
                        name.starts_with("target/"),
                        "save plans outside source tree or below target/"
                    );
                    config::safe_join(&root, name)?;
                }
                let parent = path.parent().context("plan output has no parent")?;
                fs::create_dir_all(parent)?;
                let mut out = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&path)?;
                out.write_all(&bytes)?;
                out.write_all(b"\n")?;
                eprintln!("engine: plan {} saved to {}", plan_id, path.display());
            } else {
                println!("{}", String::from_utf8(bytes)?);
            }
        }
        Command::Rehearse {
            plan: path,
            output,
            skip_runtime,
            nfpm: _,
            ..
        } => {
            if json_schema(&path)? == 2 {
                let receipt =
                    v2::run::execute(&root, &v2::plan::load(&path)?, &output, skip_runtime)?;
                println!("{}", serde_json::to_string_pretty(&receipt)?);
            } else {
                let receipt = execute::run(&root, &plan::load(&path)?, &output, skip_runtime)?;
                println!("{}", serde_json::to_string_pretty(&receipt)?);
            }
        }
        Command::Status { output, json } => {
            if json_schema(&output.join("receipt.json"))? == 3 {
                let receipt = cohort::run::status(&output)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&receipt)?);
                } else {
                    println!(
                        "{}: last recorded {} ({} completed units, updated {} ms since Unix epoch)",
                        receipt.plan_id,
                        receipt.status,
                        receipt.units.len(),
                        receipt.updated_at_ms
                    );
                    for invocation in &receipt.invocations {
                        println!("invocation {}: {}", invocation.id, invocation.status);
                        for task in &invocation.tasks {
                            println!(
                                "  {} {:?} {} ms{}",
                                task.id,
                                task.state,
                                task.elapsed_ms,
                                task.error
                                    .as_ref()
                                    .map(|e| format!("  {e}"))
                                    .unwrap_or_default()
                            );
                        }
                    }
                    if receipt.finished_at_ms.is_none() {
                        println!("Unfinished snapshot; process liveness is not inferred.");
                    }
                    if let Some(error) = receipt.error {
                        println!("{error}");
                    }
                }
                return Ok(());
            }
            if json_schema(&output.join("receipt.json"))? == 2 {
                let receipt = v2::run::status(&output)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&receipt)?);
                } else {
                    println!(
                        "{}: last recorded state {} (updated {} ms since Unix epoch)",
                        receipt.plan_id, receipt.status, receipt.updated_at_ms
                    );
                    if receipt.finished_at_ms.is_none() {
                        println!(
                            "Attempt is unfinished; process liveness and recovery are not inferred."
                        );
                    }
                    for task in &receipt.tasks {
                        println!(
                            "{}  {:?}  {} ms{}",
                            task.id,
                            task.state,
                            task.elapsed_ms,
                            task.error
                                .as_ref()
                                .map(|e| format!("  {e}"))
                                .unwrap_or_default()
                        );
                        if let Some(log) = &task.log {
                            println!("  logs: {}/{}.stdout / .stderr", output.display(), log);
                        }
                    }
                }
            } else {
                let receipt: relship::model::Receipt =
                    v2::plan::read_json(&output.join("receipt.json"))?;
                ensure!(receipt.schema == 1, "unsupported receipt schema");
                if json {
                    println!("{}", serde_json::to_string_pretty(&receipt)?);
                } else {
                    println!(
                        "{}: {} (schema 1 has no task-level status)",
                        receipt.plan_id, receipt.status
                    );
                }
            }
        }
        Command::Verify { output, policy } => {
            if output.join("collection.json").exists() {
                let policy = cohort::crypto::load_policy(
                    policy
                        .as_deref()
                        .context("collection verification requires --policy")?,
                )?;
                let collection = cohort::bundle::verify_collection(&root, &output, &policy)?;
                println!(
                    "verified preparation {}: {} policy-authorized units (not published)",
                    collection.id,
                    collection.selections.len()
                );
                return Ok(());
            }
            if json_schema(&output.join("plan.json"))? == 3 {
                let receipt = cohort::run::verify_run(&root, &output)?;
                println!(
                    "checked worker preparation {}: {} completed units (trust requires merge policy)",
                    receipt.plan_id,
                    receipt.units.len()
                );
                return Ok(());
            }
            if json_schema(&output.join("plan.json"))? == 2 {
                let receipt = v2::run::verify(&root, &output)?;
                println!(
                    "verified {}: {} archives (local unsigned evidence)",
                    receipt.plan_id,
                    receipt.artifacts.len()
                );
                return Ok(());
            }
            let receipt = verify::verify(&root, &output)?;
            println!(
                "verified {}: {} archives (local unsigned evidence)",
                receipt.plan_id,
                receipt.artifacts.len()
            );
        }
        Command::Assign {
            plan,
            units,
            retry_safe,
            skip_runtime,
            output,
        } => {
            let plan = cohort::plan::load(&plan)?;
            cohort::plan::validate(&root, &plan)?;
            let units = cohort::plan::select(&plan, &units)?;
            let retry = selected_or_empty(&plan, &retry_safe)?;
            let assignment =
                cohort::plan::assignment(&plan, units, retry, skip_runtime, None, None)?;
            write_new_json(&root, &output, &assignment)?;
            println!(
                "assigned {}: {} units",
                assignment.id,
                assignment.units.len()
            );
        }
        Command::Worker {
            plan,
            assignment,
            output,
            nfpm: _,
            ..
        } => {
            let plan = cohort::plan::load(&plan)?;
            let assignment = cohort::io::read_json(&assignment)?;
            let receipt =
                cohort::run::execute(&root, &plan, &assignment, &output, false, &[], None)?;
            export_default(&root, &output)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        Command::Resume {
            output,
            allow_retry,
            key,
            nfpm: _,
            ..
        } => {
            let plan = cohort::plan::load(&config::safe_join(&output, "plan.json")?)?;
            let assignment =
                cohort::io::read_json(&config::safe_join(&output, "assignment.json")?)?;
            let retry = selected_or_empty(&plan, &allow_retry)?;
            let key = key.as_deref().map(cohort::crypto::load_key).transpose()?;
            let receipt = cohort::run::execute(
                &root,
                &plan,
                &assignment,
                &output,
                true,
                &retry,
                key.as_ref(),
            )?;
            export_default(&root, &output)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        Command::Export { attempt, output } => {
            let bundle = cohort::bundle::export_run(&root, &attempt, &output)?;
            println!("exported {}: {} units", bundle.id, bundle.units.len());
        }
        Command::Import {
            plan,
            bundle,
            output,
        } => {
            let plan = cohort::plan::load(&plan)?;
            let bundle = cohort::bundle::import_candidate(&root, &plan, &bundle, &output)?;
            println!(
                "candidate {}: {} units; supplied code was not executed",
                bundle.id,
                bundle.units.len()
            );
        }
        Command::Keygen {
            private_key,
            public_key,
        } => {
            let key = cohort::crypto::keygen(&private_key, &public_key)?;
            println!("public rebuild key: {key}");
        }
        Command::Rebuild {
            plan,
            units,
            retry_safe,
            candidate,
            key,
            skip_runtime,
            output,
            nfpm: _,
            ..
        } => {
            let plan = cohort::plan::load(&plan)?;
            cohort::plan::validate(&root, &plan)?;
            let key = cohort::crypto::load_key(&key)?;
            let candidate = candidate
                .as_deref()
                .map(|dir| cohort::bundle::candidate_ref(&root, &plan, dir))
                .transpose()?;
            let units = if units.is_empty() {
                candidate
                    .as_ref()
                    .map(|c| c.digests.keys().copied().collect())
                    .unwrap_or_else(|| (0..plan.units.len()).collect())
            } else {
                cohort::plan::select(&plan, &units)?
            };
            let candidate = candidate.map(|mut c| {
                c.digests.retain(|unit, _| units.contains(unit));
                c
            });
            let retry = selected_or_empty(&plan, &retry_safe)?;
            let assignment = cohort::plan::assignment(
                &plan,
                units,
                retry,
                skip_runtime,
                Some(cohort::crypto::public_key(&key)),
                candidate,
            )?;
            let receipt =
                cohort::run::execute(&root, &plan, &assignment, &output, false, &[], Some(&key))?;
            export_default(&root, &output)?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        Command::Merge {
            plan,
            results,
            policy,
            output,
        } => {
            let plan = cohort::plan::load(&plan)?;
            let policy = cohort::crypto::load_policy(&policy)?;
            let collection = cohort::bundle::merge(&root, &plan, &results, &policy, &output)?;
            println!(
                "prepared {}: {} policy-authorized units; publication_ready=false",
                collection.id,
                collection.selections.len()
            );
        }
    }
    Ok(())
}

fn run_ci(root: &std::path::Path, command: CiCommand) -> Result<()> {
    let at = |path: PathBuf| {
        if path.is_absolute() {
            path
        } else {
            root.join(path)
        }
    };
    let expected = |commit: &str| -> Result<()> {
        ensure!(
            commit.len() == 40
                && commit
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "expected source must be an exact lowercase commit SHA"
        );
        ensure!(
            source::git(root, &["rev-parse", "HEAD"])?.trim() == commit,
            "CI checkout differs from the approved source commit"
        );
        Ok(())
    };
    match command {
        CiCommand::InspectWindowsRuntime {
            sdk,
            arch,
            directories,
            licenses,
            mode,
        } => {
            let sdk: relship::compatibility::NativeSdkExpectation =
                serde_json::from_slice(&std::fs::read(sdk)?)?;
            let mode = match mode.as_str() {
                "static" => relship::compatibility::windows_crt::WindowsRuntimeMode::Static,
                "dynamic" => relship::compatibility::windows_crt::WindowsRuntimeMode::Dynamic,
                _ => relship::compatibility::windows_crt::WindowsRuntimeMode::FollowProject,
            };
            let policy = relship::compatibility::windows_crt::inspect_runtime(
                relship::compatibility::Architecture::parse(&arch)?,
                &sdk,
                &directories,
                &licenses,
                mode,
            )?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
        }
        CiCommand::InspectSdk {
            id,
            version,
            roots,
            tools,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&relship::qualified::run::inspect_sdk(
                    &id, &version, &roots, &tools
                )?)?
            );
        }
        CiCommand::QualifiedRun {
            config,
            plan,
            profile,
            expected_source,
            role,
            output,
            resume,
        } => {
            expected(&expected_source)?;
            let cfg = ci::config::load(&at(config))?;
            let plan = relship::qualified::plan::load(&at(plan))?;
            let role = if role == "candidate" {
                ci::seal::Role::Candidate
            } else {
                ci::seal::Role::Rebuild
            };
            let receipt = ci::qualified::execute_job(
                root,
                &cfg,
                &plan,
                &profile,
                role,
                &expected_source,
                &at(output),
                resume,
            )?;
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        CiCommand::Seal {
            config,
            plan,
            expected_source,
            run_id,
            run_attempt,
            results,
            output,
            key,
        } => {
            let cfg = ci::config::load(&at(config))?;
            ci::config::assert_current_engine(&cfg)?;
            let plan = relship::qualified::plan::load(&at(plan))?;
            let result = ci::seal::execute(
                &cfg,
                &plan,
                &expected_source,
                run_id,
                run_attempt,
                &at(results),
                &at(output),
                &at(key),
            )?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        CiCommand::VerifySeal { output, public_key } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&ci::seal::verify_collection(
                    &at(output),
                    &public_key
                )?)?
            );
        }
        CiCommand::Generate {
            config,
            output,
            force,
        } => {
            let profile = ci::config::load(&at(config))?;
            ci::config::assert_current_engine(&profile)?;
            ci::render::generate(root, &profile, &at(output), force)?;
            println!("generated reviewed relship workflow files; no remote changes made");
        }
        CiCommand::Check { config, output } => {
            let profile = ci::config::load(&at(config))?;
            ci::config::assert_current_engine(&profile)?;
            ci::render::check(root, &profile, &at(output))?;
            println!("generated CI files match the installation and scheduling profile");
        }
        CiCommand::Schedule {
            config,
            plan,
            expected_source,
            output,
        } => {
            expected(&expected_source)?;
            let profile = ci::config::load(&at(config))?;
            let plan_path = at(plan);
            let schedule = if json_schema(&plan_path)? == 5 {
                let plan = v5::plan::load(&plan_path)?;
                ensure!(
                    plan.source.commit == expected_source,
                    "CI plan differs from approved source commit"
                );
                ci::schedule::create_v5(root, &profile, &plan)?
            } else if json_schema(&plan_path)? == 4 {
                let plan = delivery::plan::load(&plan_path)?;
                ensure!(
                    plan.source.commit == expected_source,
                    "CI plan differs from approved source commit"
                );
                ci::schedule::create_delivery(root, &profile, &plan)?
            } else {
                let plan = cohort::plan::load(&plan_path)?;
                ensure!(
                    plan.source.commit == expected_source,
                    "CI plan differs from approved source commit"
                );
                ci::schedule::create(root, &profile, &plan)?
            };
            let path = at(output);
            ensure!(!path.exists(), "schedule output already exists");
            cohort::io::write_json_atomic(&path, &schedule)?;
            println!("{}", serde_json::to_string_pretty(&schedule)?);
        }
        CiCommand::RunJob {
            config,
            plan,
            schedule,
            profile,
            role,
            expected_source,
            output,
            key,
            candidate,
        } => {
            expected(&expected_source)?;
            let configuration = ci::config::load(&at(config))?;
            let plan_path = at(plan);
            let schedule = cohort::io::read_json(&at(schedule))?;
            let key = key.map(at);
            let candidate = candidate.map(at);
            let role = match role {
                CiRole::Worker => ci::model::JobRole::Worker,
                CiRole::Rebuild => ci::model::JobRole::Rebuild,
            };
            let receipt = if json_schema(&plan_path)? == 5 {
                let plan = v5::plan::load(&plan_path)?;
                ensure!(
                    plan.source.commit == expected_source,
                    "CI plan differs from approved source commit"
                );
                serde_json::to_value(ci::run::execute_v5_job(
                    root,
                    &configuration,
                    &plan,
                    &schedule,
                    &profile,
                    role,
                    key.as_deref(),
                    candidate.as_deref(),
                    &at(output),
                )?)?
            } else if json_schema(&plan_path)? == 4 {
                let plan = delivery::plan::load(&plan_path)?;
                ensure!(
                    plan.source.commit == expected_source,
                    "CI plan differs from approved source commit"
                );
                serde_json::to_value(ci::run::execute_delivery_job(
                    root,
                    &configuration,
                    &plan,
                    &schedule,
                    &profile,
                    role,
                    key.as_deref(),
                    candidate.as_deref(),
                    &at(output),
                )?)?
            } else {
                let plan = cohort::plan::load(&plan_path)?;
                ensure!(
                    plan.source.commit == expected_source,
                    "CI plan differs from approved source commit"
                );
                serde_json::to_value(ci::run::execute_job(
                    root,
                    &configuration,
                    &plan,
                    &schedule,
                    &profile,
                    role,
                    key.as_deref(),
                    candidate.as_deref(),
                    &at(output),
                )?)?
            };
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        }
        CiCommand::PackState {
            config,
            collection,
            attempt,
            run_id,
            run_attempt,
            output,
        } => {
            let profile = ci::config::load(&at(config))?;
            ci::state::pack(
                root,
                &profile,
                &at(collection),
                &at(attempt),
                &run_id,
                &run_attempt,
                &at(output),
            )?;
            println!("saved complete delivery state for explicit restore");
        }
        CiCommand::RestoreState {
            config,
            archive,
            run_id,
            run_attempt,
            old_writer_stopped,
            expected_source,
            expected_tag,
            output,
        } => {
            let profile = ci::config::load(&at(config))?;
            let output = at(output);
            ci::state::restore(
                root,
                &profile,
                &at(archive),
                &run_id,
                &run_attempt,
                old_writer_stopped,
                &output,
            )?;
            let plan = github::plan::load(&output.join("attempt/plan.json"))?;
            ensure!(
                expected_source
                    .as_deref()
                    .is_none_or(|value| value == plan.source_commit),
                "restored source differs from approved dispatch"
            );
            ensure!(
                expected_tag
                    .as_deref()
                    .is_none_or(|value| value == plan.tag),
                "restored tag differs from approved dispatch"
            );
            println!("restored the explicitly selected delivery state");
        }
    }
    Ok(())
}

fn run_github(root: &std::path::Path, command: GithubCommand, account: Option<&str>) -> Result<()> {
    if let GithubCommand::Status { output, json } = &command {
        let receipt = github::run::status(output)?;
        if *json {
            println!("{}", serde_json::to_string_pretty(&receipt)?);
        } else {
            println!(
                "{}: {} (last saved snapshot at {} ms)",
                receipt.plan_id, receipt.status, receipt.updated_at_ms
            );
            if let Some(error) = receipt.error {
                println!("{error}");
            }
        }
        return Ok(());
    }
    if let GithubCommand::Auth { command } = command {
        return run_github_auth(command, account);
    }
    let mut api = github::auth::client(account)?;
    if let Some(account) = account {
        eprintln!("GitHub credential account: {account} (gh; identity checked)");
    }
    let receipt = match command {
        GithubCommand::Plan {
            collection,
            policy,
            repo,
            tag,
            create_tag_if_missing,
            title,
            notes_file,
            prerelease,
            output,
        } => {
            let notes = if let Some(path) = notes_file {
                let meta = fs::symlink_metadata(&path)?;
                ensure!(
                    meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= 1024 * 1024,
                    "notes must be a regular file no larger than 1 MiB"
                );
                use std::io::Read;
                let mut bytes = Vec::new();
                fs::File::open(path)?
                    .take(1024 * 1024 + 1)
                    .read_to_end(&mut bytes)?;
                ensure!(bytes.len() <= 1024 * 1024, "notes grew beyond limit");
                String::from_utf8(bytes).context("notes must be UTF-8")?
            } else {
                String::new()
            };
            let options = github::plan::Options {
                repository: repo,
                title: title.unwrap_or_else(|| tag.clone()),
                tag,
                create_tag_if_missing,
                notes,
                prerelease,
            };
            let saved = if json_schema(&collection.join("collection.json"))? == 5 {
                let policy = catalog_cli::load_policy(&policy)?;
                github::plan::create_v5(root, &collection, &policy, options, &mut api)?
            } else {
                let policy = cohort::crypto::load_policy(&policy)?;
                github::plan::create(root, &collection, &policy, options, &mut api)?
            };
            write_new_json(root, &output, &saved)?;
            println!(
                "planned GitHub draft {}: {} assets; no remote writes",
                saved.id,
                saved.assets.len()
            );
            return Ok(());
        }
        GithubCommand::Stage {
            plan,
            collection,
            policy,
            output,
        } => {
            let saved = github::plan::load(&plan)?;
            if json_schema(&collection.join("collection.json"))? == 5 {
                let policy = catalog_cli::load_policy(&policy)?;
                github::run::stage_v5(root, &collection, &policy, &saved, &output, &mut api)?
            } else {
                let policy = cohort::crypto::load_policy(&policy)?;
                github::run::stage(root, &collection, &policy, &saved, &output, &mut api)?
            }
        }
        GithubCommand::Resume {
            collection,
            policy,
            output,
            retry_create_draft,
        } => {
            if json_schema(&collection.join("collection.json"))? == 5 {
                let policy = catalog_cli::load_policy(&policy)?;
                github::run::resume_v5(
                    root,
                    &collection,
                    &policy,
                    &output,
                    &mut api,
                    retry_create_draft,
                )?
            } else {
                let policy = cohort::crypto::load_policy(&policy)?;
                github::run::resume(
                    root,
                    &collection,
                    &policy,
                    &output,
                    &mut api,
                    retry_create_draft,
                )?
            }
        }
        GithubCommand::Verify {
            collection,
            policy,
            output,
        } => {
            if json_schema(&collection.join("collection.json"))? == 5 {
                let policy = catalog_cli::load_policy(&policy)?;
                github::run::verify_v5(root, &collection, &policy, &output, &mut api)?
            } else {
                let policy = cohort::crypto::load_policy(&policy)?;
                github::run::verify(root, &collection, &policy, &output, &mut api)?
            }
        }
        GithubCommand::Status { .. } | GithubCommand::Auth { .. } => unreachable!(),
    };
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(())
}

fn run_github_auth(command: GithubAuthCommand, account: Option<&str>) -> Result<()> {
    match command {
        GithubAuthCommand::Accounts { json } => {
            ensure!(
                account.is_none(),
                "omit --account when listing stored accounts"
            );
            let accounts = github::auth::accounts()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&accounts)?);
            } else {
                for account in accounts {
                    println!(
                        "{} {}{} ({})",
                        account.host,
                        account.login,
                        if account.active { " [active]" } else { "" },
                        account.state
                    );
                }
            }
        }
        GithubAuthCommand::Status { repo, json } => {
            use github::model::Api;
            if let Some(repo) = &repo {
                github::plan::repository_name(repo)?;
            }
            let mut api = github::auth::client(account)?;
            let repository = repo
                .as_deref()
                .map(|repo| api.repository(repo))
                .transpose()?;
            let identity = match api.identity() {
                Ok(identity) => Some(identity),
                Err(_) if account.is_none() && repository.is_some() => None,
                Err(_) => anyhow::bail!(
                    "could not verify user identity; for repository-scoped credentials use github auth status --repo OWNER/REPO"
                ),
            };
            let view = serde_json::json!({
                "source": if account.is_some() { "gh" } else { "environment" },
                "selected_account": account,
                "identity_verified": identity.is_some(), "identity": identity,
                "repository": repository,
                "repository_access": if repository.is_some() { Some("readable") } else { None },
                "write_access_checked": false,
            });
            if json {
                println!("{}", serde_json::to_string_pretty(&view)?);
            } else {
                println!("credential source: {}", view["source"].as_str().unwrap());
                if let Some(identity) = identity {
                    println!("authenticated user: {} ({})", identity.login, identity.id);
                } else {
                    println!("user identity: not verified");
                }
                if let Some(repository) = repository {
                    println!(
                        "repository: {} ({}); read access checked, write access not exercised",
                        repository.full_name, repository.id
                    );
                }
            }
        }
    }
    Ok(())
}

fn selected_or_empty(plan: &cohort::model::Plan, names: &[String]) -> Result<Vec<usize>> {
    if names.is_empty() {
        Ok(vec![])
    } else {
        cohort::plan::select(plan, names)
    }
}
fn export_default(root: &std::path::Path, output: &std::path::Path) -> Result<()> {
    let plan = cohort::plan::load(&config::safe_join(output, "plan.json")?)?;
    let directory = output.join("result");
    if directory.exists() {
        cohort::bundle::validate(root, &plan, &directory)?;
    } else {
        cohort::bundle::export_run(root, output, &directory)?;
    }
    Ok(())
}
fn write_new_json<T: serde::Serialize>(
    root: &std::path::Path,
    path: &std::path::Path,
    value: &T,
) -> Result<()> {
    let path = std::path::absolute(path)?;
    if let Ok(relative) = path.strip_prefix(root) {
        let name = relative.to_str().context("non-UTF8 output")?;
        ensure!(
            name.starts_with("target/"),
            "save records outside source or below target/"
        );
        config::safe_join(root, name)?;
    }
    fs::create_dir_all(path.parent().context("record has no parent")?)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn config_schema(root: &std::path::Path) -> Result<u64> {
    let value: toml::Value = toml::from_str(&fs::read_to_string(config::safe_join(
        root,
        "release.toml",
    )?)?)?;
    let schema = value
        .get("schema")
        .and_then(toml::Value::as_integer)
        .context("missing configuration schema")?;
    ensure!(matches!(schema, 1..=5), "unsupported release.toml schema");
    Ok(schema as u64)
}
fn json_schema(path: &std::path::Path) -> Result<u64> {
    let value: serde_json::Value = v2::plan::read_json(path)?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_u64)
        .context("missing saved schema")?;
    ensure!(matches!(schema, 1..=6), "unsupported saved schema");
    Ok(schema)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("engine: {error:#}");
        let interrupted = error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::Interrupted)
        });
        std::process::exit(if interrupted { 130 } else { 1 });
    }
}
