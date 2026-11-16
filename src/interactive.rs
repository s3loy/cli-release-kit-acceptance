use super::{
    Command, GithubAuthCommand, GithubCommand, config_schema, run_command, write_new_json,
};
use anyhow::{Context, Result, ensure};
use dialoguer::{Confirm, Input, MultiSelect, Select, theme::ColorfulTheme};
use relship::{cohort, github, plan, settings, source, v2};
use serde_json::Value;
use std::{
    io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[path = "interactive_catalog.rs"]
mod catalog_ui;
#[path = "interactive_delivery.rs"]
mod delivery_ui;

pub(super) enum Entry {
    Home,
    Settings,
}

pub(super) fn run(project: PathBuf, entry: Entry) -> Result<()> {
    let project = std::path::absolute(project)?;
    let project = source::git(&project, &["rev-parse", "--show-toplevel"])
        .and_then(|root| source::root(Path::new(root.trim())))
        .unwrap_or(project);
    let mut account = None;
    println!("relship — interactive release preparation");
    println!("Project: {}", path_label(&project));
    println!("Use arrow keys and Enter; Space selects multiple items. Esc or q returns.");
    println!("Text prompts: submit an empty value to cancel. Ctrl-C exits.\n");
    if matches!(entry, Entry::Settings) {
        handle(settings_menu(&project))?;
    }
    loop {
        let choice = select(
            "What would you like to do?",
            &[
                "Preview / build",
                "Project settings",
                "Tasks / status / verify / resume",
                "GitHub drafts",
                "Accounts",
                "Exit",
            ],
        )?;
        let result = match choice {
            Some(0) => preview_menu(&project),
            Some(1) => settings_menu(&project),
            Some(2) => tasks_menu(&project),
            Some(3) => github_menu(&project, account.as_deref()),
            Some(4) => accounts_menu(&project, &mut account),
            _ => return Ok(()),
        };
        handle(result)?;
    }
}

fn handle(result: Result<()>) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if interrupted(&error) => Err(error),
        Err(error) => {
            eprintln!("\nOperation stopped: {}\n", escaped(&format!("{error:#}")));
            Ok(())
        }
    }
}

fn interrupted(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::Interrupted)
    })
}

fn prompt_error(error: dialoguer::Error) -> anyhow::Error {
    io::Error::from(error).into()
}

struct PromptGuard {
    #[cfg(unix)]
    previous_sigint: libc::sigaction,
}

impl PromptGuard {
    fn new() -> Result<Self> {
        #[cfg(unix)]
        {
            extern "C" fn interrupt_prompt(_: libc::c_int) {}
            // console restores termios before raising SIGINT. Catch that signal
            // only while prompting so its Interrupted error can run our cleanup.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = interrupt_prompt as *const () as libc::sighandler_t;
            action.sa_flags = 0;
            let mut previous = std::mem::MaybeUninit::uninit();
            let status = unsafe {
                libc::sigemptyset(&mut action.sa_mask);
                libc::sigaction(libc::SIGINT, &action, previous.as_mut_ptr())
            };
            if status != 0 {
                return Err(io::Error::last_os_error().into());
            }
            Ok(Self {
                previous_sigint: unsafe { previous.assume_init() },
            })
        }
        #[cfg(not(unix))]
        Ok(Self {})
    }
}

impl Drop for PromptGuard {
    fn drop(&mut self) {
        let term = console::Term::stderr();
        let _ = term.show_cursor();
        let _ = term.flush();
        #[cfg(unix)]
        unsafe {
            libc::sigaction(libc::SIGINT, &self.previous_sigint, std::ptr::null_mut());
        }
    }
}

fn select(prompt: &str, items: &[impl AsRef<str>]) -> Result<Option<usize>> {
    let _guard = PromptGuard::new()?;
    Select::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .items(items.iter().map(AsRef::as_ref))
        .default(0)
        .max_length(14)
        .interact_opt()
        .map_err(prompt_error)
}

fn multi(prompt: &str, items: &[String], defaults: &[bool]) -> Result<Option<Vec<usize>>> {
    let _guard = PromptGuard::new()?;
    MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .items(items)
        .defaults(defaults)
        .max_length(14)
        .interact_opt()
        .map_err(prompt_error)
}

fn confirm(prompt: &str) -> Result<bool> {
    Ok(confirm_choice(prompt)?.unwrap_or(false))
}

fn confirm_choice(prompt: &str) -> Result<Option<bool>> {
    let _guard = PromptGuard::new()?;
    Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .default(false)
        .interact_opt()
        .map_err(prompt_error)
}

fn text(prompt: &str) -> Result<Option<String>> {
    let _guard = PromptGuard::new()?;
    let value: String = Input::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("{prompt} (empty cancels)"))
        .allow_empty(true)
        .report(false)
        .interact_text()
        .map_err(prompt_error)?;
    if value.is_empty() {
        Ok(None)
    } else {
        ensure!(
            !value.chars().any(char::is_control),
            "input must not contain control characters"
        );
        Ok(Some(value))
    }
}

fn input_path(project: &Path, prompt: &str) -> Result<Option<PathBuf>> {
    Ok(text(prompt)?.map(|value| {
        let path = PathBuf::from(value);
        if path.is_absolute() {
            path
        } else {
            project.join(path)
        }
    }))
}

fn escaped(value: &str) -> String {
    let mut label = String::new();
    for character in value.chars() {
        if character.is_control() || matches!(character, '\u{2028}' | '\u{2029}') {
            label.extend(character.escape_default());
        } else {
            label.push(character);
        }
    }
    label
}

fn path_label(path: &Path) -> String {
    format!("{:?}", path.as_os_str())
}

fn fresh_directory(root: &Path, purpose: &str) -> Result<PathBuf> {
    let millis = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).context("generate fresh interactive output path")?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(root
        .join("target/relship/interactive")
        .join(format!("{purpose}-{millis}-{suffix}")))
}

fn preview_menu(project: &Path) -> Result<()> {
    let root = source::root(project)?;
    if !root.join("release.toml").exists() {
        println!("This project has no release.toml. Open Project settings to initialize it.");
        return Ok(());
    }
    let schema = config_schema(&root)?;
    if schema == 4 {
        return catalog_ui::create_plan(&root);
    }
    let protocol = if schema == 3 {
        4
    } else if schema == 2 {
        match select(
            "Preview an execution plan",
            &[
                "Local execution (protocol 2)",
                "Worker assignment (protocol 3)",
                "Back",
            ],
        )? {
            Some(0) => 2,
            Some(1) => 3,
            _ => return Ok(()),
        }
    } else {
        1
    };
    println!("Resolving the committed source and release contract…");
    // Keep this exact snapshot through review, saving, and execution.
    let saved = match protocol {
        4 => serde_json::to_value(relship::delivery::plan::create(&root)?)?,
        3 => serde_json::to_value(cohort::plan::create(&root)?)?,
        2 => serde_json::to_value(v2::plan::create(&root)?)?,
        _ => serde_json::to_value(plan::create(&root)?)?,
    };
    show_plan(&saved)?;
    let build = loop {
        match select(
            "Reviewed plan — no files have been written",
            &[
                "Return to home",
                "Save this plan only",
                "Save and build this plan (runtime checks required)",
                "Inspect exact commands and complete plan JSON",
            ],
        )? {
            Some(1) => break false,
            Some(2) => break true,
            Some(3) => println!("{}", serde_json::to_string_pretty(&saved)?),
            _ => return Ok(()),
        }
    };
    let directory = fresh_directory(&root, "plan")?;
    let path = directory.join("plan.json");
    println!("Save exact reviewed plan: {}", path_label(&path));
    if !confirm("Write this immutable plan to a fresh file?")? {
        return Ok(());
    }
    write_new_json(&root, &path, &saved)?;
    println!("Saved plan: {}", path_label(&path));
    if !build {
        return Ok(());
    }
    let output = directory.join("attempt");
    if protocol == 4 {
        delivery_ui::worker_build(project, &path, &output, &saved)
    } else if protocol == 3 {
        worker_build(project, &path, &output, &saved)
    } else {
        println!("Build attempt: {}", path_label(&output));
        println!("Builds run the reviewed commands and required runtime/version checks.");
        if confirm("Build this saved plan now?")? {
            ensure_reviewed_plan(&path, &saved)?;
            run_command(
                project,
                Command::Rehearse {
                    plan: path,
                    output,
                    skip_runtime: false,
                    nfpm: None,
                    runtime: Default::default(),
                },
            )?;
        }
        Ok(())
    }
}

fn show_plan(saved: &Value) -> Result<()> {
    if saved["schema"] == 4 {
        return delivery_ui::show_plan(saved);
    }
    println!("\nSource-bound plan for review:");
    println!(
        "Plan: {}",
        saved["id"].as_str().context("missing plan identity")?
    );
    println!(
        "Source commit: {}",
        saved["source"]["commit"]
            .as_str()
            .context("missing source commit")?
    );
    println!("Execution protocol: {}", saved["schema"]);
    let artifacts = saved
        .get("units")
        .or_else(|| saved.get("outputs"))
        .and_then(Value::as_array)
        .context("missing planned artifacts")?;
    println!("Expected artifacts ({}):", artifacts.len());
    for artifact in artifacts {
        println!(
            "  {}",
            escaped(
                artifact["filename"]
                    .as_str()
                    .context("missing artifact filename")?
            )
        );
    }
    println!("Inspect the complete plan to review every build command, hook, target, and input.");
    println!(
        "Runtime checks remain enabled. Cross-target execution can fail when the host lacks a runner."
    );
    Ok(())
}

fn ensure_reviewed_plan(path: &Path, reviewed: &Value) -> Result<()> {
    let current: Value = v2::plan::read_json(path)?;
    ensure!(
        &current == reviewed,
        "saved plan changed after review; preview it again before execution"
    );
    Ok(())
}

fn unit_labels(plan: &cohort::model::Plan, units: &[usize]) -> Result<Vec<String>> {
    units
        .iter()
        .map(|index| {
            let unit = plan
                .units
                .get(*index)
                .context("assignment unit is out of range")?;
            let product = plan
                .config
                .products
                .get(unit.product)
                .context("unit product is out of range")?;
            let target = plan
                .config
                .targets
                .get(unit.target)
                .context("unit target is out of range")?;
            Ok(format!(
                "{} — {} / {} — {}",
                escaped(&unit.id),
                escaped(&product.id),
                escaped(&target.key()),
                escaped(&unit.filename)
            ))
        })
        .collect()
}

fn worker_build(project: &Path, path: &Path, output: &Path, reviewed: &Value) -> Result<()> {
    ensure_reviewed_plan(path, reviewed)?;
    let plan = cohort::plan::load(path)?;
    let units: Vec<_> = (0..plan.units.len()).collect();
    let labels = unit_labels(&plan, &units)?;
    let Some(selected) = multi(
        "Choose worker units (Space toggles)",
        &labels,
        &vec![true; labels.len()],
    )?
    else {
        return Ok(());
    };
    ensure!(!selected.is_empty(), "select at least one worker unit");
    let names: Vec<_> = selected.iter().map(|i| plan.units[*i].id.clone()).collect();
    let selected_labels: Vec<_> = selected.iter().map(|i| labels[*i].clone()).collect();
    println!(
        "Retry-safe permission allows an interrupted unit to be rerun later. Select only commands whose repeated side effects are safe."
    );
    let Some(retry) = multi(
        "Mark reviewed units retry-safe (none selected by default)",
        &selected_labels,
        &vec![false; selected.len()],
    )?
    else {
        return Ok(());
    };
    let retry_safe: Vec<_> = retry.iter().map(|i| names[*i].clone()).collect();
    let assignment = path.with_file_name("assignment.json");
    println!("Plan: {}", path_label(path));
    println!("Assignment: {}", path_label(&assignment));
    println!("Worker attempt: {}", path_label(output));
    println!("Units: {}", escaped(&names.join(", ")));
    println!("Retry-safe units: {}", escaped(&retry_safe.join(", ")));
    println!("Runtime checks: required. Worker output is unsigned preparation evidence.");
    if !confirm("Write this assignment and execute its selected units?")? {
        return Ok(());
    }
    ensure_reviewed_plan(path, reviewed)?;
    run_command(
        project,
        Command::Assign {
            plan: path.to_path_buf(),
            units: names,
            retry_safe,
            skip_runtime: false,
            output: assignment.clone(),
        },
    )?;
    ensure_reviewed_plan(path, reviewed)?;
    run_command(
        project,
        Command::Worker {
            nfpm: None,
            runtime: Default::default(),
            plan: path.to_path_buf(),
            assignment,
            output: output.to_path_buf(),
        },
    )
}

fn settings_menu(project: &Path) -> Result<()> {
    if !project.join("release.toml").exists() {
        return initialize_menu(project);
    }
    loop {
        if config_schema(project)? == 4 {
            return catalog_ui::settings_menu(project);
        }
        let document = settings::Document::load(project)?;
        println!(
            "\nSettings: {} (schema {})",
            path_label(document.path()),
            document.schema()
        );
        println!(
            "Targets: {}",
            escaped(&document.current_targets().join(", "))
        );
        for product in document.product_scopes() {
            println!(
                "Product {} [{}]: {} — {}",
                escaped(&product.product),
                product.builder,
                if product.explicit {
                    "explicit targets"
                } else {
                    "inherits global targets"
                },
                escaped(&product.targets.join(", "))
            );
        }
        let packaging_action = if document.schema() == 3 {
            "Choose package formats"
        } else {
            "Review upgrade to schema 3"
        };
        match select(
            "Project settings",
            &[
                "Back",
                "Edit operating systems / architectures / product target scopes",
                "Inspect capability catalog and package formats",
                "Run project doctor",
                packaging_action,
                "Review upgrade to catalog schema 4",
            ],
        )? {
            Some(1) => edit_settings(&document)?,
            Some(2) => show_catalog(document.schema()),
            Some(3) => run_command(project, Command::Doctor)?,
            Some(5) => catalog_ui::migrate_menu(project)?,
            Some(4) if document.schema() == 3 => delivery_ui::edit_formats(&document)?,
            Some(4) => delivery_ui::migrate(&document)?,
            _ => return Ok(()),
        }
    }
}

fn show_catalog(schema: u32) {
    println!("\nOperating systems:");
    show_capabilities(settings::operating_systems());
    println!("\nArchitectures (aliases resolve to canonical contract names):");
    show_capabilities(settings::architectures());
    println!("Bare ARM is ambiguous and cannot automatically select ARM64 or an ARM32 ABI.");
    println!("\nPackage formats:");
    if schema == 3 {
        delivery_ui::show_formats();
    } else {
        show_capabilities(settings::package_formats());
        println!(
            "Archive format is fixed by the target: Linux/macOS use tar.gz; Windows uses zip."
        );
        println!(
            "Schema 3 supports selectable archives and Linux native formats; review the explicit upgrade to use them."
        );
    }
}

fn show_capabilities(capabilities: &[settings::Capability]) {
    for capability in capabilities {
        if capability.available {
            println!("  {}: supported", capability.label);
        } else {
            println!(
                "  {}: unavailable — {}",
                capability.label,
                capability.reason.unwrap_or("No backend support")
            );
        }
    }
}

fn edit_settings(document: &settings::Document) -> Result<()> {
    let choices = document.target_choices();
    for choice in choices.iter().filter(|choice| !choice.available) {
        println!(
            "Unavailable {}: {}",
            escaped(&choice.key),
            escaped(choice.reason.as_deref().unwrap_or("No configured builder"))
        );
    }
    let available: Vec<_> = choices.iter().filter(|choice| choice.available).collect();
    let labels: Vec<_> = available
        .iter()
        .map(|choice| {
            format!(
                "{} [{}; {}]",
                escaped(&choice.key),
                choice.builders.join("/"),
                if document.schema() == 3 {
                    "formats configured separately"
                } else if choice.os == "windows" {
                    "zip"
                } else {
                    "tar.gz"
                }
            )
        })
        .collect();
    let defaults: Vec<_> = available.iter().map(|choice| choice.selected).collect();
    let Some(indices) = multi("Choose global targets (Space toggles)", &labels, &defaults)? else {
        return Ok(());
    };
    let selected: Vec<_> = indices
        .iter()
        .map(|index| available[*index].key.clone())
        .collect();
    ensure!(!selected.is_empty(), "select at least one target");
    let mut scopes = Vec::new();
    if document.schema() >= 2 {
        for scope in document.product_scopes() {
            println!("\nProduct {} [{}]", escaped(&scope.product), scope.builder);
            println!(
                "Current {}: {}",
                if scope.explicit {
                    "explicit targets"
                } else {
                    "inherited targets"
                },
                escaped(&scope.targets.join(", "))
            );
            let Some(action) = select(
                "Product target scope",
                &[
                    "Preserve current scope (intersect explicit targets with global selection)",
                    "Choose explicit targets for this product",
                    "Inherit all global targets (requires builder compatibility)",
                    "Cancel settings edit",
                ],
            )?
            else {
                return Ok(());
            };
            match action {
                0 => {}
                1 => {
                    let compatible: Vec<_> = selected
                        .iter()
                        .filter(|key| scope.compatible_targets.contains(key))
                        .cloned()
                        .collect();
                    ensure!(
                        !compatible.is_empty(),
                        "product {} has no compatible selected target",
                        scope.product
                    );
                    let defaults: Vec<_> = compatible
                        .iter()
                        .map(|key| scope.targets.contains(key))
                        .collect();
                    let labels: Vec<_> = compatible.iter().map(|key| escaped(key)).collect();
                    let Some(indices) = multi("Explicit product targets", &labels, &defaults)?
                    else {
                        return Ok(());
                    };
                    ensure!(
                        !indices.is_empty(),
                        "explicit product scope needs at least one target"
                    );
                    scopes.push(settings::ProductSelection {
                        product: scope.product,
                        targets: Some(indices.iter().map(|i| compatible[*i].clone()).collect()),
                    });
                }
                2 => scopes.push(settings::ProductSelection {
                    product: scope.product,
                    targets: None,
                }),
                _ => return Ok(()),
            }
        }
    }
    let proposal = document.proposal_with_scopes(&selected, &scopes)?;
    if !proposal.changed() {
        println!("No settings changed.");
        return Ok(());
    }
    println!("\nReview release.toml changes (complete before/after; control characters escaped):");
    show_document("--- current release.toml", proposal.old_text());
    show_document("+++ proposed release.toml", proposal.new_text());
    for change in proposal.product_changes() {
        println!(
            "Product {}: {} [{}] -> {} [{}]",
            escaped(&change.product),
            if change.old_explicit {
                "explicit"
            } else {
                "inherited"
            },
            escaped(&change.old_targets.join(", ")),
            if change.new_explicit {
                "explicit"
            } else {
                "inherited"
            },
            escaped(&change.new_targets.join(", "))
        );
    }
    if document.schema() == 3 {
        println!("Package formats, resources and hooks remain in the reviewed contract.");
    } else {
        println!(
            "Archive formats: Linux/macOS tar.gz; Windows zip. Resources and hooks remain in the reviewed contract."
        );
    }
    println!(
        "Saving changes requires your subsequent review and commit before source-bound planning."
    );
    if confirm("Save exactly this release.toml proposal?")? {
        document.save(&proposal)?;
        println!(
            "Saved {}. Review and commit the contract before planning; relship does not commit it.",
            path_label(document.path())
        );
    }
    Ok(())
}

fn show_document(label: &str, document: &str) {
    println!("{label}");
    for (index, line) in document.lines().enumerate() {
        println!("{:4} | {}", index + 1, escaped(line));
    }
}

fn initialize_menu(project: &Path) -> Result<()> {
    println!("No release.toml exists in {}.", path_label(project));
    println!("Initialize a schema 3 contract from one Rust Cargo workspace or Go module.");
    let builder = match select("Project builder", &["Back", "Rust", "Go"])? {
        Some(1) => "rust",
        Some(2) => "go",
        _ => return Ok(()),
    };
    let Some(directory) = text("Builder directory relative to the project (use . for root)")?
    else {
        return Ok(());
    };
    let version = if builder == "go" {
        let Some(version) = text("Application version (not the Go toolchain version)")? else {
            return Ok(());
        };
        Some(version)
    } else {
        None
    };
    println!(
        "\nNew contract: {}",
        path_label(&project.join("release.toml"))
    );
    println!(
        "Schema: 3; builder: {builder}; directory: {}",
        escaped(&directory)
    );
    if let Some(version) = &version {
        println!("Application version: {}", escaped(version));
    }
    println!("Existing initialization discovers products and selects supported host targets.");
    println!(
        "Review the generated contract, resources, hooks, target scopes, and then commit it before planning."
    );
    if confirm("Create release.toml without overwriting an existing file?")? {
        run_command(
            project,
            Command::Init {
                builder: Some(builder.into()),
                directory,
                app_version: version,
                schema: Some(3),
            },
        )?;
        return settings_menu(project);
    }
    Ok(())
}

fn tasks_menu(project: &Path) -> Result<()> {
    let Some(output) = input_path(project, "Attempt or collection directory")? else {
        return Ok(());
    };
    println!("Attempt: {}", path_label(&output));
    if output.join("collection.json").exists() {
        let collection: Value = v2::plan::read_json(&output.join("collection.json"))?;
        println!(
            "Saved collection:\n{}",
            serde_json::to_string_pretty(&collection)?
        );
    } else {
        run_command(
            project,
            Command::Status {
                output: output.clone(),
                json: false,
            },
        )?;
    }
    loop {
        let protocol = if output.join("plan.json").exists() {
            super::json_schema(&output.join("plan.json"))?
        } else {
            0
        };
        let resumable = matches!(protocol, 3..=5) && output.join("assignment.json").exists();
        let mut actions = vec![
            "Back",
            "Show saved status",
            "Verify against matching source",
        ];
        if resumable {
            actions.push(if protocol == 5 {
                "Resume protocol 5 attempt"
            } else if protocol == 4 {
                "Resume protocol 4 attempt"
            } else {
                "Resume protocol 3 attempt"
            });
        } else {
            println!(
                "Resume is available for protocol 3/4/5 worker/rebuild attempts; schema 1/2 attempts require a fresh build."
            );
        }
        match select("Task actions", &actions)? {
            Some(1) => {
                if output.join("collection.json").exists() {
                    let collection: Value = v2::plan::read_json(&output.join("collection.json"))?;
                    println!("{}", serde_json::to_string_pretty(&collection)?);
                } else {
                    run_command(
                        project,
                        Command::Status {
                            output: output.clone(),
                            json: false,
                        },
                    )?;
                }
            }
            Some(2) => {
                println!(
                    "Verification requires the original matching source checkout and checks the saved exact inputs and artifact bytes."
                );
                let policy = if output.join("collection.json").exists() {
                    let Some(path) = input_path(project, "Trusted merge policy file")? else {
                        continue;
                    };
                    Some(path)
                } else {
                    None
                };
                run_command(
                    project,
                    Command::Verify {
                        output: output.clone(),
                        policy,
                    },
                )?;
            }
            Some(3) if resumable && protocol == 5 => catalog_ui::resume_attempt(project, &output)?,
            Some(3) if resumable && protocol == 4 => delivery_ui::resume_attempt(project, &output)?,
            Some(3) if resumable => resume_attempt(project, &output)?,
            _ => return Ok(()),
        }
    }
}

fn resume_attempt(project: &Path, output: &Path) -> Result<()> {
    let plan = cohort::plan::load(&output.join("plan.json"))?;
    let assignment: cohort::model::Assignment =
        cohort::io::read_json(&output.join("assignment.json"))?;
    cohort::plan::validate_assignment(&plan, &assignment)?;
    let receipt = cohort::run::status(output)?;
    ensure!(
        receipt.plan_id == plan.id && receipt.assignment_id == assignment.id,
        "receipt belongs to a different plan or assignment"
    );
    println!(
        "Source commit: {}; engine: {}",
        plan.source.commit, plan.engine_source_id
    );
    println!("Plan: {}; assignment: {}", plan.id, assignment.id);
    println!("Assigned units (completed checkpoints are rechecked):");
    for label in unit_labels(&plan, &assignment.units)? {
        println!("  {label}");
    }
    println!(
        "Runtime checks: {}",
        if assignment.skip_runtime {
            "skipped by the saved assignment; output remains build-only"
        } else {
            "required by the saved assignment"
        }
    );
    println!(
        "Resume rechecks completed checkpoints and matching source. Retry permission can rerun incomplete units and their side effects."
    );
    if !assignment.retry_safe_units.is_empty() {
        println!("Already approved retry-safe units (no new permission required):");
        for label in unit_labels(&plan, &assignment.retry_safe_units)? {
            println!("  {label}");
        }
    }
    let retry_units: Vec<_> = assignment
        .units
        .iter()
        .copied()
        .filter(|unit| {
            !receipt.units.contains_key(unit) && !assignment.retry_safe_units.contains(unit)
        })
        .collect();
    let labels = unit_labels(&plan, &retry_units)?;
    let allow_retry = if labels.is_empty() {
        println!(
            "No incomplete units need additional retry permission according to the saved receipt. Completed checkpoints will be rechecked."
        );
        Vec::new()
    } else {
        let Some(indices) = multi(
            "Allow retry for reviewed units (none selected)",
            &labels,
            &vec![false; labels.len()],
        )?
        else {
            return Ok(());
        };
        indices
            .iter()
            .map(|i| plan.units[retry_units[*i]].id.clone())
            .collect()
    };
    let key = if let Some(public) = &assignment.trusted_key {
        println!("Trusted rebuild assignment key: {}", escaped(public));
        let Some(key) = input_path(project, "Matching private signing-key file")? else {
            return Ok(());
        };
        Some(key)
    } else {
        None
    };
    println!("Resume attempt: {}", path_label(output));
    println!("Allow retry: {}", escaped(&allow_retry.join(", ")));
    if confirm("Resume this attempt with these explicit retry permissions?")? {
        let current_assignment: cohort::model::Assignment =
            cohort::io::read_json(&output.join("assignment.json"))?;
        ensure!(
            cohort::plan::load(&output.join("plan.json"))? == plan
                && current_assignment == assignment,
            "saved plan or assignment changed after review; inspect it again before resuming"
        );
        run_command(
            project,
            Command::Resume {
                nfpm: None,
                runtime: Default::default(),
                output: output.to_path_buf(),
                allow_retry,
                key,
            },
        )?;
    }
    Ok(())
}

fn accounts_menu(project: &Path, selected: &mut Option<String>) -> Result<()> {
    loop {
        println!(
            "\nCredential selection for this interactive session: {}",
            selected
                .as_deref()
                .map(escaped)
                .unwrap_or_else(|| "environment credentials".into())
        );
        println!(
            "Stored-account selection does not change gh's active account or persist credentials."
        );
        match select(
            "Accounts",
            &[
                "Back",
                "List and select a stored GitHub account",
                "Use environment credentials",
                "Check selected credential identity / repository access",
            ],
        )? {
            Some(1) => {
                let accounts = github::auth::accounts()?;
                let mut labels = vec!["Keep current session selection".to_owned()];
                labels.extend(accounts.iter().map(|account| {
                    format!(
                        "{} @ {} — {}{}",
                        escaped(&account.login),
                        escaped(&account.host),
                        escaped(&account.state),
                        if account.active { "; gh active" } else { "" }
                    )
                }));
                if accounts.is_empty() {
                    println!(
                        "No stored github.com accounts. Sign in separately with gh auth login --hostname github.com."
                    );
                }
                if let Some(index) = select("Stored accounts (safe metadata only)", &labels)?
                    && index > 0
                {
                    *selected = Some(accounts[index - 1].login.clone());
                }
            }
            Some(2) => *selected = None,
            Some(3) => {
                let repository = match select(
                    "Identity check",
                    &[
                        "Back",
                        "User identity only",
                        "Check a specific repository (supports scoped/App credentials)",
                    ],
                )? {
                    Some(1) => None,
                    Some(2) => {
                        let Some(repository) = text("GitHub repository owner/repo")? else {
                            continue;
                        };
                        Some(repository)
                    }
                    _ => continue,
                };
                run_command(
                    project,
                    Command::Github {
                        account: selected.clone(),
                        command: GithubCommand::Auth {
                            command: GithubAuthCommand::Status {
                                repo: repository,
                                json: false,
                            },
                        },
                    },
                )?;
            }
            _ => return Ok(()),
        }
    }
}

fn github_menu(project: &Path, account: Option<&str>) -> Result<()> {
    loop {
        println!(
            "\nGitHub credential: {}",
            account
                .map(escaped)
                .unwrap_or_else(|| "environment credentials".into())
        );
        println!("Draft preparation only. Publication remains a separate manual action.");
        match select(
            "GitHub drafts",
            &[
                "Back",
                "Plan a new draft (read-only remote queries)",
                "Review and stage an existing saved plan",
                "Inspect / verify / resume an existing draft attempt",
            ],
        )? {
            Some(1) => github_plan(project, account)?,
            Some(2) => {
                let Some(path) = input_path(project, "Saved GitHub draft plan file")? else {
                    continue;
                };
                let Some(collection) = input_path(project, "Verified collection directory")? else {
                    continue;
                };
                let Some(policy) = input_path(project, "Trusted merge policy file")? else {
                    continue;
                };
                stage_plan(project, account, &path, &collection, &policy)?;
            }
            Some(3) => github_attempt(project, account)?,
            _ => return Ok(()),
        }
    }
}

fn github_plan(project: &Path, account: Option<&str>) -> Result<()> {
    let Some(collection) = input_path(
        project,
        "Verified collection directory (protocol 3, 4 or 5)",
    )?
    else {
        return Ok(());
    };
    let Some(policy) = input_path(project, "Trusted merge policy file")? else {
        return Ok(());
    };
    let Some(repo) = text("GitHub repository owner/repo")? else {
        return Ok(());
    };
    github::plan::repository_name(&repo)?;
    let Some(tag) = text("Exact release tag")? else {
        return Ok(());
    };
    github::plan::tag_name(&tag)?;
    let Some(create_tag_if_missing) =
        confirm_choice("Allow the later stage action to create this exact tag if missing?")?
    else {
        return Ok(());
    };
    let Some(prerelease) = confirm_choice("Mark the draft as a prerelease?")? else {
        return Ok(());
    };
    let root = source::root(project)?;
    let output = fresh_directory(&root, "github-plan")?.join("draft-plan.json");
    println!(
        "\nRead-only GitHub plan: {} / {}",
        escaped(&repo),
        escaped(&tag)
    );
    println!("Collection: {}", path_label(&collection));
    println!("Policy: {}", path_label(&policy));
    println!(
        "Credential: {}",
        account
            .map(escaped)
            .unwrap_or_else(|| "environment credentials".into())
    );
    println!("Save plan: {}", path_label(&output));
    if !confirm("Query GitHub read-only and save a new draft plan?")? {
        return Ok(());
    }
    run_command(
        project,
        Command::Github {
            account: account.map(str::to_owned),
            command: GithubCommand::Plan {
                collection: collection.clone(),
                policy: policy.clone(),
                repo,
                tag,
                create_tag_if_missing,
                title: None,
                notes_file: None,
                prerelease,
                output: output.clone(),
            },
        },
    )?;
    stage_plan(project, account, &output, &collection, &policy)
}

fn show_github_plan(path: &Path, account: Option<&str>) -> Result<github::model::Plan> {
    let saved = github::plan::load(path)?;
    println!("\nSaved GitHub draft plan: {}", path_label(path));
    println!("Plan: {}", saved.id);
    println!(
        "Repository: {} (id {})",
        escaped(&saved.repository.full_name),
        saved.repository.id
    );
    println!(
        "Tag: {}; source commit: {}",
        escaped(&saved.tag),
        saved.source_commit
    );
    println!(
        "Collection: {}; policy: {}",
        saved.collection_id, saved.policy_id
    );
    println!(
        "Credential: {}",
        account
            .map(escaped)
            .unwrap_or_else(|| "environment credentials".into())
    );
    println!(
        "Create missing lightweight tag at bound source: {}",
        if saved.create_tag_if_missing {
            "allowed"
        } else {
            "forbidden"
        }
    );
    println!(
        "Title: {}; prerelease: {}",
        escaped(&saved.title),
        saved.prerelease
    );
    println!("Notes: {}", escaped(&saved.notes));
    println!("Assets (exact filenames / bytes / SHA-256):");
    for asset in &saved.assets {
        println!(
            "  {} / {} / {}",
            escaped(&asset.name),
            asset.size,
            asset.sha256
        );
    }
    Ok(saved)
}

fn stage_plan(
    project: &Path,
    account: Option<&str>,
    path: &Path,
    collection: &Path,
    policy: &Path,
) -> Result<()> {
    let saved = show_github_plan(path, account)?;
    println!("Collection directory: {}", path_label(collection));
    println!("Trusted policy file: {}", path_label(policy));
    let root = source::root(project)?;
    let output = fresh_directory(&root, "github-attempt")?;
    println!("Local attempt: {}", path_label(&output));
    println!(
        "Remote effect: create a GitHub draft, upload the listed assets, and create a missing tag only when this saved plan allows it."
    );
    if confirm("Create this remote draft using exactly the saved plan?")? {
        if let Some(account) = account {
            eprintln!("GitHub credential account: {account} (gh; identity checked)");
        }
        // Pass the reviewed object to the same core operation used by Stage;
        // reopening the path after approval could select a different plan.
        let receipt = if super::json_schema(&collection.join("collection.json"))? == 5 {
            let policy = super::catalog_cli::load_policy(policy)?;
            let mut api = github::auth::client(account)?;
            github::run::stage_v5(&root, collection, &policy, &saved, &output, &mut api)?
        } else {
            let policy = cohort::crypto::load_policy(policy)?;
            let mut api = github::auth::client(account)?;
            github::run::stage(&root, collection, &policy, &saved, &output, &mut api)?
        };
        println!("{}", serde_json::to_string_pretty(&receipt)?);
    }
    Ok(())
}

fn github_attempt(project: &Path, account: Option<&str>) -> Result<()> {
    let Some(output) = input_path(project, "Existing GitHub draft attempt directory")? else {
        return Ok(());
    };
    run_command(
        project,
        Command::Github {
            account: account.map(str::to_owned),
            command: GithubCommand::Status {
                output: output.clone(),
                json: false,
            },
        },
    )?;
    loop {
        match select(
            "Draft attempt actions",
            &[
                "Back",
                "Show saved status (offline)",
                "Verify remote draft and exact asset bytes (read-only)",
                "Resume unfinished draft uploads",
            ],
        )? {
            Some(1) => run_command(
                project,
                Command::Github {
                    account: account.map(str::to_owned),
                    command: GithubCommand::Status {
                        output: output.clone(),
                        json: false,
                    },
                },
            )?,
            Some(action @ (2 | 3)) => {
                let Some(collection) = input_path(project, "Verified collection directory")? else {
                    continue;
                };
                let Some(policy) = input_path(project, "Trusted merge policy file")? else {
                    continue;
                };
                let plan_path = output.join("plan.json");
                let reviewed = show_github_plan(&plan_path, account)?;
                println!("Collection directory: {}", path_label(&collection));
                println!("Trusted policy file: {}", path_label(&policy));
                if action == 2 {
                    run_command(
                        project,
                        Command::Github {
                            account: account.map(str::to_owned),
                            command: GithubCommand::Verify {
                                collection,
                                policy,
                                output: output.clone(),
                            },
                        },
                    )?;
                } else {
                    println!(
                        "Resume reconciles remote state and can create missing draft state or continue uploads."
                    );
                    let receipt = github::run::status(&output)?;
                    let retry_create_draft = if receipt
                        .pending
                        .as_ref()
                        .is_some_and(|intent| intent.operation == "create_draft")
                    {
                        println!(
                            "Draft creation has an uncertain outcome. Review GitHub for an existing draft before authorizing a retry."
                        );
                        let Some(permit) = confirm_choice(
                            "Explicitly permit retry of the uncertain draft creation?",
                        )?
                        else {
                            continue;
                        };
                        permit
                    } else {
                        false
                    };
                    if confirm("Resume remote writes for this saved draft attempt?")? {
                        ensure!(
                            github::plan::load(&plan_path)? == reviewed,
                            "saved draft plan changed after review; inspect it again before resuming"
                        );
                        run_command(
                            project,
                            Command::Github {
                                account: account.map(str::to_owned),
                                command: GithubCommand::Resume {
                                    collection,
                                    policy,
                                    output: output.clone(),
                                    retry_create_draft,
                                },
                            },
                        )?;
                    }
                }
            }
            _ => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_labels_escape_control_characters() {
        assert_eq!(escaped("a\x1b[31m\nb\t"), "a\\u{1b}[31m\\nb\\t");
        assert!(!path_label(Path::new("a\nb")).contains('\n'));
        assert_eq!(escaped("项目/发布\n"), "项目/发布\\n");
    }

    #[test]
    fn prompt_interruption_remains_an_io_error_for_exit_handling() {
        let error = prompt_error(dialoguer::Error::IO(io::Error::new(
            io::ErrorKind::Interrupted,
            "interrupted",
        )));
        assert!(interrupted(&error));
        let error = prompt_error(dialoguer::Error::IO(io::Error::new(
            io::ErrorKind::NotConnected,
            "not a terminal",
        )));
        assert!(!interrupted(&error));
    }

    #[test]
    fn generated_paths_are_fresh_and_below_target() {
        let root = Path::new("/example/project");
        let first = fresh_directory(root, "plan").unwrap();
        let second = fresh_directory(root, "plan").unwrap();
        assert!(first.starts_with(root.join("target/relship/interactive")));
        assert_ne!(first, second);
        assert!(!first.exists());
    }

    #[test]
    fn replacing_a_saved_plan_after_review_blocks_execution() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("plan.json");
        let reviewed = serde_json::json!({"schema": 3, "id": "reviewed-source"});
        std::fs::write(&path, serde_json::to_vec(&reviewed).unwrap()).unwrap();
        ensure_reviewed_plan(&path, &reviewed).unwrap();
        std::fs::write(&path, br#"{"schema":3,"id":"other-source"}"#).unwrap();
        assert!(ensure_reviewed_plan(&path, &reviewed).is_err());
    }
}
