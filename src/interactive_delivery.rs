use super::{
    Command, confirm, ensure_reviewed_plan, escaped, input_path, multi, path_label, run_command,
    select, show_document, text,
};
use anyhow::{Context, Result, ensure};
use relship::{
    cohort, delivery,
    delivery::model::{Config, Format, NativeMetadata, Plan},
    settings,
};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};
use toml_edit::{Array, DocumentMut, InlineTable, Item, TableLike, Value as TomlValue};

const ALL_FORMATS: &[Format] = &[
    Format::TarGz,
    Format::Zip,
    Format::Deb,
    Format::Rpm,
    Format::Apk,
    Format::Pacman,
    Format::Ipk,
];

pub(super) fn show_formats() {
    println!("  tar.gz / zip: selectable on Linux, macOS and Windows");
    println!("  deb / rpm / APK v2 / pacman / ipk: selectable on Linux (nFPM 2.49.0)");
    println!("  pkg / dmg / msi / msix / exe installer: unavailable");
    println!(
        "Defaults: Linux/macOS tar.gz; Windows zip. Each product may replace an OS list in full."
    );
}

pub(super) fn migrate(document: &settings::Document) -> Result<()> {
    let migration = delivery::migrate::propose_text(document.text())?;
    println!(
        "Explicit contract upgrade: schema {} -> {}. Existing targets, product scopes and archive defaults are preserved.",
        migration.from_schema, migration.to_schema
    );
    for warning in &migration.warnings {
        println!("Warning: {}", escaped(warning));
    }
    let proposal = document.proposal_text(migration.proposed)?;
    review_save(document, &proposal)
}

fn review_save(document: &settings::Document, proposal: &settings::Proposal) -> Result<()> {
    if !proposal.changed() {
        println!("No settings changed.");
        return Ok(());
    }
    println!("\nReview release.toml changes (complete before/after; control characters escaped):");
    show_document("--- current release.toml", proposal.old_text());
    show_document("+++ proposed release.toml", proposal.new_text());
    println!(
        "Review and commit the contract before source-bound planning; relship does not commit it."
    );
    if confirm("Save exactly this release.toml proposal?")? {
        document.save(proposal)?;
        println!(
            "Saved {}. Review and commit the contract before planning.",
            path_label(document.path())
        );
    }
    Ok(())
}

fn format_names(formats: &[Format]) -> String {
    formats
        .iter()
        .map(|f| f.name())
        .collect::<Vec<_>>()
        .join(", ")
}

fn defaults(config: &Config, os: &str) -> Vec<Format> {
    config
        .packaging
        .formats
        .get(os)
        .cloned()
        .unwrap_or_else(|| {
            vec![if os == "windows" {
                Format::Zip
            } else {
                Format::TarGz
            }]
        })
}

fn child_table<'a>(table: &'a mut dyn TableLike, key: &str) -> Result<&'a mut dyn TableLike> {
    if !table.contains_key(key) {
        table.insert(key, Item::Value(TomlValue::InlineTable(InlineTable::new())));
    }
    table
        .get_mut(key)
        .and_then(Item::as_table_like_mut)
        .with_context(|| format!("{key} must be a TOML table"))
}

fn product_table(doc: &mut DocumentMut, index: usize) -> Result<&mut dyn TableLike> {
    match doc.get_mut("products").context("missing products")? {
        Item::ArrayOfTables(tables) => tables
            .get_mut(index)
            .map(|table| table as &mut dyn TableLike)
            .context("missing product table"),
        Item::Value(TomlValue::Array(values)) => values
            .get_mut(index)
            .and_then(TomlValue::as_inline_table_mut)
            .map(|table| table as &mut dyn TableLike)
            .context("product must be a TOML table"),
        _ => anyhow::bail!("products must be an array of tables"),
    }
}

fn replace(table: &mut dyn TableLike, key: &str, mut value: TomlValue) {
    if let Some(old) = table.get(key).and_then(Item::as_value) {
        *value.decor_mut() = old.decor().clone();
    }
    table.insert(key, Item::Value(value));
}

fn set_formats(table: &mut dyn TableLike, os: &str, formats: &[Format]) -> Result<()> {
    let formats_table = child_table(child_table(table, "packaging")?, "formats")?;
    let mut array = Array::new();
    for format in formats {
        array.push(format.name());
    }
    replace(formats_table, os, TomlValue::Array(array));
    Ok(())
}

fn has_os(config: &Config, product: usize, os: &str) -> bool {
    let product = &config.products[product];
    config.targets.iter().any(|target| {
        target.os == os && (product.targets.is_empty() || product.targets.contains(&target.key()))
    })
}

fn prompt_native(product: &str) -> Result<Option<NativeMetadata>> {
    println!(
        "Native package metadata for {}. Enter the actual project values.",
        escaped(product)
    );
    let Some(name) = text("Native package name (lowercase package identifier)")? else {
        return Ok(None);
    };
    delivery::config::package_name(&name)?;
    let Some(description) = text("Package description")? else {
        return Ok(None);
    };
    let Some(license) = text("Package license")? else {
        return Ok(None);
    };
    let Some(maintainer) = text("Package maintainer")? else {
        return Ok(None);
    };
    let homepage = match select(
        "Package homepage",
        &["Omit homepage", "Enter homepage", "Cancel settings edit"],
    )? {
        Some(0) => None,
        Some(1) => {
            let Some(homepage) = text("Package homepage URL")? else {
                return Ok(None);
            };
            Some(homepage)
        }
        _ => return Ok(None),
    };
    Ok(Some(NativeMetadata {
        name: Some(name),
        description,
        license,
        maintainer,
        homepage,
        dependencies: BTreeMap::new(),
        install: Vec::new(),
    }))
}

pub(super) fn edit_formats(document: &settings::Document) -> Result<()> {
    let original: Config = toml::from_str(document.text())?;
    delivery::config::validate(&original)?;
    show_formats();
    let mut scopes = vec![
        "Back".to_string(),
        "Global defaults per operating system".into(),
    ];
    scopes.extend(
        original
            .products
            .iter()
            .map(|p| format!("Product {}", escaped(&p.id))),
    );
    let product = match select("Package format scope", &scopes)? {
        Some(1) => None,
        Some(index) if index >= 2 => Some(index - 2),
        _ => return Ok(()),
    };
    let os = match select(
        "Operating system for package formats",
        &["Back", "Linux", "macOS", "Windows"],
    )? {
        Some(1) => "linux",
        Some(2) => "macos",
        Some(3) => "windows",
        _ => return Ok(()),
    };
    let current = product.map_or_else(
        || defaults(&original, os),
        |index| delivery::config::effective_formats(&original, index, os),
    );
    println!("Current {} formats: {}", os, format_names(&current));
    let inherit = if let Some(index) = product {
        println!(
            "Product {}: {}",
            escaped(&original.products[index].id),
            if original.products[index].packaging.formats.contains_key(os) {
                "explicit OS list"
            } else {
                "inherits global OS list"
            }
        );
        match select(
            "Product format override",
            &[
                "Choose explicit formats (replaces the complete OS list)",
                "Inherit global formats",
                "Cancel settings edit",
            ],
        )? {
            Some(0) => false,
            Some(1) => true,
            _ => return Ok(()),
        }
    } else {
        false
    };
    let mut config = original.clone();
    let mut doc = document.text().parse::<DocumentMut>()?;
    if inherit {
        let index = product.context("inherit requires a product")?;
        config.products[index].packaging.formats.remove(os);
        let table = product_table(&mut doc, index)?;
        if let Some(packaging) = table.get_mut("packaging").and_then(Item::as_table_like_mut)
            && let Some(formats) = packaging
                .get_mut("formats")
                .and_then(Item::as_table_like_mut)
        {
            formats.remove(os);
        }
    } else {
        let available: Vec<_> = ALL_FORMATS
            .iter()
            .copied()
            .filter(|f| os == "linux" || !f.is_native())
            .collect();
        let labels = available
            .iter()
            .map(|f| {
                if *f == Format::Apk {
                    "apk (APK v2)".into()
                } else {
                    f.name().into()
                }
            })
            .collect::<Vec<String>>();
        let selected = available
            .iter()
            .map(|f| current.contains(f))
            .collect::<Vec<_>>();
        let Some(indices) = multi("Choose package formats (Space toggles)", &labels, &selected)?
        else {
            return Ok(());
        };
        ensure!(
            !indices.is_empty(),
            "select at least one package format; empty lists are not permitted"
        );
        let formats: Vec<_> = indices.iter().map(|i| available[*i]).collect();
        if let Some(index) = product {
            config.products[index]
                .packaging
                .formats
                .insert(os.into(), formats.clone());
            set_formats(product_table(&mut doc, index)?, os, &formats)?;
        } else {
            config.packaging.formats.insert(os.into(), formats.clone());
            set_formats(doc.as_table_mut(), os, &formats)?;
        }
    }
    println!("Affected products for {os}:");
    if !(0..config.products.len()).any(|index| has_os(&config, index, os)) {
        println!(
            "  No products currently target this OS; this list applies when matching targets are selected."
        );
    }
    for index in 0..config.products.len() {
        if !has_os(&config, index, os) {
            continue;
        }
        let before = delivery::config::effective_formats(&original, index, os);
        let after = delivery::config::effective_formats(&config, index, os);
        println!(
            "  {}: [{}] -> [{}]{}",
            escaped(&config.products[index].id),
            format_names(&before),
            format_names(&after),
            if before == after { " (unchanged)" } else { "" }
        );
        let native_needed = has_os(&config, index, "linux")
            && delivery::config::effective_formats(&config, index, "linux")
                .iter()
                .any(|f| f.is_native());
        if native_needed && config.products[index].packaging.native.is_none() {
            let Some(native) = prompt_native(&config.products[index].id)? else {
                return Ok(());
            };
            let table = child_table(
                child_table(product_table(&mut doc, index)?, "packaging")?,
                "native",
            )?;
            for (key, value) in [
                ("name", native.name.as_deref().unwrap()),
                ("description", &native.description),
                ("license", &native.license),
                ("maintainer", &native.maintainer),
            ] {
                replace(table, key, TomlValue::from(value));
            }
            if let Some(homepage) = &native.homepage {
                replace(table, "homepage", TomlValue::from(homepage.as_str()));
            }
            config.products[index].packaging.native = Some(native);
        }
    }
    delivery::config::validate(&config)?;
    let proposal = document.proposal_text(doc.to_string())?;
    review_save(document, &proposal)
}

pub(super) fn show_plan(saved: &Value) -> Result<()> {
    let plan: Plan = serde_json::from_value(saved.clone())?;
    println!("\nSource-bound plan for review:");
    println!("Plan: {}", plan.id);
    println!("Source commit: {}", plan.source.commit);
    println!("Execution protocol: 4");
    println!(
        "Build units: {}; expected packages: {}",
        plan.builds.len(),
        plan.packages.len()
    );
    for package in &plan.packages {
        let build = &plan.builds[package.build];
        println!(
            "  {} — {} / {} — format {}",
            escaped(&package.filename),
            escaped(&plan.config.products[build.product].id),
            escaped(&plan.config.targets[build.target].key()),
            package.format.name()
        );
        if let Some(native_version) = &package.native_version {
            println!(
                "    Native version: {} -> {} (release {})",
                escaped(&plan.resolved[build.product].version),
                escaped(native_version),
                package.metadata.release
            );
        }
    }
    println!("Each build produces one payload shared by its selected package formats.");
    println!("Inspect the complete plan to review every build command, hook, target, and input.");
    println!(
        "Runtime checks remain enabled. Cross-target execution can fail when the host lacks a runner."
    );
    Ok(())
}

fn build_labels(plan: &Plan, units: &[usize]) -> Result<Vec<String>> {
    units
        .iter()
        .map(|index| {
            let build = plan
                .builds
                .get(*index)
                .context("assignment build is out of range")?;
            let packages: Vec<_> = plan
                .packages
                .iter()
                .filter(|p| p.build == *index)
                .map(|p| p.format.name())
                .collect();
            Ok(format!(
                "{} — {} / {} — {}",
                escaped(&build.id),
                escaped(&plan.config.products[build.product].id),
                escaped(&plan.config.targets[build.target].key()),
                packages.join(", ")
            ))
        })
        .collect()
}

fn choose_nfpm(
    project: &Path,
    plan: &Plan,
    units: &[usize],
) -> Result<Option<Option<std::path::PathBuf>>> {
    if !plan
        .packages
        .iter()
        .any(|p| units.contains(&p.build) && p.format.is_native())
    {
        return Ok(Some(None));
    }
    println!("Selected native packages require the pinned nFPM 2.49.0 backend.");
    let requested = match select(
        "Native packaging backend",
        &[
            "Cancel build / resume",
            "Use nFPM from PATH",
            "Choose an explicit nFPM executable file",
        ],
    )? {
        Some(1) => None,
        Some(2) => {
            let Some(path) = input_path(project, "nFPM executable file")? else {
                return Ok(None);
            };
            Some(path)
        }
        _ => return Ok(None),
    };
    let tool = delivery::native::resolve_nfpm(requested.as_deref())?;
    println!(
        "Native backend: {} (version {}; SHA-256 {})",
        path_label(&tool.path),
        tool.version,
        tool.sha256
    );
    Ok(Some(Some(tool.path)))
}

pub(super) fn worker_build(
    project: &Path,
    path: &Path,
    output: &Path,
    reviewed: &Value,
) -> Result<()> {
    ensure_reviewed_plan(path, reviewed)?;
    let plan = delivery::plan::load(path)?;
    let units: Vec<_> = (0..plan.builds.len()).collect();
    let labels = build_labels(&plan, &units)?;
    let Some(selected) = multi(
        "Choose build units (Space toggles)",
        &labels,
        &vec![true; labels.len()],
    )?
    else {
        return Ok(());
    };
    ensure!(!selected.is_empty(), "select at least one build unit");
    let selected_labels: Vec<_> = selected.iter().map(|i| labels[*i].clone()).collect();
    println!(
        "Retry-safe permission allows interrupted builds and their hooks to run again. Select only commands whose repeated side effects are safe."
    );
    let Some(retry) = multi(
        "Mark reviewed builds retry-safe (none selected by default)",
        &selected_labels,
        &vec![false; selected.len()],
    )?
    else {
        return Ok(());
    };
    let retry_units = retry.iter().map(|i| selected[*i]).collect::<Vec<_>>();
    let assignment = delivery::run::assignment(
        &plan,
        &delivery::run::RunOptions {
            units: selected.clone(),
            retry_safe_units: retry_units.clone(),
            ..Default::default()
        },
    )?;
    let Some(nfpm) = choose_nfpm(project, &plan, &selected)? else {
        return Ok(());
    };
    let assignment_path = path.with_file_name("assignment.json");
    println!("Plan: {}", path_label(path));
    println!("Assignment: {}", path_label(&assignment_path));
    println!("Worker attempt: {}", path_label(output));
    println!("Runtime checks: required. Completed payloads can be reused for package retries.");
    println!(
        "Reviewed assignment:\n{}",
        serde_json::to_string_pretty(&assignment)?
    );
    if !confirm("Write this assignment and execute its selected builds and packages?")? {
        return Ok(());
    }
    ensure_reviewed_plan(path, reviewed)?;
    run_command(
        project,
        Command::Assign {
            plan: path.to_path_buf(),
            units: selected
                .iter()
                .map(|i| plan.builds[*i].id.clone())
                .collect(),
            retry_safe: retry_units
                .iter()
                .map(|i| plan.builds[*i].id.clone())
                .collect(),
            skip_runtime: false,
            output: assignment_path.clone(),
        },
    )?;
    ensure_reviewed_plan(path, reviewed)?;
    let current: delivery::run::Assignment = cohort::io::read_json(&assignment_path)?;
    ensure!(
        current == assignment,
        "saved assignment changed after review"
    );
    run_command(
        project,
        Command::Worker {
            plan: path.to_path_buf(),
            assignment: assignment_path,
            output: output.to_path_buf(),
            nfpm,
            runtime: Default::default(),
        },
    )
}

pub(super) fn resume_attempt(project: &Path, output: &Path) -> Result<()> {
    let plan = delivery::plan::load(&output.join("plan.json"))?;
    let assignment: delivery::run::Assignment =
        cohort::io::read_json(&output.join("assignment.json"))?;
    delivery::run::validate_assignment(&plan, &assignment)?;
    let receipt = delivery::run::status(output)?;
    ensure!(
        receipt.plan_id == plan.id && receipt.assignment_id == assignment.id,
        "receipt belongs to a different plan or assignment"
    );
    println!(
        "Source commit: {}; engine: {}",
        plan.source.commit, plan.engine_source_id
    );
    println!("Plan: {}; assignment: {}", plan.id, assignment.id);
    let packages = delivery::run::selected_packages(&plan, &assignment);
    println!(
        "Assigned builds: {}; packages: {}",
        assignment.units.len(),
        packages.len()
    );
    for label in build_labels(&plan, &assignment.units)? {
        println!("  {label}");
    }
    println!(
        "Payload checkpoints: {}; package checkpoints: {}",
        receipt.payloads.len(),
        receipt.packages.len()
    );
    for index in &packages {
        println!(
            "  {} — {}",
            escaped(&plan.packages[*index].filename),
            if receipt.packages.contains_key(index) {
                "completed package; bytes will be rechecked"
            } else if receipt.payloads.contains_key(&plan.packages[*index].build) {
                "package pending; completed payload will be reused"
            } else {
                "payload and package pending"
            }
        );
    }
    println!(
        "Runtime checks: {}",
        if assignment.skip_runtime {
            "WARNING: skipped by the saved assignment; output remains build-only"
        } else {
            "required by the saved assignment"
        }
    );
    println!(
        "Complete saved assignment:\n{}",
        serde_json::to_string_pretty(&assignment)?
    );
    println!(
        "Resume rechecks completed checkpoints and matching source. Retry permission can rerun incomplete builds and their side effects."
    );
    let retry_units = assignment
        .units
        .iter()
        .copied()
        .filter(|index| {
            let product = &plan.config.products[plan.builds[*index].product];
            !receipt.payloads.contains_key(index)
                && !assignment.retry_safe_units.contains(index)
                && (!product.prepare.is_empty() || !product.checks.is_empty())
        })
        .collect::<Vec<_>>();
    let labels = build_labels(&plan, &retry_units)?;
    let allow_retry = if labels.is_empty() {
        println!(
            "No incomplete builds need additional retry permission according to the saved receipt. Completed payloads will be reused without recompiling."
        );
        Vec::new()
    } else {
        let Some(indices) = multi(
            "Allow retry for reviewed builds (none selected)",
            &labels,
            &vec![false; labels.len()],
        )?
        else {
            return Ok(());
        };
        indices
            .iter()
            .map(|i| plan.builds[retry_units[*i]].id.clone())
            .collect::<Vec<_>>()
    };
    let Some(nfpm) = choose_nfpm(project, &plan, &assignment.units)? else {
        return Ok(());
    };
    let key = if let Some(public) = &assignment.trusted_key {
        println!("Trusted rebuild assignment key: {}", escaped(public));
        let Some(path) = input_path(project, "Matching private signing-key file")? else {
            return Ok(());
        };
        Some(path)
    } else {
        None
    };
    println!("Resume attempt: {}", path_label(output));
    println!("Allow retry: {}", escaped(&allow_retry.join(", ")));
    if confirm("Resume this attempt with these explicit retry permissions?")? {
        let current_assignment: delivery::run::Assignment =
            cohort::io::read_json(&output.join("assignment.json"))?;
        ensure!(
            delivery::plan::load(&output.join("plan.json"))? == plan
                && current_assignment == assignment,
            "saved plan or assignment changed after review; inspect it again before resuming"
        );
        run_command(
            project,
            Command::Resume {
                output: output.to_path_buf(),
                allow_retry,
                key,
                nfpm,
                runtime: Default::default(),
            },
        )?;
    }
    Ok(())
}
