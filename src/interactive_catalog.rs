use super::super::RuntimeArgs;
use super::{
    Command, confirm, escaped, fresh_directory, input_path, multi, path_label, run_command, select,
    show_document, text,
};
use anyhow::{Context, Result, ensure};
use relship::{
    catalog, cohort, delivery,
    delivery::model::{Format, NativeMetadata},
    settings::Snapshot,
    source, v5,
    v5::model::{Config, Plan, RuntimeConstraint, RuntimeMode, TargetSelection},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use toml_edit::{Array, DocumentMut, InlineTable, Item, TableLike, Value};

const FORMATS: &[Format] = &[
    Format::TarGz,
    Format::Zip,
    Format::Deb,
    Format::Rpm,
    Format::Apk,
    Format::Pacman,
    Format::Ipk,
];

struct Document {
    snapshot: Snapshot,
    config: Config,
}

impl Document {
    fn load(project: &Path) -> Result<Self> {
        let snapshot = Snapshot::load(project)?;
        let config: Config = toml::from_str(snapshot.text())?;
        v5::config::validate(&config)?;
        Ok(Self { snapshot, config })
    }

    fn review_save(&self, doc: DocumentMut, expected: &Config) -> Result<()> {
        v5::config::validate(expected)?;
        let proposed = doc.to_string();
        ensure!(
            toml::from_str::<Config>(&proposed)? == *expected,
            "proposed TOML differs from the reviewed settings"
        );
        if proposed == self.snapshot.text() {
            println!("No settings changed.");
            return Ok(());
        }
        println!(
            "\nReview release.toml changes (complete before/after; control characters escaped):"
        );
        show_document("--- current release.toml", self.snapshot.text());
        show_document("+++ proposed release.toml", &proposed);
        show_package_profiles(expected)?;
        println!(
            "Review and commit the contract before source-bound planning; relship does not commit it."
        );
        if !confirm("Save exactly this release.toml proposal?")? {
            println!("Discarded settings proposal.");
            return Ok(());
        }
        self.snapshot
            .save(&proposed, |candidate| {
                let config: Config = toml::from_str(candidate)?;
                v5::config::validate(&config)?;
                ensure!(
                    config == *expected,
                    "proposed TOML differs from the reviewed settings"
                );
                Ok(())
            })
            .context("release.toml changed after review or could not be saved; inspect the current file before saving")?;
        println!(
            "Saved {}. Review and commit the contract before planning.",
            path_label(self.snapshot.path())
        );
        Ok(())
    }
}

fn bounded_text(prompt: &str) -> Result<Option<String>> {
    let value = text(prompt)?;
    ensure!(
        value.as_ref().is_none_or(|v| v.len() <= 4096),
        "input exceeds 4096 bytes"
    );
    Ok(value)
}

fn bounded_path(project: &Path, prompt: &str) -> Result<Option<PathBuf>> {
    let value = input_path(project, prompt)?;
    ensure!(
        value.as_ref().is_none_or(|v| v.as_os_str().len() <= 4096),
        "path exceeds 4096 bytes"
    );
    Ok(value)
}

pub(super) fn settings_menu(project: &Path) -> Result<()> {
    loop {
        let document = Document::load(project)?;
        println!(
            "\nSettings: {} (catalog targets and controlled runtime)",
            path_label(document.snapshot.path())
        );
        println!(
            "Canonical targets: {}",
            escaped(
                &document
                    .config
                    .targets
                    .iter()
                    .map(|t| t.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        );
        for product in &document.config.products {
            let ids = if product.targets.is_empty() {
                document
                    .config
                    .targets
                    .iter()
                    .map(|t| t.id.as_str())
                    .collect::<Vec<_>>()
            } else {
                product.targets.iter().map(String::as_str).collect()
            };
            println!(
                "Product {} [{}]: {} — {}",
                escaped(&product.id),
                product.build.name(),
                if product.targets.is_empty() {
                    "inherits global targets"
                } else {
                    "explicit targets"
                },
                escaped(&ids.join(", "))
            );
        }
        for target in &document.config.targets {
            println!(
                "  {}: runtime {}{}",
                escaped(&target.id),
                if target.runtime.mode == RuntimeMode::Native {
                    "native"
                } else {
                    "emulated"
                },
                target
                    .runtime
                    .cpu
                    .as_ref()
                    .map(|cpu| format!("; CPU {}", escaped(cpu)))
                    .unwrap_or_default()
            );
        }
        match select(
            "Project settings",
            &[
                "Back",
                "Edit operating systems / CPU profiles / product target scopes",
                "Inspect capability catalog and package formats",
                "Run project doctor",
                "Choose package formats",
                "Choose native or controlled-emulator runtime",
            ],
        )? {
            Some(1) => edit_targets(&document)?,
            Some(2) => show_catalog(&document.config),
            Some(3) => run_command(project, Command::Doctor)?,
            Some(4) => edit_formats(&document)?,
            Some(5) => edit_runtime(project, &document)?,
            _ => return Ok(()),
        }
    }
}

pub(super) fn migrate_menu(project: &Path) -> Result<()> {
    let proposal = v5::migrate::propose(project)?;
    println!(
        "Explicit catalog upgrade: schema {} -> {}. Review the exact contract before saving.",
        proposal.from_schema, proposal.to_schema
    );
    for warning in &proposal.warnings {
        println!("Warning: {}", escaped(warning));
    }
    show_document("--- current release.toml", &proposal.original);
    show_document("+++ proposed release.toml", &proposal.proposed);
    println!(
        "An exact original backup is created beside release.toml. Existing backups are never overwritten."
    );
    println!("Every existing target keeps native runtime. Choose controlled emulation separately.");
    if confirm("Save this catalog schema-4 upgrade and original backup?")? {
        let path = v5::migrate::apply(project, &proposal)?;
        println!(
            "Saved {}. Review and commit the contract before planning.",
            path_label(&path)
        );
    } else {
        println!("Discarded migration proposal.");
    }
    Ok(())
}

fn show_catalog(config: &Config) {
    println!(
        "\nSelect exact catalog IDs. Bare ARM and ARM32 aliases are ambiguous: choose the ARM version, float ABI and builder profile explicitly."
    );
    for target in catalog::all() {
        let builders = config
            .products
            .iter()
            .filter(|p| catalog::for_builder(&target, &p.build).is_ok())
            .map(|p| p.build.name())
            .collect::<BTreeSet<_>>();
        println!(
            "  {} — {} / CPU {} / FPU {} / {} / ABI {} — builders: {}",
            target.id,
            target.os,
            target.cpu,
            target.fpu,
            target.libc,
            target.c_abi,
            if builders.is_empty() {
                "no configured compatible builder".into()
            } else {
                builders.into_iter().collect::<Vec<_>>().join("/")
            }
        );
        for format in FORMATS {
            match catalog::package_support(&target, *format) {
                Ok(profile) => println!(
                    "    {} — package arch {} — {}",
                    format.name(),
                    escaped(&profile.package_arch),
                    escaped(&profile.compatibility)
                ),
                Err(reason) => println!(
                    "    {} unavailable — {}",
                    format.name(),
                    escaped(&reason.to_string())
                ),
            }
        }
    }
    println!(
        "Archives: tar.gz / zip. Native Linux formats: deb / rpm / APK v2 / pacman / ipk, subject to each target's compatibility above."
    );
    println!("pkg / dmg / msi / msix / exe installers: unavailable.");
}

fn child_table<'a>(table: &'a mut dyn TableLike, key: &str) -> Result<&'a mut dyn TableLike> {
    if !table.contains_key(key) {
        table.insert(key, Item::Value(Value::InlineTable(InlineTable::new())));
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
            .map(|t| t as &mut dyn TableLike)
            .context("missing product table"),
        Item::Value(Value::Array(values)) => values
            .get_mut(index)
            .and_then(Value::as_inline_table_mut)
            .map(|t| t as &mut dyn TableLike)
            .context("product must be a TOML table"),
        _ => anyhow::bail!("products must be an array of tables"),
    }
}

fn replace(table: &mut dyn TableLike, key: &str, mut value: Value) {
    if let Some(old) = table.get(key).and_then(Item::as_value) {
        *value.decor_mut() = old.decor().clone();
    }
    table.insert(key, Item::Value(value));
}

fn strings(values: &[String]) -> Value {
    let mut array = Array::new();
    for value in values {
        array.push(value.as_str());
    }
    Value::Array(array)
}

fn set_targets(doc: &mut DocumentMut, targets: &[TargetSelection]) -> Result<()> {
    let mut array = Array::new();
    for target in targets {
        let mut entry = InlineTable::new();
        entry.insert("id", target.id.as_str().into());
        if target.runtime != RuntimeConstraint::default() {
            let serialized = toml::to_string(&target.runtime)?.parse::<DocumentMut>()?;
            let mut runtime = InlineTable::new();
            for (key, value) in serialized.iter() {
                runtime.insert(
                    key,
                    value
                        .as_value()
                        .context("runtime field must be a value")?
                        .clone(),
                );
            }
            entry.insert("runtime", Value::InlineTable(runtime));
        }
        array.push(Value::InlineTable(entry));
    }
    replace(doc.as_table_mut(), "targets", Value::Array(array));
    Ok(())
}

fn edit_targets(document: &Document) -> Result<()> {
    println!("Choose exact CPU and ABI profiles. Bare ARM aliases cannot choose a catalog target.");
    let filter = match select(
        "Operating systems to edit",
        &[
            "All operating systems",
            "Linux",
            "macOS",
            "Windows",
            "Cancel settings edit",
        ],
    )? {
        Some(0) => None,
        Some(1) => Some("linux"),
        Some(2) => Some("macos"),
        Some(3) => Some("windows"),
        _ => return Ok(()),
    };
    let available = catalog::all()
        .into_iter()
        .filter(|t| filter.is_none_or(|os| os == t.os))
        .filter(|t| {
            document
                .config
                .products
                .iter()
                .any(|p| catalog::for_builder(t, &p.build).is_ok())
        })
        .collect::<Vec<_>>();
    let labels = available
        .iter()
        .map(|t| {
            format!(
                "{} — CPU {} / FPU {} / {} / ABI {}",
                t.id, t.cpu, t.fpu, t.libc, t.c_abi
            )
        })
        .collect::<Vec<_>>();
    let defaults = available
        .iter()
        .map(|t| document.config.targets.iter().any(|s| s.id == t.id))
        .collect::<Vec<_>>();
    let Some(selected) = multi(
        "Choose canonical global targets (Space toggles)",
        &labels,
        &defaults,
    )?
    else {
        return Ok(());
    };
    let mut config = document.config.clone();
    let mut targets = config
        .targets
        .iter()
        .filter(|t| filter.is_some_and(|os| catalog::resolve(&t.id).is_ok_and(|t| t.os != os)))
        .cloned()
        .collect::<Vec<_>>();
    for index in selected {
        let id = &available[index].id;
        targets.push(
            config
                .targets
                .iter()
                .find(|t| &t.id == id)
                .cloned()
                .unwrap_or_else(|| TargetSelection::native(id)),
        );
    }
    ensure!(!targets.is_empty(), "select at least one target");
    let ids = targets.iter().map(|t| t.id.clone()).collect::<Vec<_>>();
    config.targets = targets;
    let mut doc = document.snapshot.text().parse::<DocumentMut>()?;
    set_targets(&mut doc, &config.targets)?;
    for (index, product) in config.products.iter_mut().enumerate() {
        println!(
            "\nProduct {} [{}]: {}",
            escaped(&product.id),
            product.build.name(),
            if product.targets.is_empty() {
                "inherits global targets"
            } else {
                "explicit target filter"
            }
        );
        let compatible = ids
            .iter()
            .filter(|id| {
                catalog::resolve(id)
                    .and_then(|t| catalog::for_builder(&t, &product.build))
                    .is_ok()
            })
            .cloned()
            .collect::<Vec<_>>();
        ensure!(
            !compatible.is_empty(),
            "product {} has no compatible selected target",
            product.id
        );
        for id in ids.iter().filter(|id| !compatible.contains(id)) {
            println!(
                "  {} is unavailable for this {} builder; choose an explicit compatible filter.",
                id,
                product.build.name()
            );
        }
        let scope = match select(
            "Product target scope",
            &[
                "Preserve current scope (intersect explicit targets with global selection)",
                "Choose explicit targets for this product",
                "Inherit all global targets (requires builder compatibility)",
                "Cancel settings edit",
            ],
        )? {
            Some(scope @ 0..=2) => scope,
            _ => return Ok(()),
        };
        match scope {
            0 if !product.targets.is_empty() => {
                product.targets.retain(|id| ids.contains(id));
                ensure!(
                    !product.targets.is_empty(),
                    "preserved explicit product scope is empty; choose a compatible filter"
                );
            }
            1 => {
                let selected = compatible
                    .iter()
                    .map(|id| product.targets.is_empty() || product.targets.contains(id))
                    .collect::<Vec<_>>();
                let Some(chosen) = multi(
                    "Explicit compatible product targets",
                    &compatible,
                    &selected,
                )?
                else {
                    return Ok(());
                };
                ensure!(
                    !chosen.is_empty(),
                    "explicit product scope needs at least one target"
                );
                product.targets = chosen.into_iter().map(|i| compatible[i].clone()).collect();
            }
            2 => product.targets.clear(),
            _ => (),
        }
        if product.targets.is_empty() {
            product_table(&mut doc, index)?.remove("targets");
        } else {
            replace(
                product_table(&mut doc, index)?,
                "targets",
                strings(&product.targets),
            );
        }
    }
    if !complete_native_metadata(&mut doc, &mut config)? {
        return Ok(());
    }
    document.review_save(doc, &config)
}

fn formats_label(formats: &[Format]) -> String {
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

fn product_targets(
    config: &Config,
    product: usize,
    os: &str,
) -> Result<Vec<catalog::TargetDescriptor>> {
    let product = &config.products[product];
    config
        .targets
        .iter()
        .filter(|t| product.targets.is_empty() || product.targets.contains(&t.id))
        .map(|t| catalog::resolve(&t.id).and_then(|t| catalog::for_builder(&t, &product.build)))
        .filter(|t| match t {
            Ok(t) => t.os == os,
            Err(_) => true,
        })
        .collect()
}

fn set_formats(table: &mut dyn TableLike, os: &str, formats: &[Format]) -> Result<()> {
    let values = formats
        .iter()
        .map(|f| f.name().to_string())
        .collect::<Vec<_>>();
    replace(
        child_table(child_table(table, "packaging")?, "formats")?,
        os,
        strings(&values),
    );
    Ok(())
}

fn prompt_native(product: &str) -> Result<Option<NativeMetadata>> {
    println!(
        "Native package metadata for {}. Enter the actual project values.",
        escaped(product)
    );
    let Some(name) = bounded_text("Native package name (lowercase package identifier)")? else {
        return Ok(None);
    };
    v5::config::package_name(&name)?;
    let Some(description) = bounded_text("Package description")? else {
        return Ok(None);
    };
    let Some(license) = bounded_text("Package license")? else {
        return Ok(None);
    };
    let Some(maintainer) = bounded_text("Package maintainer")? else {
        return Ok(None);
    };
    let homepage = match select(
        "Package homepage",
        &["Omit homepage", "Enter homepage", "Cancel settings edit"],
    )? {
        Some(0) => None,
        Some(1) => {
            let Some(value) = bounded_text("Package homepage URL")? else {
                return Ok(None);
            };
            Some(value)
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

fn complete_native_metadata(doc: &mut DocumentMut, config: &mut Config) -> Result<bool> {
    for index in 0..config.products.len() {
        if product_targets(config, index, "linux")?.is_empty()
            || !v5::config::effective_formats(config, index, "linux")
                .iter()
                .any(|format| format.is_native())
            || config.products[index].packaging.native.is_some()
        {
            continue;
        }
        let Some(native) = prompt_native(&config.products[index].id)? else {
            return Ok(false);
        };
        let table = child_table(
            child_table(product_table(doc, index)?, "packaging")?,
            "native",
        )?;
        for (key, value) in [
            ("name", native.name.as_deref().unwrap()),
            ("description", &native.description),
            ("license", &native.license),
            ("maintainer", &native.maintainer),
        ] {
            replace(table, key, Value::from(value));
        }
        if let Some(homepage) = &native.homepage {
            replace(table, "homepage", Value::from(homepage.as_str()));
        }
        config.products[index].packaging.native = Some(native);
    }
    Ok(true)
}

fn edit_formats(document: &Document) -> Result<()> {
    let mut scopes = vec!["Back".into(), "Global defaults per operating system".into()];
    scopes.extend(
        document
            .config
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
        || defaults(&document.config, os),
        |p| v5::config::effective_formats(&document.config, p, os),
    );
    println!("Current {os} formats: {}", formats_label(&current));
    let inherit = if let Some(index) = product {
        println!(
            "Product {}: {}",
            escaped(&document.config.products[index].id),
            if document.config.products[index]
                .packaging
                .formats
                .contains_key(os)
            {
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
    let mut config = document.config.clone();
    let mut doc = document.snapshot.text().parse::<DocumentMut>()?;
    if inherit {
        let index = product.context("inherit requires a product")?;
        config.products[index].packaging.formats.remove(os);
        if let Some(packaging) = product_table(&mut doc, index)?
            .get_mut("packaging")
            .and_then(Item::as_table_like_mut)
            && let Some(formats) = packaging
                .get_mut("formats")
                .and_then(Item::as_table_like_mut)
        {
            formats.remove(os);
        }
    } else {
        let affected = (0..config.products.len())
            .filter(|p| product.is_none_or(|selected| selected == *p))
            .filter(|p| {
                product.is_some() || !config.products[*p].packaging.formats.contains_key(os)
            })
            .collect::<Vec<_>>();
        let mut available = Vec::new();
        for format in FORMATS {
            let mut reasons = Vec::new();
            if os != "linux" && format.is_native() {
                reasons.push(format!("{} packages require Linux", format.name()));
            }
            for index in &affected {
                for target in product_targets(&config, *index, os)? {
                    if let Err(reason) = catalog::package_support(&target, *format) {
                        reasons.push(format!("{}: {reason}", target.id));
                    }
                }
            }
            reasons.sort();
            reasons.dedup();
            if reasons.is_empty() {
                available.push(*format);
            } else {
                println!(
                    "Unavailable {} — {}",
                    format.name(),
                    escaped(&reasons.join("; "))
                );
            }
        }
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
        let formats = indices
            .iter()
            .map(|index| available[*index])
            .collect::<Vec<_>>();
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
    for index in 0..config.products.len() {
        if product_targets(&config, index, os)?.is_empty() {
            continue;
        }
        println!(
            "  {}: [{}] -> [{}]",
            escaped(&config.products[index].id),
            formats_label(&v5::config::effective_formats(&document.config, index, os)),
            formats_label(&v5::config::effective_formats(&config, index, os))
        );
    }
    if !complete_native_metadata(&mut doc, &mut config)? {
        return Ok(());
    }
    document.review_save(doc, &config)
}

fn edit_runtime(project: &Path, document: &Document) -> Result<()> {
    let labels = document
        .config
        .targets
        .iter()
        .map(|t| {
            format!(
                "{} — {}",
                t.id,
                if t.runtime.mode == RuntimeMode::Native {
                    "native"
                } else {
                    "controlled emulation"
                }
            )
        })
        .collect::<Vec<_>>();
    let Some(index) = select("Target runtime contract", &labels)? else {
        return Ok(());
    };
    let target = catalog::resolve(&document.config.targets[index].id)?;
    println!(
        "Native execution verifies the host architecture and CPU. Implicit binfmt is never accepted as emulation evidence."
    );
    let canonical = catalog::canonical_emulation(&target);
    if let Err(reason) = &canonical {
        println!(
            "Controlled emulation unavailable — {}",
            escaped(&reason.to_string())
        );
    }
    let mut choices = vec!["Keep current runtime", "Native runtime"];
    if canonical.is_ok() {
        choices.push("Controlled emulation (pin the exact QEMU executable and CPU profile)");
    }
    choices.push("Cancel settings edit");
    let runtime = match select("Choose runtime", &choices)? {
        Some(1) => RuntimeConstraint::default(),
        Some(2) if canonical.is_ok() => {
            let (emulator, cpu) = canonical?;
            println!(
                "Exact controlled profile: {} -cpu {}",
                v5::runtime::emulator_name(emulator),
                cpu
            );
            let Some(path) = bounded_path(project, "Existing QEMU executable file")? else {
                return Ok(());
            };
            let rootfs = if target.libc == "glibc" {
                println!(
                    "GNU runtime requires a materialized matching loader and libraries directory; symlinks are rejected."
                );
                let Some(path) = bounded_path(
                    project,
                    "Existing materialized GNU runtime rootfs directory",
                )?
                else {
                    return Ok(());
                };
                Some(path)
            } else {
                None
            };
            let pin = v5::runtime::inspect(&path, rootfs.as_deref())?;
            println!("QEMU identity: {}", escaped(pin.emulator_version.trim()));
            println!("Emulator SHA-256: {}", pin.emulator_sha256);
            if let Some(hash) = &pin.rootfs_sha256 {
                println!("Rootfs SHA-256: {hash}");
            }
            println!(
                "The contract saves these identities. Supply matching local paths again when running a plan."
            );
            RuntimeConstraint {
                mode: RuntimeMode::Emulated,
                emulator: Some(emulator),
                cpu: Some(cpu.into()),
                emulator_sha256: Some(pin.emulator_sha256),
                rootfs_sha256: pin.rootfs_sha256,
            }
        }
        _ => return Ok(()),
    };
    v5::config::validate_runtime(&target, &runtime)?;
    let mut config = document.config.clone();
    config.targets[index].runtime = runtime;
    let mut doc = document.snapshot.text().parse::<DocumentMut>()?;
    set_targets(&mut doc, &config.targets)?;
    document.review_save(doc, &config)
}

fn show_plan(plan: &Plan) {
    println!("\nSource-bound plan for review:");
    println!(
        "Plan: {}\nSource commit: {}\nExecution protocol: 5",
        plan.id, plan.source.commit
    );
    println!(
        "Build units: {}; expected packages: {}",
        plan.builds.len(),
        plan.packages.len()
    );
    for (index, build) in plan.builds.iter().enumerate() {
        let selection = &plan.config.targets[build.target];
        println!(
            "  {} — {} / {} — CPU {} / FPU {} / ABI {} — runtime {}",
            escaped(&build.id),
            escaped(&plan.config.products[build.product].id),
            build.descriptor.id,
            build.descriptor.cpu,
            build.descriptor.fpu,
            build.descriptor.c_abi,
            if selection.runtime.mode == RuntimeMode::Native {
                "native"
            } else {
                "controlled emulation"
            }
        );
        for (package_index, package) in plan
            .packages
            .iter()
            .enumerate()
            .filter(|(_, p)| p.build == index)
        {
            let profile = &plan.package_profiles[package_index];
            println!(
                "    {} — format {} — package arch {}",
                escaped(&package.filename),
                package.format.name(),
                escaped(&profile.package_arch)
            );
            if package.format.is_native() {
                println!("      {}", escaped(&profile.compatibility));
            }
        }
        if let Some(cpu) = &selection.runtime.cpu {
            println!(
                "    Runtime CPU: {}; emulator SHA-256: {}; rootfs SHA-256: {}",
                cpu,
                selection
                    .runtime
                    .emulator_sha256
                    .as_deref()
                    .unwrap_or("none"),
                selection.runtime.rootfs_sha256.as_deref().unwrap_or("none")
            );
        }
    }
    println!(
        "Each build produces one payload shared by its selected package formats. Runtime checks require the exact native host or explicit pinned emulator paths."
    );
}

fn build_labels(plan: &Plan, units: &[usize]) -> Result<Vec<String>> {
    units
        .iter()
        .map(|index| {
            let build = plan
                .builds
                .get(*index)
                .context("assignment build is out of range")?;
            Ok(format!(
                "{} — {} / {} — {}",
                escaped(&build.id),
                escaped(&plan.config.products[build.product].id),
                plan.config.targets[build.target].id,
                plan.packages
                    .iter()
                    .filter(|p| p.build == *index)
                    .map(|p| p.format.name())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
        .collect()
}

fn choose_nfpm(project: &Path, plan: &Plan, units: &[usize]) -> Result<Option<Option<PathBuf>>> {
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
            let Some(path) = bounded_path(project, "nFPM executable file")? else {
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

fn choose_runtime_paths(
    project: &Path,
    plan: &Plan,
    units: &[usize],
    skip_runtime: bool,
) -> Result<Option<RuntimeArgs>> {
    let mut args = RuntimeArgs::default();
    if skip_runtime {
        return Ok(Some(args));
    }
    let mut tools = v5::runtime::RuntimeTools::default();
    let mut targets = BTreeSet::new();
    for unit in units {
        let build = &plan.builds[*unit];
        let selection = &plan.config.targets[build.target];
        if !targets.insert(selection.id.clone()) || selection.runtime.mode == RuntimeMode::Native {
            continue;
        }
        let emulator = selection
            .runtime
            .emulator
            .context("missing controlled emulator")?;
        let name = v5::runtime::emulator_name(emulator);
        println!(
            "Runtime {}: {} -cpu {}; required emulator SHA-256 {}",
            selection.id,
            name,
            selection.runtime.cpu.as_deref().unwrap_or("missing"),
            selection
                .runtime
                .emulator_sha256
                .as_deref()
                .unwrap_or("missing")
        );
        if !tools.emulators.contains_key(name) {
            let Some(path) = bounded_path(project, &format!("Matching {name} executable file"))?
            else {
                return Ok(None);
            };
            let path = path.canonicalize()?;
            args.emulators.push(format!("{name}={}", path.display()));
            tools.emulators.insert(name.into(), path);
        }
        if let Some(pin) = &selection.runtime.rootfs_sha256 {
            println!("Required {} rootfs SHA-256: {pin}", selection.id);
            let Some(path) = bounded_path(
                project,
                &format!("Matching {} materialized rootfs directory", selection.id),
            )?
            else {
                return Ok(None);
            };
            let path = path.canonicalize()?;
            args.rootfs
                .push(format!("{}={}", selection.id, path.display()));
            tools.rootfs.insert(selection.id.clone(), path);
        }
        v5::runtime::validate_tools(&build.descriptor, &selection.runtime, &tools)?;
    }
    Ok(Some(args))
}

pub(super) fn create_plan(project: &Path) -> Result<()> {
    let root = source::root(project)?;
    println!("Resolving the committed source and release contract…");
    let plan = v5::plan::create(&root)?;
    show_plan(&plan);
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
            Some(3) => println!("{}", serde_json::to_string_pretty(&plan)?),
            _ => return Ok(()),
        }
    };
    let directory = fresh_directory(&root, "plan")?;
    let path = directory.join("plan.json");
    println!("Save exact reviewed plan: {}", path_label(&path));
    if !confirm("Write this immutable plan to a fresh file?")? {
        return Ok(());
    }
    let relative = path
        .strip_prefix(&root)?
        .to_str()
        .context("non-UTF8 interactive plan path")?;
    source::git(&root, &["check-ignore", "--quiet", "--", relative])
        .context("interactive plans require an ignored target/ output path")?;
    ensure!(
        source::git(&root, &["ls-files", "--", relative])?.is_empty(),
        "interactive plan output overlaps tracked inputs"
    );
    super::super::write_new_json(&root, &path, &plan)?;
    println!("Saved plan: {}", path_label(&path));
    if !build {
        return Ok(());
    }
    worker_build(project, &path, &directory.join("attempt"), &plan)
}

fn ensure_plan(path: &Path, reviewed: &Plan) -> Result<()> {
    ensure!(
        v5::plan::load(path)? == *reviewed,
        "saved plan changed after review; inspect it again before running"
    );
    Ok(())
}

fn worker_build(project: &Path, path: &Path, output: &Path, plan: &Plan) -> Result<()> {
    ensure_plan(path, plan)?;
    let all = (0..plan.builds.len()).collect::<Vec<_>>();
    let labels = build_labels(plan, &all)?;
    let Some(selected) = multi(
        "Choose build units (Space toggles)",
        &labels,
        &vec![true; labels.len()],
    )?
    else {
        return Ok(());
    };
    ensure!(!selected.is_empty(), "select at least one build unit");
    let selected_labels = selected
        .iter()
        .map(|i| labels[*i].clone())
        .collect::<Vec<_>>();
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
    let assignment = v5::run::assignment(
        plan,
        &v5::run::RunOptions {
            units: selected.clone(),
            retry_safe_units: retry_units.clone(),
            ..Default::default()
        },
    )?;
    let Some(nfpm) = choose_nfpm(project, plan, &selected)? else {
        return Ok(());
    };
    let Some(runtime) = choose_runtime_paths(project, plan, &selected, false)? else {
        return Ok(());
    };
    let assignment_path = path.with_file_name("assignment.json");
    println!(
        "Plan: {}\nAssignment: {}\nWorker attempt: {}",
        path_label(path),
        path_label(&assignment_path),
        path_label(output)
    );
    println!(
        "Runtime checks: required. Reviewed assignment:\n{}",
        serde_json::to_string_pretty(&assignment)?
    );
    if !confirm("Write this assignment and execute its selected builds and packages?")? {
        return Ok(());
    }
    ensure_plan(path, plan)?;
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
    ensure_plan(path, plan)?;
    ensure!(
        cohort::io::read_json::<v5::run::Assignment>(&assignment_path)? == assignment,
        "saved assignment changed after review"
    );
    run_command(
        project,
        Command::Worker {
            plan: path.to_path_buf(),
            assignment: assignment_path,
            output: output.to_path_buf(),
            nfpm,
            runtime,
        },
    )
}

pub(super) fn resume_attempt(project: &Path, output: &Path) -> Result<()> {
    let plan_path = output.join("plan.json");
    let assignment_path = output.join("assignment.json");
    let plan = v5::plan::load(&plan_path)?;
    let assignment: v5::run::Assignment = cohort::io::read_json(&assignment_path)?;
    v5::run::validate_assignment(&plan, &assignment)?;
    let receipt = v5::run::status(output)?;
    ensure!(
        receipt.plan_id == plan.id && receipt.assignment_id == assignment.id,
        "receipt belongs to a different plan or assignment"
    );
    println!(
        "Source commit: {}; engine: {}\nPlan: {}; assignment: {}",
        plan.source.commit, plan.engine_source_id, plan.id, assignment.id
    );
    for label in build_labels(&plan, &assignment.units)? {
        println!("  {label}");
    }
    println!(
        "Payload checkpoints: {}; package checkpoints: {}",
        receipt.payloads.len(),
        receipt.packages.len()
    );
    for index in v5::run::selected_packages(&plan, &assignment) {
        let package = &plan.packages[index];
        println!(
            "  {} — {}",
            escaped(&package.filename),
            if receipt.packages.contains_key(&index) {
                "completed package; bytes will be rechecked"
            } else if receipt.payloads.contains_key(&package.build) {
                "package pending; completed payload will be reused"
            } else {
                "payload and package pending"
            }
        );
    }
    println!(
        "Runtime checks: {}",
        if assignment.skip_runtime {
            "WARNING: skipped by the saved assignment; output remains build-only and merge-ineligible"
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
    let allow_retry = if retry_units.is_empty() {
        Vec::new()
    } else {
        let labels = build_labels(&plan, &retry_units)?;
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
            .collect()
    };
    let Some(nfpm) = choose_nfpm(project, &plan, &assignment.units)? else {
        return Ok(());
    };
    let Some(runtime) =
        choose_runtime_paths(project, &plan, &assignment.units, assignment.skip_runtime)?
    else {
        return Ok(());
    };
    let key = if let Some(public) = &assignment.trusted_key {
        println!("Trusted rebuild assignment key: {}", escaped(public));
        let Some(path) = bounded_path(project, "Matching private signing-key file")? else {
            return Ok(());
        };
        Some(path)
    } else {
        None
    };
    println!(
        "Resume attempt: {}\nAllow retry: {}",
        path_label(output),
        escaped(&allow_retry.join(", "))
    );
    if confirm("Resume this attempt with these explicit retry permissions?")? {
        ensure_plan(&plan_path, &plan)?;
        ensure!(
            cohort::io::read_json::<v5::run::Assignment>(&assignment_path)? == assignment,
            "saved assignment changed after review"
        );
        run_command(
            project,
            Command::Resume {
                output: output.to_path_buf(),
                allow_retry,
                key,
                nfpm,
                runtime,
            },
        )?;
    }
    Ok(())
}

fn show_package_profiles(config: &Config) -> Result<()> {
    for (index, product) in config.products.iter().enumerate() {
        for selected in config
            .targets
            .iter()
            .filter(|target| product.targets.is_empty() || product.targets.contains(&target.id))
        {
            let target = catalog::for_builder(&catalog::resolve(&selected.id)?, &product.build)?;
            for format in v5::config::effective_formats(config, index, &target.os) {
                let profile = catalog::package_support(&target, format)?;
                println!(
                    "Package profile: {} / {} / {} -> {}",
                    escaped(&product.id),
                    escaped(&target.id),
                    format.name(),
                    escaped(&profile.package_arch)
                );
                if format.is_native() {
                    println!("  {}", escaped(&profile.compatibility));
                }
            }
        }
    }
    Ok(())
}
