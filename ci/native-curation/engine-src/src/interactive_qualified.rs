use super::super::qualified_cli;
use super::{
    Command, confirm, escaped, fresh_directory, input_path, multi, path_label, run_command, select,
    show_document, text,
};
use anyhow::{Context, Result, ensure};
use relship::{
    catalog, cmake,
    compatibility::{Environment, Profile, windows_crt::WindowsRuntimeMode},
    delivery::model::{Format, NativeMetadata},
    qualified::{
        self,
        model::{Builder, Config, Plan},
    },
    settings::Snapshot,
    source,
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use toml_edit::{DocumentMut, InlineTable, Item, TableLike, Value};

const FORMATS: &[Format] = &[Format::TarGz, Format::Zip, Format::Deb, Format::Rpm];

struct Document {
    snapshot: Snapshot,
    config: Config,
}
impl Document {
    fn load(project: &Path) -> Result<Self> {
        let snapshot = Snapshot::load(project)?;
        let config = qualified::config::parse(snapshot.text())?;
        Ok(Self { snapshot, config })
    }
    fn review_save(&self, doc: DocumentMut, expected: &Config) -> Result<()> {
        qualified::config::validate(expected)?;
        let proposed = doc.to_string();
        ensure!(
            qualified::config::parse(&proposed)? == *expected,
            "proposed TOML differs from reviewed settings"
        );
        if proposed == self.snapshot.text() {
            println!("No settings changed.");
            return Ok(());
        }
        show_document("--- current release.toml", self.snapshot.text());
        show_document("+++ proposed release.toml", &proposed);
        qualified_cli::compatibility_summary(expected)?;
        println!("Review and commit the contract before source-bound planning.");
        if !confirm("Save exactly this release.toml proposal?")? {
            println!("Discarded settings proposal.");
            return Ok(());
        }
        self.snapshot
            .save(&proposed, |candidate| {
                ensure!(
                    qualified::config::parse(candidate)? == *expected,
                    "settings differ from the reviewed proposal"
                );
                Ok(())
            })
            .context(
                "release.toml changed after review or could not be saved; inspect the current file",
            )?;
        println!(
            "Saved {}. Review and commit before planning.",
            path_label(self.snapshot.path())
        );
        Ok(())
    }
}

fn bounded_text(prompt: &str) -> Result<Option<String>> {
    let value = text(prompt)?;
    ensure!(
        value.as_ref().is_none_or(|s| s.len() <= 4096),
        "input exceeds 4096 bytes"
    );
    Ok(value)
}
fn strings(values: &[String]) -> Value {
    let mut array = toml_edit::Array::new();
    for value in values {
        array.push(value.as_str());
    }
    Value::Array(array)
}
fn replace(table: &mut dyn TableLike, key: &str, mut value: Value) {
    if let Some(old) = table.get(key).and_then(Item::as_value) {
        *value.decor_mut() = old.decor().clone();
    }
    table.insert(key, Item::Value(value));
}
fn child<'a>(table: &'a mut dyn TableLike, key: &str) -> Result<&'a mut dyn TableLike> {
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
        Item::ArrayOfTables(values) => values
            .get_mut(index)
            .map(|v| v as &mut dyn TableLike)
            .context("missing product"),
        Item::Value(Value::Array(values)) => values
            .get_mut(index)
            .and_then(Value::as_inline_table_mut)
            .map(|v| v as &mut dyn TableLike)
            .context("product must be a table"),
        _ => anyhow::bail!("products must be an array of tables"),
    }
}
fn literal(value: serde_json::Value) -> Result<Value> {
    Ok(match value {
        serde_json::Value::String(v) => v.into(),
        serde_json::Value::Bool(v) => v.into(),
        serde_json::Value::Number(v) => v.as_i64().context("TOML integer out of bounds")?.into(),
        serde_json::Value::Array(values) => {
            let mut array = toml_edit::Array::new();
            for value in values {
                array.push(literal(value)?);
            }
            Value::Array(array)
        }
        serde_json::Value::Object(values) => {
            let mut table = InlineTable::new();
            for (key, value) in values {
                if !value.is_null() {
                    table.insert(&key, literal(value)?);
                }
            }
            Value::InlineTable(table)
        }
        _ => anyhow::bail!("unsupported null TOML value"),
    })
}

pub(super) fn settings_menu(project: &Path) -> Result<()> {
    loop {
        let document = Document::load(project)?;
        println!(
            "\nSettings: {} (schema 5; environment-qualified preparation)",
            path_label(document.snapshot.path())
        );
        println!("Targets: {}", escaped(&document.config.targets.join(", ")));
        println!(
            "Windows CRT: {}",
            runtime_mode_name(document.config.compatibility.windows.crt)
        );
        for product in &document.config.products {
            println!(
                "  {} [{}]: {}",
                escaped(&product.id),
                product.build.name(),
                if product.targets.is_empty() {
                    "inherits global targets".into()
                } else {
                    escaped(&product.targets.join(", "))
                }
            );
        }
        match select(
            "Project settings",
            &[
                "Back",
                "Edit native operating systems / architectures / product scopes",
                "Edit CMake source version, preset and targets",
                "Choose archive / native package formats",
                "Review broad Linux compatibility and SDK requirements",
                "Run project doctor",
                "Choose Windows CRT and review app-local DLL inputs",
            ],
        )? {
            Some(1) => edit_targets(&document)?,
            Some(2) => edit_cmake(project, &document)?,
            Some(3) => edit_formats(&document)?,
            Some(4) => qualified_cli::compatibility_summary(&document.config)?,
            Some(5) => run_command(project, Command::Doctor)?,
            Some(6) => edit_windows_runtime(project, &document)?,
            _ => return Ok(()),
        }
    }
}

fn runtime_mode_name(mode: WindowsRuntimeMode) -> &'static str {
    match mode {
        WindowsRuntimeMode::FollowProject => "follow-project",
        WindowsRuntimeMode::Static => "static",
        WindowsRuntimeMode::Dynamic => "dynamic",
    }
}

fn show_windows_runtime_inputs(project: &Path) -> Result<()> {
    let path = relship::config::safe_join(project, "release-ci.toml")?;
    println!(
        "Windows SDK and app-local DLL inputs: {}",
        path_label(&path)
    );
    println!(
        "Advanced SDK curation: relship ci inspect-windows-runtime --sdk <sdk.json> --arch <x86_64|aarch64> --directory <SDK-redist-directory> --license <SDK-license-file> --mode <follow-project|static|dynamic>. Repeat --directory and --license for additional inputs; review the returned provider and license pins in release-ci.toml. This settings edit changes only the project CRT mode."
    );
    if !path.exists() {
        println!(
            "No release-ci.toml is present. Windows execution requires reviewed SDK pins; imported CRT DLLs also require explicit SDK provider and license pins."
        );
        return Ok(());
    }
    let contents = std::fs::read_to_string(&path)?;
    let document = contents
        .parse::<toml::Value>()
        .context("invalid release-ci.toml")?;
    let mut windows_profiles = 0;
    if let Some(environments) = document.get("environments") {
        for (name, value) in environments
            .as_table()
            .context("release-ci.toml environments must be a table")?
        {
            let profile: Profile = value
                .clone()
                .try_into()
                .with_context(|| format!("invalid environment profile {name}"))?;
            if profile.os != "windows" {
                continue;
            }
            windows_profiles += 1;
            println!(
                "  Profile {} — native {} — {}",
                escaped(name),
                profile.arch.name(),
                escaped(&profile.id)
            );
            if let Environment::NativeSdk { sdk, .. } = &profile.environment {
                println!(
                    "    SDK {} {}; content SHA-256 {}",
                    escaped(&sdk.sdk_id),
                    escaped(&sdk.sdk_version),
                    sdk.sdk_content_sha256
                );
                for (root, sha256) in &sdk.roots {
                    println!("    SDK root: {} — SHA-256 {}", escaped(root), sha256);
                }
            }
            if let Some(runtime) = &profile.windows_runtime {
                println!(
                    "    SDK DLL provider allowlist (only imported DLLs are delivered app-local):"
                );
                if runtime.libraries.is_empty() {
                    println!("      No DLL providers pinned.");
                }
                for library in &runtime.libraries {
                    println!(
                        "      {} [{}] <- {} — SHA-256 {}",
                        escaped(&library.filename),
                        library.arch.name(),
                        escaped(&library.source),
                        library.sha256
                    );
                }
                println!("    Runtime license pins:");
                if runtime.licenses.is_empty() {
                    println!("      No runtime licenses pinned.");
                }
                for license in &runtime.licenses {
                    println!(
                        "      {} <- {} — SHA-256 {}",
                        escaped(&license.destination),
                        escaped(&license.source),
                        license.sha256
                    );
                }
            } else {
                println!(
                    "    No DLL provider or runtime license pins. Undeclared imported CRT DLLs prevent completed delivery."
                );
            }
            if let Err(error) = profile.validate() {
                println!(
                    "    Profile validation blocker: {}",
                    escaped(&format!("{error:#}"))
                );
            }
        }
    }
    if windows_profiles == 0 {
        println!("No Windows SDK environment profiles are declared.");
    }
    Ok(())
}

fn edit_windows_runtime(project: &Path, document: &Document) -> Result<()> {
    println!(
        "Current Windows CRT mode: {}",
        runtime_mode_name(document.config.compatibility.windows.crt)
    );
    println!(
        "Follow project preserves project and preset CRT choices. Static and dynamic are explicit requirements; conflicting CMake settings or delivered binary imports stop preparation."
    );
    println!(
        "Required CRT DLLs are copied beside the application from pinned SDK providers, including their declared licenses. Each DLL's architecture and import closure are verified; missing providers stop preparation."
    );
    show_windows_runtime_inputs(project)?;
    let mode = match select(
        "Windows CRT mode",
        &[
            "Back",
            "Follow project / preset (default)",
            "Require static CRT",
            "Require dynamic CRT with app-local DLL delivery",
        ],
    )? {
        Some(1) => WindowsRuntimeMode::FollowProject,
        Some(2) => WindowsRuntimeMode::Static,
        Some(3) => WindowsRuntimeMode::Dynamic,
        _ => return Ok(()),
    };
    for product in &document.config.products {
        let has_windows = document.config.targets.iter().any(|target| {
            (product.targets.is_empty() || product.targets.contains(target))
                && target.starts_with("windows-")
        });
        if !has_windows {
            continue;
        }
        if let Builder::Cmake(spec) = &product.build
            && let Some(explicit) = spec.cache_variables.get("CMAKE_MSVC_RUNTIME_LIBRARY")
        {
            let expected = match mode {
                WindowsRuntimeMode::FollowProject => None,
                WindowsRuntimeMode::Static => Some("MultiThreaded"),
                WindowsRuntimeMode::Dynamic => Some("MultiThreadedDLL"),
            };
            if let Some(expected) = expected {
                ensure!(
                    explicit == expected,
                    "product {} explicitly requests CMAKE_MSVC_RUNTIME_LIBRARY={explicit}, which conflicts with Windows CRT mode {}; review that setting before changing mode",
                    product.id,
                    runtime_mode_name(mode)
                );
            }
        }
    }
    let mut config = document.config.clone();
    config.compatibility.windows.crt = mode;
    let mut doc = document.snapshot.text().parse::<DocumentMut>()?;
    let compatibility = child(doc.as_table_mut(), "compatibility")?;
    replace(
        child(compatibility, "windows")?,
        "crt",
        runtime_mode_name(mode).into(),
    );
    document.review_save(doc, &config)
}

fn edit_targets(document: &Document) -> Result<()> {
    let choices = catalog::all()
        .into_iter()
        .filter(|t| {
            matches!(t.arch.as_str(), "x86_64" | "aarch64")
                && matches!(t.os.as_str(), "linux" | "macos" | "windows")
                && (t.os != "linux" || t.libc == "glibc" || t.builder == "go")
        })
        .filter(|t| {
            document
                .config
                .products
                .iter()
                .any(|p| qualified::plan::descriptor(&t.id, &p.build).is_ok())
        })
        .collect::<Vec<_>>();
    let labels = choices
        .iter()
        .map(|t| format!("{} — {} / {} / {}", t.id, t.os, t.arch, t.c_abi))
        .collect::<Vec<_>>();
    let defaults = choices
        .iter()
        .map(|t| document.config.targets.contains(&t.id))
        .collect::<Vec<_>>();
    let Some(selected) = multi(
        "Choose native global targets (Space toggles)",
        &labels,
        &defaults,
    )?
    else {
        return Ok(());
    };
    ensure!(!selected.is_empty(), "select at least one target");
    let mut config = document.config.clone();
    config.targets = selected
        .into_iter()
        .map(|i| choices[i].id.clone())
        .collect();
    let mut doc = document.snapshot.text().parse::<DocumentMut>()?;
    replace(doc.as_table_mut(), "targets", strings(&config.targets));
    for (index, product) in config.products.iter_mut().enumerate() {
        let compatible = config
            .targets
            .iter()
            .filter(|t| qualified::plan::descriptor(t, &product.build).is_ok())
            .cloned()
            .collect::<Vec<_>>();
        ensure!(
            !compatible.is_empty(),
            "product {} has no compatible native target",
            product.id
        );
        println!(
            "Product {} [{}]",
            escaped(&product.id),
            product.build.name()
        );
        let mode = select(
            "Product target scope",
            &[
                "Keep current scope within the selected global targets",
                "Choose explicit compatible targets",
                "Inherit all selected global targets",
                "Cancel settings edit",
            ],
        )?;
        match mode {
            Some(0) => {
                if !product.targets.is_empty() {
                    product.targets.retain(|id| config.targets.contains(id));
                    ensure!(
                        !product.targets.is_empty(),
                        "preserved explicit product scope would be empty; choose an explicit scope"
                    );
                }
            }
            Some(1) => {
                let defaults = compatible
                    .iter()
                    .map(|id| product.targets.is_empty() || product.targets.contains(id))
                    .collect::<Vec<_>>();
                let Some(selected) =
                    multi("Choose explicit product targets", &compatible, &defaults)?
                else {
                    return Ok(());
                };
                ensure!(!selected.is_empty(), "select at least one product target");
                product.targets = selected
                    .into_iter()
                    .map(|i| compatible[i].clone())
                    .collect();
            }
            Some(2) => {
                ensure!(
                    compatible.len() == config.targets.len(),
                    "this builder cannot inherit every global target; choose an explicit compatible scope"
                );
                product.targets.clear();
            }
            _ => return Ok(()),
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

fn edit_cmake(project: &Path, document: &Document) -> Result<()> {
    let products = document
        .config
        .products
        .iter()
        .enumerate()
        .filter(|(_, p)| matches!(p.build, Builder::Cmake(_)))
        .map(|(i, p)| (i, p.id.clone()))
        .collect::<Vec<_>>();
    if products.is_empty() {
        println!(
            "This contract has no CMake products. Initialize a CMake contract with explicit BINARY=TARGET mappings."
        );
        return Ok(());
    }
    let mut labels = vec!["Back".to_string()];
    labels.extend(products.iter().map(|(_, name)| escaped(name)));
    let Some(choice) = select("CMake product", &labels)? else {
        return Ok(());
    };
    if choice == 0 {
        return Ok(());
    }
    let index = products[choice - 1].0;
    let mut config = document.config.clone();
    let product = &mut config.products[index];
    let Builder::Cmake(spec) = &mut product.build else {
        unreachable!()
    };
    println!(
        "{}: source version {}; configuration {}; preset {}; generator {}",
        escaped(&product.id),
        escaped(&spec.version),
        escaped(&spec.configuration),
        escaped(spec.configure_preset.as_deref().unwrap_or("none")),
        escaped(spec.generator.as_deref().unwrap_or("preset/default"))
    );
    for mapping in &spec.binary_targets {
        println!(
            "  {} = {}",
            escaped(&mapping.binary),
            escaped(&mapping.target)
        );
    }
    let field = select(
        "CMake settings",
        &[
            "Back",
            "Source version",
            "Build configuration",
            "Source configure preset",
            "Generator",
            "Declared binaries and executable targets",
            "Add / change cache variable",
            "Remove cache variable",
        ],
    )?;
    let mut changed_keys = Vec::new();
    match field {
        Some(1) => {
            let Some(value) = bounded_text("Explicit semantic application version")? else {
                return Ok(());
            };
            spec.version = value;
            changed_keys.push("version");
        }
        Some(2) => {
            let Some(value) = bounded_text("Exact CMake configuration (for example Release)")?
            else {
                return Ok(());
            };
            spec.configuration = value;
            changed_keys.push("configuration");
        }
        Some(3) => {
            let directory = if product.directory == "." {
                project.to_path_buf()
            } else {
                relship::config::safe_join(project, &product.directory)?
            };
            let names = cmake::configure_presets(&directory)?;
            let mut labels = vec!["No configure preset".to_string()];
            labels.extend(names.iter().map(|s| escaped(s)));
            labels.push("Cancel settings edit".into());
            let Some(choice) = select("Source-provided configure preset", &labels)? else {
                return Ok(());
            };
            if choice == labels.len() - 1 {
                return Ok(());
            }
            spec.configure_preset = if choice == 0 {
                None
            } else {
                Some(names[choice - 1].clone())
            };
            changed_keys.push("configure-preset");
        }
        Some(4) => {
            match select(
                "Generator",
                &[
                    "Use source preset / CMake default",
                    "Enter explicit generator",
                    "Cancel settings edit",
                ],
            )? {
                Some(0) => spec.generator = None,
                Some(1) => {
                    let Some(value) = bounded_text("CMake generator name")? else {
                        return Ok(());
                    };
                    spec.generator = Some(value);
                }
                _ => return Ok(()),
            };
            changed_keys.push("generator");
        }
        Some(5) => {
            let Some(value) = bounded_text("Declared binary names, separated by commas")? else {
                return Ok(());
            };
            let binaries = value
                .split(',')
                .map(str::trim)
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let mut mappings = Vec::new();
            for binary in &binaries {
                relship::config::identifier(binary)?;
                let Some(target) = bounded_text(&format!("CMake EXECUTABLE target for {binary}"))?
                else {
                    return Ok(());
                };
                mappings.push(cmake::BinaryTarget {
                    binary: binary.clone(),
                    target,
                });
            }
            product.binaries = binaries;
            spec.binary_targets = mappings;
            changed_keys.push("binary-targets");
        }
        Some(6) => {
            let Some(value) =
                bounded_text("Cache variable as NAME=VALUE (an empty value is allowed)")?
            else {
                return Ok(());
            };
            let (name, value) = value
                .split_once('=')
                .context("cache variable requires NAME=VALUE")?;
            spec.cache_variables.insert(name.into(), value.into());
            changed_keys.push("cache-variables");
        }
        Some(7) => {
            let names = spec.cache_variables.keys().cloned().collect::<Vec<_>>();
            if names.is_empty() {
                println!("No explicit cache variables.");
                return Ok(());
            }
            let mut labels = vec!["Cancel settings edit".into()];
            labels.extend(names.iter().map(|s| escaped(s)));
            let Some(choice) = select("Remove cache variable", &labels)? else {
                return Ok(());
            };
            if choice == 0 {
                return Ok(());
            }
            spec.cache_variables.remove(&names[choice - 1]);
            changed_keys.push("cache-variables");
        }
        _ => return Ok(()),
    }
    cmake::validate(spec, &product.binaries)?;
    let serialized = serde_json::to_value(&product.build)?;
    let mut doc = document.snapshot.text().parse::<DocumentMut>()?;
    let table = product_table(&mut doc, index)?;
    if changed_keys.contains(&"binary-targets") {
        replace(table, "binaries", strings(&product.binaries));
    }
    let build = child(table, "build")?;
    for key in changed_keys {
        if let Some(value) = serialized.get(key) {
            replace(build, key, literal(value.clone())?);
        } else {
            build.remove(key);
        }
    }
    document.review_save(doc, &config)
}

fn formats_value(formats: &[Format]) -> Value {
    strings(&formats.iter().map(|f| f.name().into()).collect::<Vec<_>>())
}
fn set_formats(table: &mut dyn TableLike, os: &str, formats: &[Format]) -> Result<()> {
    replace(
        child(child(table, "packaging")?, "formats")?,
        os,
        formats_value(formats),
    );
    Ok(())
}

fn edit_formats(document: &Document) -> Result<()> {
    let mut scopes = vec!["Back".to_string(), "Global package defaults".to_string()];
    scopes.extend(
        document
            .config
            .products
            .iter()
            .map(|p| format!("Product {}", escaped(&p.id))),
    );
    let Some(scope) = select("Package format scope", &scopes)? else {
        return Ok(());
    };
    if scope == 0 {
        return Ok(());
    }
    let os = match select("Operating system", &["Back", "Linux", "macOS", "Windows"])? {
        Some(1) => "linux",
        Some(2) => "macos",
        Some(3) => "windows",
        _ => return Ok(()),
    };
    let mut config = document.config.clone();
    let mut doc = document.snapshot.text().parse::<DocumentMut>()?;
    if scope >= 2 {
        let index = scope - 2;
        match select(
            "Product format policy",
            &[
                "Choose explicit formats",
                "Inherit global formats",
                "Cancel settings edit",
            ],
        )? {
            Some(1) => {
                config.products[index].packaging.formats.remove(os);
                if let Some(table) = product_table(&mut doc, index)?
                    .get_mut("packaging")
                    .and_then(Item::as_table_like_mut)
                    .and_then(|p| p.get_mut("formats"))
                    .and_then(Item::as_table_like_mut)
                {
                    table.remove(os);
                }
                if !complete_native_metadata(&mut doc, &mut config)? {
                    return Ok(());
                }
                return document.review_save(doc, &config);
            }
            Some(0) => (),
            _ => return Ok(()),
        }
    }
    let available = FORMATS
        .iter()
        .copied()
        .filter(|format| os == "linux" || !format.is_native())
        .collect::<Vec<_>>();
    let current = if scope >= 2 {
        qualified::config::formats(&config, scope - 2, os)
    } else {
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
    };
    let labels = available
        .iter()
        .map(|format| format.name().to_string())
        .collect::<Vec<_>>();
    let defaults = available
        .iter()
        .map(|f| current.contains(f))
        .collect::<Vec<_>>();
    let Some(selected) = multi("Choose package formats (Space toggles)", &labels, &defaults)?
    else {
        return Ok(());
    };
    ensure!(!selected.is_empty(), "select at least one package format");
    let formats = selected
        .into_iter()
        .map(|i| available[i])
        .collect::<Vec<_>>();
    if scope == 1 {
        config.packaging.formats.insert(os.into(), formats.clone());
        set_formats(doc.as_table_mut(), os, &formats)?;
    } else {
        config.products[scope - 2]
            .packaging
            .formats
            .insert(os.into(), formats.clone());
        set_formats(product_table(&mut doc, scope - 2)?, os, &formats)?;
    }
    if !complete_native_metadata(&mut doc, &mut config)? {
        return Ok(());
    }
    document.review_save(doc, &config)
}

fn complete_native_metadata(doc: &mut DocumentMut, config: &mut Config) -> Result<bool> {
    for index in 0..config.products.len() {
        let product = &config.products[index];
        let linux = config
            .targets
            .iter()
            .filter(|id| product.targets.is_empty() || product.targets.contains(id))
            .any(|id| catalog::resolve(id).is_ok_and(|t| t.os == "linux"));
        if !linux
            || !qualified::config::formats(config, index, "linux")
                .iter()
                .any(|f| f.is_native())
            || product.packaging.native.is_some()
        {
            continue;
        }
        println!("Native package metadata for {}", escaped(&product.id));
        let Some(name) = bounded_text("Native package name (lowercase)")? else {
            return Ok(false);
        };
        relship::delivery::config::package_name(&name)?;
        let Some(description) = bounded_text("Package description")? else {
            return Ok(false);
        };
        let Some(license) = bounded_text("Package license")? else {
            return Ok(false);
        };
        let Some(maintainer) = bounded_text("Package maintainer")? else {
            return Ok(false);
        };
        let homepage = match select(
            "Package homepage",
            &["Omit homepage", "Enter homepage", "Cancel settings edit"],
        )? {
            Some(0) => None,
            Some(1) => {
                let Some(value) = bounded_text("Homepage URL")? else {
                    return Ok(false);
                };
                Some(value)
            }
            _ => return Ok(false),
        };
        let native = NativeMetadata {
            name: Some(name),
            description,
            license,
            maintainer,
            homepage,
            dependencies: BTreeMap::new(),
            install: Vec::new(),
        };
        replace(
            child(product_table(doc, index)?, "packaging")?,
            "native",
            literal(serde_json::to_value(&native)?)?,
        );
        config.products[index].packaging.native = Some(native);
    }
    Ok(true)
}

pub(super) fn migrate_menu(project: &Path) -> Result<()> {
    let proposal = qualified_cli::migration_proposal(project)?;
    println!("Explicit upgrade: schema 4 -> 5");
    for warning in &proposal.warnings {
        println!("{}", escaped(warning));
    }
    show_document("--- current release.toml", &proposal.original);
    show_document("+++ proposed release.toml", &proposal.proposed);
    println!("An exact schema 4 backup is created without overwriting an existing backup.");
    if confirm("Save this schema 5 compatibility contract and original backup?")? {
        println!(
            "Saved {}. Review and commit before planning.",
            path_label(&qualified_cli::apply_migration(project, &proposal)?)
        );
    } else {
        println!("Discarded migration proposal.");
    }
    Ok(())
}

fn show_plan(plan: &Plan) {
    println!("\nSource-bound plan for review:");
    println!(
        "Plan: {}\nSource commit: {}\nExecution protocol: 6",
        plan.id, plan.source.commit
    );
    println!(
        "Build units: {}; expected packages: {}; independent validations: {}",
        plan.builds.len(),
        plan.packages.len(),
        plan.validations.len()
    );
    for (index, build) in plan.builds.iter().enumerate() {
        println!(
            "  {} — {} / {} — native {} — environment {}",
            escaped(&build.id),
            escaped(&plan.config.products[build.product].id),
            escaped(&build.target),
            build.profile.arch.name(),
            escaped(&build.profile.id)
        );
        match &build.profile.environment {
            Environment::LinuxContainer { image, .. } => println!(
                "    glibc 2.17 baseline; {} / {}; emulation forbidden",
                escaped(&image.platform),
                escaped(&image.reference)
            ),
            Environment::NativeSdk { sdk, .. } => println!(
                "    SDK {} {}; content SHA-256 {}",
                escaped(&sdk.sdk_id),
                escaped(&sdk.sdk_version),
                sdk.sdk_content_sha256
            ),
        }
        for (package_index, package) in plan
            .packages
            .iter()
            .enumerate()
            .filter(|(_, p)| p.build == index)
        {
            println!(
                "    {} — {}",
                escaped(&package.filename),
                package.format.name()
            );
            for validation in plan
                .validations
                .iter()
                .filter(|v| v.package == package_index)
            {
                println!(
                    "      {}: {}",
                    escaped(&validation.kind),
                    escaped(&validation.environment)
                );
            }
        }
    }
    println!(
        "Builds and final-package checks use the exact planned environments. An incomplete stage stops preparation; completed checkpoints can be resumed. Preparation evidence does not authorize publication."
    );
}

fn ensure_plan(path: &Path, reviewed: &Plan) -> Result<()> {
    ensure!(
        qualified::plan::load(path)? == *reviewed,
        "saved plan changed after review; inspect it again before running"
    );
    Ok(())
}

fn choose_nfpm(
    project: &Path,
    plan: &Plan,
    pending_builds: &[usize],
    completed_packages: &[usize],
) -> Result<Option<Option<PathBuf>>> {
    if !plan.packages.iter().enumerate().any(|(index, p)| {
        pending_builds.contains(&p.build)
            && !completed_packages.contains(&index)
            && p.format.is_native()
    }) {
        return Ok(Some(None));
    }
    println!("Pending native packages require the pinned nFPM 2.49.0 backend.");
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
    let tool = relship::delivery::native::resolve_nfpm(requested.as_deref())?;
    println!(
        "Native backend: {} (version {}; SHA-256 {})",
        path_label(&tool.path),
        tool.version,
        tool.sha256
    );
    Ok(Some(Some(tool.path)))
}

pub(super) fn create_plan(project: &Path) -> Result<()> {
    let root = source::root(project)?;
    println!("Resolving the committed source and release contract…");
    let plan = qualified::plan::create(&root)?;
    show_plan(&plan);
    let build = loop {
        match select(
            "Reviewed plan — no files have been written",
            &[
                "Return to home",
                "Save this plan only",
                "Save and build this plan (environment checks required)",
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
    super::super::write_new_json(&root, &path, &plan)?;
    println!("Saved plan: {}", path_label(&path));
    if !build {
        return Ok(());
    }
    let selected = (0..plan.builds.len()).collect::<Vec<_>>();
    let Some(nfpm) = choose_nfpm(project, &plan, &selected, &[])? else {
        return Ok(());
    };
    let output = directory.join("attempt");
    println!("Build attempt: {}", path_label(&output));
    println!("Every reviewed build, package and environment validation is required.");
    if confirm("Build this saved qualified plan now?")? {
        ensure_plan(&path, &plan)?;
        run_command(
            project,
            Command::Rehearse {
                plan: path,
                output,
                skip_runtime: false,
                nfpm,
                runtime: Default::default(),
            },
        )?;
    }
    Ok(())
}

pub(super) fn resume_attempt(project: &Path, output: &Path) -> Result<()> {
    let path = output.join("plan.json");
    let plan = qualified::plan::load(&path)?;
    let receipt = qualified::run::verify(output, false)?;
    println!(
        "Source commit: {}; engine: {}\nPlan: {}",
        plan.source.commit, plan.engine_source_id, plan.id
    );
    println!("Saved build selection (completed checkpoints are rechecked):");
    for index in &receipt.selected {
        let build = &plan.builds[*index];
        println!("  {} — {}", escaped(&build.id), escaped(&build.target));
    }
    println!(
        "Payload checkpoints: {}; package checkpoints: {}; environment validation checkpoints: {}",
        receipt.payloads.len(),
        receipt.packages.len(),
        receipt.validations.len()
    );
    for failure in &receipt.failures {
        println!(
            "Previous failure at {}: {}",
            escaped(&failure.stage),
            escaped(&failure.message)
        );
    }
    println!(
        "Resume requires the original matching source and exact environment pins. Saved checkpoints are reused after verification; package and validation retries do not rerun completed payloads."
    );
    let retry_builds = receipt
        .selected
        .iter()
        .copied()
        .filter(|index| {
            !receipt.payloads.contains_key(index)
                && !plan.config.products[plan.builds[*index].product]
                    .prepare
                    .is_empty()
                && receipt
                    .failures
                    .iter()
                    .any(|failure| failure.stage == format!("build-{index}"))
        })
        .collect::<Vec<_>>();
    let allow_retry = if retry_builds.is_empty() {
        Vec::new()
    } else {
        let labels = retry_builds
            .iter()
            .map(|index| {
                let build = &plan.builds[*index];
                format!("{} — {}", escaped(&build.id), escaped(&build.target))
            })
            .collect::<Vec<_>>();
        println!("These failed builds have prepare hooks whose side effects may run again.");
        let Some(selected) = multi(
            "Allow retry for reviewed builds (none selected)",
            &labels,
            &vec![false; labels.len()],
        )?
        else {
            return Ok(());
        };
        selected
            .into_iter()
            .map(|index| plan.builds[retry_builds[index]].id.clone())
            .collect()
    };
    let completed_packages = receipt.packages.keys().copied().collect::<Vec<_>>();
    let Some(nfpm) = choose_nfpm(project, &plan, &receipt.selected, &completed_packages)? else {
        return Ok(());
    };
    println!("Resume attempt: {}", path_label(output));
    println!("Allow retry: {}", escaped(&allow_retry.join(", ")));
    if confirm("Resume this qualified attempt with these explicit retry permissions?")? {
        ensure_plan(&path, &plan)?;
        ensure!(
            qualified::run::verify(output, false)? == receipt,
            "saved receipt changed after review; inspect it again before resuming"
        );
        run_command(
            project,
            Command::Resume {
                output: output.to_path_buf(),
                allow_retry,
                key: None,
                nfpm,
                runtime: Default::default(),
            },
        )?;
    }
    Ok(())
}

pub(super) fn initialize_menu(project: &Path) -> Result<()> {
    println!(
        "Initialize CMake C with explicit source version and executable target mappings. CMake is not run for discovery."
    );
    let Some(directory) = bounded_text("CMake directory relative to the project (use . for root)")?
    else {
        return Ok(());
    };
    let Some(version) = bounded_text("Application semantic version")? else {
        return Ok(());
    };
    let Some(mappings) = bounded_text("Binary=target mappings, separated by commas")? else {
        return Ok(());
    };
    let mappings = mappings
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    ensure!(
        !mappings.is_empty(),
        "declare at least one binary=target mapping"
    );
    let directory_path = if directory == "." {
        project.to_path_buf()
    } else {
        relship::config::safe_join(project, &directory)?
    };
    let presets = cmake::configure_presets(&directory_path)?;
    let mut labels = vec!["No configure preset".into()];
    labels.extend(presets.iter().map(|s| escaped(s)));
    labels.push("Cancel initialization".into());
    let Some(choice) = select("Source configure preset", &labels)? else {
        return Ok(());
    };
    if choice == labels.len() - 1 {
        return Ok(());
    }
    let preset = if choice == 0 {
        None
    } else {
        Some(presets[choice - 1].clone())
    };
    let generator = match select(
        "CMake generator",
        &[
            "Use preset / CMake default",
            "Enter generator",
            "Cancel initialization",
        ],
    )? {
        Some(0) => None,
        Some(1) => {
            let Some(value) = bounded_text("CMake generator name")? else {
                return Ok(());
            };
            Some(value)
        }
        _ => return Ok(()),
    };
    let spec = cmake::Spec {
        version: version.clone(),
        configuration: "Release".into(),
        configure_preset: preset.clone(),
        generator: generator.clone(),
        binary_targets: mappings
            .iter()
            .map(|m| {
                let (binary, target) = m
                    .split_once('=')
                    .context("mapping requires BINARY=TARGET")?;
                Ok(cmake::BinaryTarget {
                    binary: binary.into(),
                    target: target.into(),
                })
            })
            .collect::<Result<Vec<_>>>()?,
        cache_variables: BTreeMap::new(),
    };
    cmake::validate(
        &spec,
        &spec
            .binary_targets
            .iter()
            .map(|m| m.binary.clone())
            .collect::<Vec<_>>(),
    )?;
    println!(
        "\nNew schema 5 contract: {}",
        path_label(&project.join("release.toml"))
    );
    println!(
        "Directory: {}; source version: {}; configuration: Release",
        escaped(&directory),
        escaped(&version)
    );
    for mapping in &spec.binary_targets {
        println!(
            "  {} = {}",
            escaped(&mapping.binary),
            escaped(&mapping.target)
        );
    }
    println!(
        "Configure preset: {}; generator: {}",
        escaped(preset.as_deref().unwrap_or("none")),
        escaped(generator.as_deref().unwrap_or("preset/default"))
    );
    println!(
        "Linux broad policy selects glibc 2.17 build inputs and independent final-package validation. Native macOS/Windows planning needs reviewed SDK pins in release-ci.toml."
    );
    let proposed = qualified_cli::initialization_proposal(
        project,
        &directory,
        "cmake",
        Some(&version),
        &mappings,
        preset.as_deref(),
        generator.as_deref(),
    )?;
    show_document(
        "+++ proposed release.toml",
        &toml::to_string_pretty(&proposed)?,
    );
    qualified_cli::compatibility_summary(&proposed)?;
    if confirm("Create this source-bound CMake contract without overwriting an existing file?")? {
        run_command(
            project,
            Command::Init {
                builder: Some("cmake".into()),
                directory,
                app_version: Some(version),
                schema: Some(5),
                cmake_target: mappings,
                configure_preset: preset,
                generator,
            },
        )?;
        return settings_menu(project);
    }
    Ok(())
}
