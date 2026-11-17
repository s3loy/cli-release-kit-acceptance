//! Bounded CMake C builds, using File API replies as artifact provenance.
use crate::{config, source};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

mod inputs;
pub use inputs::{InputSelection, validate_configured_inputs, validate_preserved_inputs};

const REPLY_DIR: &str = ".cmake/api/v1/reply";
const QUERY_DIR: &str = ".cmake/api/v1/query/client-relship";
const MAX_JSON: u64 = 8 * 1024 * 1024;
const MAX_CLOSURE: u64 = 64 * 1024 * 1024;
const MAX_FILES: usize = 4096;

fn release() -> String {
    "Release".into()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Spec {
    pub version: String,
    #[serde(default = "release")]
    pub configuration: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configure_preset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generator: Option<String>,
    pub binary_targets: Vec<BinaryTarget>,
    #[serde(default)]
    pub cache_variables: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct BinaryTarget {
    pub binary: String,
    pub target: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactWitness {
    pub binary: String,
    pub target: String,
    pub target_id: String,
    /// Relative to the owned build tree; selected by nameOnDisk, never array order.
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolchainObservation {
    pub language: String,
    pub compiler: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Witness {
    pub spec: Spec,
    pub source: PathBuf,
    pub build: PathBuf,
    /// Original paths reported inside the execution environment (for example /source).
    pub reported_source: PathBuf,
    pub reported_build: PathBuf,
    pub index: String,
    /// The complete transitive JSON reply closure, including the original index.
    pub reply_files: BTreeMap<String, String>,
    pub cmake_version: String,
    pub generator: String,
    pub multi_config: bool,
    pub artifacts: Vec<ArtifactWitness>,
    pub cache: BTreeMap<String, String>,
    pub toolchains: Vec<ToolchainObservation>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StagedArtifact {
    pub binary: String,
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

fn single_line(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && !value.chars().any(char::is_control),
        "CMake {label} must be nonempty single-line text"
    );
    Ok(())
}

fn cache_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && !name.as_bytes()[0].is_ascii_digit(),
        "invalid CMake cache variable: {name}"
    );
    Ok(())
}

pub fn validate(spec: &Spec, binaries: &[String]) -> Result<()> {
    semver::Version::parse(spec.version.strip_prefix('v').unwrap_or(&spec.version))
        .context("CMake requires an explicit semantic source version")?;
    config::identifier(&spec.configuration)?;
    if let Some(preset) = &spec.configure_preset {
        config::identifier(preset)?;
    }
    if let Some(generator) = &spec.generator {
        single_line(generator, "generator")?;
    }
    ensure!(
        !spec.binary_targets.is_empty(),
        "CMake requires binary-target mappings"
    );
    let mut names = BTreeSet::new();
    let mut targets = BTreeSet::new();
    for mapping in &spec.binary_targets {
        config::identifier(&mapping.binary)?;
        config::identifier(&mapping.target)?;
        ensure!(
            !matches!(
                mapping.target.to_ascii_lowercase().as_str(),
                "install"
                    | "package"
                    | "package_source"
                    | "test"
                    | "run_tests"
                    | "all_build"
                    | "zero_check"
                    | "clean"
                    | "all"
                    | "help"
                    | "edit_cache"
                    | "rebuild_cache"
                    | "preinstall"
                    | "list_install_components"
            ),
            "CMake binary mapping cannot select a reserved build action"
        );
        ensure!(
            names.insert(mapping.binary.clone()),
            "duplicate CMake binary mapping"
        );
        ensure!(
            targets.insert(mapping.target.clone()),
            "duplicate CMake target mapping"
        );
    }
    ensure!(
        binaries.iter().collect::<BTreeSet<_>>().len() == binaries.len()
            && names == binaries.iter().cloned().collect(),
        "CMake binary-target mappings must exactly cover declared binaries"
    );
    for (name, value) in &spec.cache_variables {
        cache_name(name)?;
        ensure!(!value.contains('\0'), "NUL in CMake cache variable {name}");
        ensure!(
            !matches!(
                name.as_str(),
                "CMAKE_HOME_DIRECTORY" | "CMAKE_CACHEFILE_DIR"
            ),
            "CMake cache variable {name} is owned by the release adapter"
        );
    }
    validate_configuration(spec, &spec.cache_variables)?;
    Ok(())
}

fn validate_spec(spec: &Spec) -> Result<()> {
    validate(
        spec,
        &spec
            .binary_targets
            .iter()
            .map(|m| m.binary.clone())
            .collect::<Vec<_>>(),
    )
}

fn validate_configuration(spec: &Spec, cache: &BTreeMap<String, String>) -> Result<()> {
    if let Some(value) = cache.get("CMAKE_BUILD_TYPE") {
        ensure!(
            value == &spec.configuration,
            "CMake build type conflicts with selected configuration"
        );
    }
    if let Some(value) = cache.get("CMAKE_CONFIGURATION_TYPES") {
        ensure!(
            value.split(';').any(|v| v == spec.configuration),
            "CMake configuration list excludes the selected configuration"
        );
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<String> {
    Ok(path
        .to_str()
        .context("non-UTF8 CMake path")?
        .replace('\\', "/"))
}

fn optional_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn owned_directory(path: &Path) -> Result<PathBuf> {
    ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "CMake owned directory is a symlink: {}",
        path.display()
    );
    ensure!(
        path.is_dir(),
        "CMake directory is not a directory: {}",
        path.display()
    );
    Ok(fs::canonicalize(path)?)
}

fn read_json(path: &Path) -> Result<(Vec<u8>, Value)> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "CMake JSON must be a regular file: {}",
        path.display()
    );
    ensure!(meta.len() <= MAX_JSON, "CMake JSON exceeds size bound");
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_JSON + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_JSON,
        "CMake JSON exceeds size bound"
    );
    let value = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid CMake JSON: {}", path.display()))?;
    let strict: Value = crate::cohort::io::read_json(path)?;
    ensure!(value == strict, "CMake JSON changed during read");
    Ok((bytes, value))
}

#[derive(Default)]
struct Presets {
    files: BTreeSet<String>,
    values: BTreeMap<String, Value>,
}

fn load_presets(source: &Path, required: bool) -> Result<Presets> {
    ensure!(
        !optional_exists(&source.join("CMakeUserPresets.json"))?,
        "CMakeUserPresets.json is unsupported in source-bound release builds"
    );
    let mut presets = Presets::default();
    let mut visiting = BTreeSet::new();
    if required || optional_exists(&source.join("CMakePresets.json"))? {
        load_preset_file(source, "CMakePresets.json", &mut presets, &mut visiting)?;
    }
    Ok(presets)
}

fn load_preset_file(
    source: &Path,
    name: &str,
    presets: &mut Presets,
    visiting: &mut BTreeSet<String>,
) -> Result<()> {
    config::relative(name)?;
    ensure!(
        name.rsplit('/').next() != Some("CMakeUserPresets.json"),
        "CMake user preset includes are unsupported"
    );
    ensure!(!visiting.contains(name), "CMake preset include cycle");
    if presets.files.contains(name) {
        return Ok(());
    }
    ensure!(
        presets.files.len() + visiting.len() < 128,
        "CMake preset include graph exceeds bound"
    );
    visiting.insert(name.into());
    let (_, document) = read_json(&config::safe_join(source, name)?)?;
    let version = document["version"]
        .as_u64()
        .context("CMake preset schema version missing")?;
    ensure!(
        (1..=10).contains(&version),
        "unsupported CMake preset schema version"
    );
    if let Some(includes) = document.get("include") {
        for include in includes
            .as_array()
            .context("CMake preset include must be an array")?
        {
            let include = include
                .as_str()
                .context("CMake preset include must be a string")?;
            // Macros and parent traversals could introduce ambient or external files.
            ensure!(
                !include.contains('$'),
                "CMake preset include macros are unsupported"
            );
            config::relative(include)?;
            let parent = Path::new(name).parent().unwrap_or(Path::new(""));
            let included = path_text(&parent.join(include))?;
            load_preset_file(source, &included, presets, visiting)?;
        }
    }
    if let Some(values) = document.get("configurePresets") {
        for preset in values
            .as_array()
            .context("CMake configurePresets must be an array")?
        {
            let preset_name = string(preset, "name")?;
            single_line(preset_name, "preset name")?;
            ensure!(
                presets
                    .values
                    .insert(preset_name.into(), preset.clone())
                    .is_none(),
                "duplicate CMake configure preset: {preset_name}"
            );
        }
    }
    visiting.remove(name);
    presets.files.insert(name.into());
    Ok(())
}

fn effective_preset(
    name: &str,
    presets: &Presets,
    visiting: &mut BTreeSet<String>,
) -> Result<Value> {
    ensure!(
        visiting.insert(name.into()),
        "CMake preset inheritance cycle"
    );
    ensure!(
        visiting.len() <= 128,
        "CMake preset inheritance exceeds bound"
    );
    let own = presets
        .values
        .get(name)
        .with_context(|| format!("unknown CMake configure preset: {name}"))?;
    let mut merged = serde_json::Map::new();
    let parents = match own.get("inherits") {
        None => vec![],
        Some(Value::String(value)) => vec![value.as_str()],
        Some(Value::Array(values)) => values
            .iter()
            .map(|v| v.as_str().context("invalid CMake preset parent"))
            .collect::<Result<Vec<_>>>()?,
        _ => bail!("invalid CMake preset inherits"),
    };
    // Earlier parents win. Per-key cache/environment inheritance follows CMake.
    for parent in parents.into_iter().rev() {
        let inherited = effective_preset(parent, presets, visiting)?;
        merge_preset(
            &mut merged,
            inherited.as_object().context("invalid CMake preset")?,
        );
    }
    merge_preset(
        &mut merged,
        own.as_object().context("invalid CMake preset")?,
    );
    visiting.remove(name);
    Ok(Value::Object(merged))
}

fn merge_preset(
    destination: &mut serde_json::Map<String, Value>,
    incoming: &serde_json::Map<String, Value>,
) {
    for (key, value) in incoming {
        if matches!(
            key.as_str(),
            "name" | "hidden" | "inherits" | "description" | "displayName"
        ) {
            continue;
        }
        if matches!(key.as_str(), "cacheVariables" | "environment")
            && let Some(object) = value.as_object()
        {
            let existing = destination
                .entry(key.clone())
                .or_insert_with(|| serde_json::json!({}));
            if let Some(existing) = existing.as_object_mut() {
                existing.extend(object.clone());
                continue;
            }
        }
        destination.insert(key.clone(), value.clone());
    }
}

fn selected_preset(source: &Path, spec: &Spec) -> Result<Value> {
    let presets = load_presets(source, spec.configure_preset.is_some())?;
    if let Some(name) = &spec.configure_preset {
        let own = presets
            .values
            .get(name)
            .context("CMake configure preset does not exist")?;
        ensure!(
            own["hidden"].as_bool() != Some(true),
            "selected CMake configure preset is hidden"
        );
        effective_preset(name, &presets, &mut BTreeSet::new())
    } else {
        Ok(serde_json::json!({}))
    }
}

/// List visible, source-provided configure presets without running CMake.
pub fn configure_presets(source: &Path) -> Result<Vec<String>> {
    let source = owned_directory(source)?;
    let presets = load_presets(&source, false)?;
    let mut names = Vec::new();
    for (name, value) in &presets.values {
        if value["hidden"].as_bool() != Some(true) {
            effective_preset(name, &presets, &mut BTreeSet::new())?;
            names.push(name.clone());
        }
    }
    Ok(names)
}

fn preset_cache(preset: &Value) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    if let Some(cache) = preset.get("cacheVariables") {
        for (key, entry) in cache
            .as_object()
            .context("invalid CMake preset cacheVariables")?
        {
            if entry.is_null() {
                continue;
            }
            let entry = entry.get("value").unwrap_or(entry);
            let value = match entry {
                Value::String(value) => value.clone(),
                Value::Bool(value) => if *value { "TRUE" } else { "FALSE" }.into(),
                _ => bail!("unsupported CMake preset cache value: {key}"),
            };
            result.insert(key.clone(), value);
        }
    }
    Ok(result)
}

/// Static planning input checks. This never configures a project or discovers targets.
pub fn source_inputs(
    root: &Path,
    project: &str,
    spec: &Spec,
    tracked: &BTreeMap<String, String>,
) -> Result<Vec<String>> {
    validate_spec(spec)?;
    let root = owned_directory(root)?;
    let directory = if project == "." {
        root.clone()
    } else {
        config::safe_join(&root, project)?
    };
    let directory = owned_directory(&directory)?;
    ensure!(
        directory.starts_with(&root),
        "CMake project leaves the source tree"
    );
    let presets = load_presets(&directory, spec.configure_preset.is_some())?;
    let preset = selected_preset(&directory, spec)?;
    let mut inputs = vec!["CMakeLists.txt".to_string()];
    inputs.extend(presets.files);
    let mut cache = preset_cache(&preset)?;
    validate_configuration(spec, &cache)?;
    cache.extend(spec.cache_variables.clone());
    if let Some(toolchain) = preset_option(&preset, "toolchainFile")? {
        cache.insert("CMAKE_TOOLCHAIN_FILE".into(), toolchain);
    }
    for (key, value) in cache {
        if key == "CMAKE_TOOLCHAIN_FILE"
            || (key.starts_with("CMAKE_PROJECT_") && key.contains("INCLUDE"))
        {
            for raw in value.split(';').filter(|part| !part.is_empty()) {
                let expanded = raw.replace("${sourceDir}", &path_text(&directory)?);
                ensure!(
                    !expanded.contains('$'),
                    "ambient CMake script path macros are unsupported: {key}"
                );
                let path = Path::new(&expanded);
                let relative = if path.is_absolute() {
                    path.strip_prefix(&directory)
                        .context("CMake project script leaves the tracked project")?
                } else {
                    path
                };
                let name = path_text(relative)?;
                config::relative(&name)?;
                inputs.push(name);
            }
        }
    }
    inputs.sort();
    inputs.dedup();
    let mut names = Vec::new();
    for input in inputs {
        let path = config::safe_join(&directory, &input)?;
        let name = path_text(path.strip_prefix(&root)?)?;
        let expected = tracked
            .get(&name)
            .with_context(|| format!("CMake input must be tracked: {name}"))?;
        ensure!(
            fs::metadata(&path)?.is_file(),
            "CMake source input must be a regular file"
        );
        ensure!(
            source::file_digest(&path)? == *expected,
            "CMake source input differs from source identity: {name}"
        );
        names.push(name);
    }
    names.sort();
    Ok(names)
}

/// Prepare owned, stateless queries before configure, without touching CMake replies.
pub fn write_query(build: &Path) -> Result<()> {
    if optional_exists(build)? {
        ensure!(
            !fs::symlink_metadata(build)?.file_type().is_symlink(),
            "CMake build directory is a symlink"
        );
    }
    fs::create_dir_all(build)?;
    let build = owned_directory(build)?;
    let query = config::safe_join(&build, QUERY_DIR)?;
    fs::create_dir_all(&query)?;
    for name in ["codemodel-v2", "cache-v2", "toolchains-v1", "cmakeFiles-v1"] {
        let path = config::safe_join(&build, &format!("{QUERY_DIR}/{name}"))?;
        if optional_exists(&path)? {
            ensure!(
                fs::symlink_metadata(&path)?.is_file() && fs::metadata(&path)?.len() == 0,
                "existing CMake query is not an empty regular file"
            );
        } else {
            OpenOptions::new().write(true).create_new(true).open(path)?;
        }
    }
    Ok(())
}

fn profile_options(args: &[String]) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        ensure!(!arg.contains('\0'), "NUL in CMake profile argument");
        let (key, value) = if arg == "-D" {
            i += 1;
            parse_definition(
                args.get(i)
                    .context("missing CMake profile cache definition")?,
            )?
        } else if let Some(definition) = arg.strip_prefix("-D") {
            parse_definition(definition)?
        } else if matches!(arg.as_str(), "-G" | "-A" | "-T" | "--toolchain") {
            i += 1;
            let value = args
                .get(i)
                .context("missing CMake profile option value")?
                .clone();
            let key = match arg.as_str() {
                "-G" => "CMAKE_GENERATOR",
                "-A" => "CMAKE_GENERATOR_PLATFORM",
                "-T" => "CMAKE_GENERATOR_TOOLSET",
                _ => "CMAKE_TOOLCHAIN_FILE",
            };
            (key.into(), value)
        } else if let Some(value) = arg.strip_prefix("--toolchain=") {
            ("CMAKE_TOOLCHAIN_FILE".into(), value.into())
        } else {
            bail!("unsupported CMake profile argument: {arg}");
        };
        ensure!(
            result.insert(key.clone(), value).is_none(),
            "duplicate CMake profile option: {key}"
        );
        i += 1;
    }
    Ok(result)
}

fn parse_definition(definition: &str) -> Result<(String, String)> {
    let (name, value) = definition
        .split_once('=')
        .context("CMake cache definition requires =")?;
    let name = name.split_once(':').map_or(name, |(name, _)| name);
    cache_name(name)?;
    Ok((name.into(), value.into()))
}

fn preset_option(preset: &Value, field: &str) -> Result<Option<String>> {
    match preset.get(field) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(Value::Object(value)) if matches!(field, "architecture" | "toolset") => {
            if value.get("strategy").and_then(Value::as_str) == Some("external") {
                Ok(None)
            } else {
                Ok(value
                    .get("value")
                    .and_then(Value::as_str)
                    .map(str::to_owned))
            }
        }
        _ => bail!("invalid CMake preset {field}"),
    }
}

fn validate_generator(spec: &Spec, options: &BTreeMap<String, String>) -> Result<()> {
    if let Some(generator) = &spec.generator
        && let Some(value) = options.get("CMAKE_GENERATOR")
    {
        ensure!(
            value == generator,
            "CMake generator conflicts with preset/profile"
        );
    }
    Ok(())
}

/// Resolve the source-selected generator before choosing native build tools.
/// `None` leaves generator selection to the platform profile or CMake default.
pub fn effective_generator(source: &Path, spec: &Spec) -> Result<Option<String>> {
    validate_spec(spec)?;
    let source = owned_directory(source)?;
    let preset = selected_preset(&source, spec)?;
    let mut inherited = preset_cache(&preset)?;
    validate_configuration(spec, &inherited)?;
    if let Some(generator) = preset_option(&preset, "generator")? {
        inherited.insert("CMAKE_GENERATOR".into(), generator);
    }
    validate_generator(spec, &inherited)?;
    Ok(spec
        .generator
        .clone()
        .or_else(|| inherited.remove("CMAKE_GENERATOR")))
}

/// Returns argv for Commands; profile options may set SDK/toolchain/platform values.
pub fn configure_argv(
    source: &Path,
    build: &Path,
    spec: &Spec,
    profile_args: &[String],
) -> Result<Vec<String>> {
    validate_spec(spec)?;
    let source = owned_directory(source)?;
    let build = if build.exists() {
        owned_directory(build)?
    } else {
        ensure!(build.is_absolute(), "CMake build path must be absolute");
        ensure!(
            !build.components().any(|component| matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )),
            "CMake build path must not contain parent/current traversal"
        );
        build.to_path_buf()
    };
    ensure!(
        build != source && !source.starts_with(&build),
        "CMake requires an owned out-of-source build directory"
    );
    let preset = selected_preset(&source, spec)?;
    let mut inherited = preset_cache(&preset)?;
    validate_configuration(spec, &inherited)?;
    for (field, key) in [
        ("generator", "CMAKE_GENERATOR"),
        ("architecture", "CMAKE_GENERATOR_PLATFORM"),
        ("toolset", "CMAKE_GENERATOR_TOOLSET"),
        ("toolchainFile", "CMAKE_TOOLCHAIN_FILE"),
    ] {
        if let Some(value) = preset_option(&preset, field)? {
            inherited.insert(key.into(), value);
        }
    }
    let profile = profile_options(profile_args)?;
    validate_configuration(spec, &profile)?;
    for options in [&inherited, &profile] {
        validate_generator(spec, options)?;
    }
    for (key, value) in &profile {
        for options in [&inherited, &spec.cache_variables] {
            if let Some(other) = options.get(key) {
                ensure!(
                    other == value,
                    "CMake profile conflicts with project option {key}"
                );
            }
        }
    }
    if let Some(environment) = preset.get("environment").and_then(Value::as_object) {
        for (environment_key, profile_key) in [
            ("CC", "CMAKE_C_COMPILER"),
            ("CFLAGS", "CMAKE_C_FLAGS"),
            ("LDFLAGS", "CMAKE_EXE_LINKER_FLAGS"),
            ("SDKROOT", "CMAKE_OSX_SYSROOT"),
            ("MACOSX_DEPLOYMENT_TARGET", "CMAKE_OSX_DEPLOYMENT_TARGET"),
        ] {
            ensure!(
                !profile.contains_key(profile_key)
                    || environment.get(environment_key).is_none_or(Value::is_null),
                "CMake preset environment {environment_key} conflicts with platform profile"
            );
        }
    }
    let mut argv = vec!["cmake".into()];
    if let Some(name) = &spec.configure_preset {
        argv.extend(["--preset".into(), name.clone()]);
    }
    argv.extend([
        "-S".into(),
        path_text(&source)?,
        "-B".into(),
        path_text(&build)?,
    ]);
    if let Some(generator) = &spec.generator
        && !profile.contains_key("CMAKE_GENERATOR")
    {
        argv.extend(["-G".into(), generator.clone()]);
    }
    argv.push(format!("-DCMAKE_BUILD_TYPE={}", spec.configuration));
    for (key, value) in &spec.cache_variables {
        argv.push(format!("-D{key}={value}"));
    }
    argv.extend_from_slice(profile_args);
    Ok(argv)
}

pub fn build_argv(build: &Path, spec: &Spec) -> Vec<String> {
    let mut argv = vec![
        "cmake".into(),
        "--build".into(),
        build.to_string_lossy().into_owned(),
        "--config".into(),
        spec.configuration.clone(),
        "--target".into(),
    ];
    argv.extend(
        spec.binary_targets
            .iter()
            .map(|mapping| mapping.target.clone()),
    );
    argv
}

/// Validate presets against host source bytes and emit paths for the execution guest.
pub fn configure_argv_mapped(
    source: &Path,
    build: &Path,
    spec: &Spec,
    profile_args: &[String],
    reported_source: &Path,
    reported_build: &Path,
) -> Result<Vec<String>> {
    for root in [reported_source, reported_build] {
        let text = recorded_root(root)?;
        ensure!(
            text.starts_with('/') || text.as_bytes().get(1) == Some(&b':'),
            "CMake reported root must be absolute"
        );
        ensure!(
            !text.split('/').any(|part| matches!(part, "." | "..")),
            "CMake reported root contains traversal"
        );
    }
    ensure!(
        recorded_root(reported_source)? != recorded_root(reported_build)?,
        "CMake reported source/build roots must differ"
    );
    let mut argv = configure_argv(source, build, spec, profile_args)?;
    let source_index = argv
        .iter()
        .position(|arg| arg == "-S")
        .context("CMake configure source option missing")?;
    let build_index = argv
        .iter()
        .position(|arg| arg == "-B")
        .context("CMake configure build option missing")?;
    argv[source_index + 1] = path_text(reported_source)?;
    argv[build_index + 1] = path_text(reported_build)?;
    Ok(argv)
}

fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("CMake reply missing string {field}"))
}

fn array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("CMake reply missing array {field}"))
}

fn reply_name(name: &str) -> Result<()> {
    config::relative(name)?;
    ensure!(
        !name.contains('/') && name.ends_with(".json"),
        "unsafe CMake reply reference: {name}"
    );
    Ok(())
}

fn references(value: &Value, result: &mut BTreeSet<String>) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if key == "jsonFile" {
                    let name = value.as_str().context("invalid CMake jsonFile reference")?;
                    reply_name(name)?;
                    result.insert(name.into());
                } else {
                    references(value, result)?;
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                references(value, result)?;
            }
        }
        _ => (),
    }
    Ok(())
}

fn reply_closure(
    reply: &Path,
    index: &str,
) -> Result<(BTreeMap<String, Value>, BTreeMap<String, String>)> {
    reply_name(index)?;
    let mut pending = BTreeSet::from([index.to_string()]);
    let mut values = BTreeMap::new();
    let mut hashes = BTreeMap::new();
    let mut total = 0;
    while let Some(name) = pending.pop_first() {
        if values.contains_key(&name) {
            continue;
        }
        ensure!(
            values.len() < MAX_FILES,
            "CMake reply closure exceeds file bound"
        );
        let (bytes, value) = read_json(&config::safe_join(reply, &name)?)?;
        total += bytes.len() as u64;
        ensure!(
            total <= MAX_CLOSURE,
            "CMake reply closure exceeds byte bound"
        );
        references(&value, &mut pending)?;
        hashes.insert(name.clone(), source::digest(&bytes));
        values.insert(name, value);
    }
    Ok((values, hashes))
}

fn object<'a>(
    index: &Value,
    values: &'a BTreeMap<String, Value>,
    kind: &str,
    major: u64,
) -> Result<&'a Value> {
    let client = index["reply"]["client-relship"]
        .as_object()
        .context("CMake reply lacks relship query response")?;
    let key = format!("{kind}-v{major}");
    let reference = client
        .get(&key)
        .with_context(|| format!("CMake reply lacks {key}"))?;
    ensure!(
        reference.get("error").is_none(),
        "CMake rejected {key} query"
    );
    ensure!(
        reference["kind"].as_str() == Some(kind)
            && reference["version"]["major"].as_u64() == Some(major),
        "CMake reply kind/version mismatch"
    );
    let value = values
        .get(string(reference, "jsonFile")?)
        .context("CMake reply reference absent from closure")?;
    ensure!(
        value["kind"].as_str() == Some(kind) && value["version"]["major"].as_u64() == Some(major),
        "CMake object kind/version mismatch"
    );
    Ok(value)
}

fn bound_path(root: &Path, raw: &str) -> Result<(String, PathBuf)> {
    let (name, path) = bound_name(root, raw)?;
    ensure!(
        fs::canonicalize(&path)?.starts_with(root),
        "CMake path leaves owned tree"
    );
    Ok((name, path))
}

fn bound_name(root: &Path, raw: &str) -> Result<(String, PathBuf)> {
    let path = Path::new(raw);
    let relative = if path.is_absolute() {
        path.strip_prefix(root)
            .context("CMake path leaves owned tree")?
    } else {
        path
    };
    let name = path_text(relative)?;
    let path = config::safe_join(root, &name)?;
    Ok((name, path))
}

fn c_language(language: &str) -> bool {
    language == "C" || language == "ASM" || language.starts_with("ASM_")
}

fn check_target_closure(
    id: &str,
    targets: &BTreeMap<String, &Value>,
    visited: &mut BTreeSet<String>,
    has_c: &mut bool,
) -> Result<()> {
    let mut pending = vec![id.to_owned()];
    while let Some(id) = pending.pop() {
        if !visited.insert(id.clone()) {
            continue;
        }
        let target = targets
            .get(&id)
            .context("CMake target dependency is missing from selected configuration")?;
        if let Some(groups) = target.get("compileGroups") {
            for group in groups.as_array().context("invalid CMake compileGroups")? {
                let language = string(group, "language")?;
                ensure!(
                    c_language(language),
                    "CMake product closure contains unsupported language {language}"
                );
                *has_c |= language == "C";
            }
        }
        if let Some(language) = target
            .get("link")
            .and_then(|link| link.get("language"))
            .and_then(Value::as_str)
        {
            ensure!(
                c_language(language),
                "CMake product closure links unsupported language {language}"
            );
        }
        if let Some(dependencies) = target.get("dependencies") {
            for dependency in dependencies
                .as_array()
                .context("invalid CMake dependencies")?
            {
                pending.push(string(dependency, "id")?.to_owned());
            }
        }
    }
    Ok(())
}

fn same_tree(value: &Value, source: &Path, build: &Path) -> Result<()> {
    ensure!(
        recorded_root(Path::new(string(&value["paths"], "source")?))? == recorded_root(source)?,
        "CMake reply source tree differs"
    );
    ensure!(
        recorded_root(Path::new(string(&value["paths"], "build")?))? == recorded_root(build)?,
        "CMake reply build tree differs"
    );
    Ok(())
}

fn validate_project_version(spec: &Spec, cache: &BTreeMap<String, String>) -> Result<()> {
    let mut keys = vec!["CMAKE_PROJECT_VERSION".into()];
    if let Some(name) = cache.get("CMAKE_PROJECT_NAME") {
        keys.push(format!("{name}_VERSION"));
    }
    let declared = semver::Version::parse(spec.version.strip_prefix('v').unwrap_or(&spec.version))?;
    for key in keys {
        if let Some(observed) = cache.get(&key).filter(|value| !value.is_empty()) {
            let parts = observed
                .split('.')
                .map(str::parse::<u64>)
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("CMake observed project version is not numeric")?;
            ensure!(
                (1..=4).contains(&parts.len())
                    && parts[0] == declared.major
                    && *parts.get(1).unwrap_or(&0) == declared.minor
                    && *parts.get(2).unwrap_or(&0) == declared.patch
                    && *parts.get(3).unwrap_or(&0) == 0,
                "CMake observed project version {observed} differs from explicit source version {}",
                spec.version
            );
        }
    }
    Ok(())
}

enum ConfigureInput {
    Source(String),
    Build(String),
    CmakeModule,
}

fn configure_input(
    index: &Value,
    input: &Value,
    reported_source: &Path,
    reported_build: &Path,
) -> Result<ConfigureInput> {
    let raw = string(input, "path")?;
    let normalized = raw.replace('\\', "/");
    let absolute = normalized.starts_with('/') || normalized.as_bytes().get(1) == Some(&b':');
    if !absolute {
        config::relative(&normalized)?;
        return Ok(ConfigureInput::Source(normalized));
    }
    if normalized.starts_with(&format!("{}/", recorded_root(reported_source)?)) {
        return Ok(ConfigureInput::Source(recorded_relative(
            reported_source,
            raw,
        )?));
    }
    if normalized.starts_with(&format!("{}/", recorded_root(reported_build)?)) {
        return Ok(ConfigureInput::Build(recorded_relative(
            reported_build,
            raw,
        )?));
    }
    ensure!(
        input["isCMake"].as_bool() == Some(true),
        "external CMake configure input is not source-bound: {raw}"
    );
    let module_root = Path::new(string(&index["cmake"]["paths"], "root")?);
    let root = recorded_root(module_root)?;
    ensure!(
        (root.starts_with('/') || root.as_bytes().get(1) == Some(&b':'))
            && !root.split('/').any(|part| matches!(part, "." | "..")),
        "CMake module root must be an absolute path without traversal"
    );
    recorded_relative(module_root, raw).with_context(|| {
        format!("CMake module input leaves the pinned CMake resource root: {raw}")
    })?;
    Ok(ConfigureInput::CmakeModule)
}

fn observe_index(
    source: &Path,
    build: &Path,
    spec: &Spec,
    index_name: &str,
    reported_source: &Path,
    reported_build: &Path,
) -> Result<Witness> {
    validate_spec(spec)?;
    let source = owned_directory(source)?;
    let build = owned_directory(build)?;
    let reply = config::safe_join(&build, REPLY_DIR)?;
    let (values, reply_files) = reply_closure(&reply, index_name)?;
    let index = values.get(index_name).context("CMake index absent")?;
    let model = object(index, &values, "codemodel", 2)?;
    same_tree(model, reported_source, reported_build)?;
    let configurations = array(model, "configurations")?
        .iter()
        .filter(|c| c["name"].as_str() == Some(&spec.configuration))
        .collect::<Vec<_>>();
    ensure!(
        configurations.len() == 1,
        "CMake selected configuration is missing or ambiguous: {}",
        spec.configuration
    );
    let configuration = configurations[0];
    let mut targets = BTreeMap::new();
    let mut by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for reference in array(configuration, "targets")? {
        let target = values
            .get(string(reference, "jsonFile")?)
            .context("CMake target absent from reply closure")?;
        let id = string(reference, "id")?;
        let name = string(reference, "name")?;
        ensure!(
            string(target, "id")? == id && string(target, "name")? == name,
            "CMake target identity mismatch"
        );
        ensure!(
            targets.insert(id.to_owned(), target).is_none(),
            "duplicate CMake target id"
        );
        by_name.entry(name.into()).or_default().push(id.into());
    }
    let mut artifacts = Vec::new();
    let mut selected_paths = BTreeSet::new();
    for mapping in &spec.binary_targets {
        let ids = by_name
            .get(&mapping.target)
            .with_context(|| format!("CMake selected target is absent: {}", mapping.target))?;
        ensure!(
            ids.len() == 1,
            "CMake selected target is ambiguous: {}",
            mapping.target
        );
        let id = &ids[0];
        let target = targets[id];
        ensure!(
            string(target, "type")? == "EXECUTABLE",
            "CMake mapped target must be EXECUTABLE: {}",
            mapping.target
        );
        let mut has_c = false;
        check_target_closure(id, &targets, &mut BTreeSet::new(), &mut has_c)?;
        ensure!(
            has_c,
            "CMake selected executable has no observed C compilation closure"
        );
        let name_on_disk = string(target, "nameOnDisk")?;
        config::relative(name_on_disk)?;
        ensure!(
            !name_on_disk.contains('/'),
            "CMake nameOnDisk must be a file name"
        );
        let extension = Path::new(name_on_disk)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        ensure!(
            !matches!(
                extension.as_str(),
                "pdb" | "lib" | "a" | "exp" | "ilk" | "manifest" | "dsym"
            ),
            "CMake selected primary artifact is not an executable"
        );
        let mut candidates = Vec::new();
        for artifact in array(target, "artifacts")? {
            let relative = recorded_relative(reported_build, string(artifact, "path")?)?;
            let (name, path) = bound_name(&build, &relative)?;
            if path.file_name().and_then(|s| s.to_str()) == Some(name_on_disk) {
                candidates.push((name, path));
            }
        }
        ensure!(
            candidates.len() == 1,
            "CMake executable artifact is missing or ambiguous: {}",
            mapping.target
        );
        let (name, path) = candidates.pop().unwrap();
        let meta = fs::symlink_metadata(&path)?;
        ensure!(
            meta.is_file() && !meta.file_type().is_symlink(),
            "CMake executable must be a regular file"
        );
        ensure!(
            selected_paths.insert(name.clone()),
            "multiple CMake binaries select the same artifact"
        );
        artifacts.push(ArtifactWitness {
            binary: mapping.binary.clone(),
            target: mapping.target.clone(),
            target_id: id.clone(),
            path: name,
            sha256: source::file_digest(&path)?,
            size: meta.len(),
        });
    }
    let cache_object = object(index, &values, "cache", 2)?;
    let mut cache = BTreeMap::new();
    for entry in array(cache_object, "entries")? {
        ensure!(
            cache
                .insert(
                    string(entry, "name")?.to_string(),
                    string(entry, "value")?.to_string()
                )
                .is_none(),
            "duplicate CMake cache entry"
        );
    }
    validate_project_version(spec, &cache)?;
    validate_configuration(spec, &cache)?;
    let toolchain_object = object(index, &values, "toolchains", 1)?;
    let mut languages = BTreeSet::new();
    let mut toolchains = Vec::new();
    for entry in array(toolchain_object, "toolchains")? {
        let language = string(entry, "language")?;
        ensure!(
            languages.insert(language.to_string()),
            "duplicate CMake toolchain language"
        );
        let compiler = entry
            .get("compiler")
            .context("CMake toolchain lacks compiler observation")?
            .clone();
        toolchains.push(ToolchainObservation {
            language: language.into(),
            compiler,
        });
    }
    ensure!(
        languages.contains("C"),
        "CMake reply lacks C compiler observation"
    );
    let files = object(index, &values, "cmakeFiles", 1)?;
    same_tree(files, reported_source, reported_build)?;
    for entry in array(files, "inputs")? {
        match configure_input(index, entry, reported_source, reported_build)? {
            ConfigureInput::Source(name) => {
                config::safe_join(&source, &name)?;
            }
            ConfigureInput::Build(name) => {
                bound_path(&build, &name)?;
            }
            ConfigureInput::CmakeModule => (),
        }
    }
    let generator = string(&index["cmake"]["generator"], "name")?.to_string();
    if let Some(expected) = &spec.generator {
        ensure!(
            expected == &generator,
            "observed CMake generator differs from source specification"
        );
    }
    Ok(Witness {
        spec: spec.clone(),
        source,
        build,
        reported_source: reported_source.to_path_buf(),
        reported_build: reported_build.to_path_buf(),
        index: index_name.into(),
        reply_files,
        cmake_version: string(&index["cmake"]["version"], "string")?.into(),
        generator,
        multi_config: index["cmake"]["generator"]["multiConfig"]
            .as_bool()
            .context("CMake generator lacks multiConfig observation")?,
        artifacts,
        cache,
        toolchains,
    })
}

/// Observe only after building the explicit mapped targets and configuration.
pub fn observe(source: &Path, build: &Path, spec: &Spec) -> Result<Witness> {
    let source = owned_directory(source)?;
    let build = owned_directory(build)?;
    observe_mapped(&source, &build, spec, &source, &build)
}

/// Map container/guest paths to owned host trees while preserving raw reply bytes.
pub fn observe_mapped(
    source: &Path,
    build: &Path,
    spec: &Spec,
    reported_source: &Path,
    reported_build: &Path,
) -> Result<Witness> {
    for root in [reported_source, reported_build] {
        let text = recorded_root(root)?;
        ensure!(
            text.starts_with('/') || text.as_bytes().get(1) == Some(&b':'),
            "CMake reported root must be absolute"
        );
        ensure!(
            !text.split('/').any(|part| matches!(part, "." | "..")),
            "CMake reported root contains traversal"
        );
    }
    let build = owned_directory(build)?;
    let reply = config::safe_join(&build, REPLY_DIR)?;
    let mut indexes = Vec::new();
    for entry in fs::read_dir(&reply)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF8 CMake reply file"))?;
        if name.starts_with("index-") && name.ends_with(".json") {
            indexes.push(name);
        }
    }
    indexes.sort();
    let index = indexes
        .last()
        .context("CMake File API reply index is absent")?;
    observe_index(source, &build, spec, index, reported_source, reported_build)
}

/// Re-open the original reply index, not whichever index happens to be newest.
pub fn verify_witness(build: &Path, witness: &Witness) -> Result<()> {
    ensure!(
        owned_directory(build)? == witness.build,
        "CMake witness build directory differs"
    );
    let observed = observe_index(
        &witness.source,
        build,
        &witness.spec,
        &witness.index,
        &witness.reported_source,
        &witness.reported_build,
    )?;
    ensure!(
        &observed == witness,
        "CMake reply/artifact witness differs from original observation"
    );
    Ok(())
}

/// Preserve the original reply bytes beside a serializable witness for offline review.
pub fn preserve_reply(build: &Path, evidence: &Path, witness: &Witness) -> Result<()> {
    verify_witness(build, witness)?;
    if optional_exists(evidence)? {
        ensure!(
            !fs::symlink_metadata(evidence)?.file_type().is_symlink(),
            "CMake evidence directory is a symlink"
        );
    }
    fs::create_dir_all(evidence)?;
    let evidence = owned_directory(evidence)?;
    let reply = config::safe_join(&witness.build, REPLY_DIR)?;
    for (name, expected) in &witness.reply_files {
        reply_name(name)?;
        let (bytes, _) = read_json(&config::safe_join(&reply, name)?)?;
        ensure!(
            source::digest(&bytes) == *expected,
            "CMake reply changed while preserving evidence"
        );
        let path = config::safe_join(&evidence, name)?;
        let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
        output.write_all(&bytes)?;
        output.flush()?;
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(config::safe_join(&evidence, "witness.json")?)?;
    output.write_all(&serde_json::to_vec_pretty(witness)?)?;
    output.flush()?;
    verify_preserved_reply(&evidence, witness)?;
    verify_witness(build, witness)?;
    Ok(())
}

fn recorded_root(path: &Path) -> Result<String> {
    let path = path_text(path)?;
    Ok(path
        .strip_prefix("//?/")
        .unwrap_or(&path)
        .trim_end_matches('/')
        .to_owned())
}

fn recorded_relative(root: &Path, raw: &str) -> Result<String> {
    let raw = raw.replace('\\', "/");
    let absolute = raw.starts_with('/') || raw.as_bytes().get(1) == Some(&b':');
    let relative = if absolute {
        let root = recorded_root(root)?;
        raw.strip_prefix(&format!("{root}/"))
            .context("CMake recorded artifact leaves its original build tree")?
            .to_string()
    } else {
        raw
    };
    config::relative(&relative)?;
    Ok(relative)
}

fn same_recorded_tree(value: &Value, witness: &Witness) -> Result<()> {
    for (key, expected) in [
        ("source", &witness.reported_source),
        ("build", &witness.reported_build),
    ] {
        ensure!(
            recorded_root(Path::new(string(&value["paths"], key)?))? == recorded_root(expected)?,
            "CMake preserved {key} path differs from original witness"
        );
    }
    Ok(())
}

/// Validate preserved File API semantics without opening the original source/build paths.
/// Executable hashes remain bound to the witness; package verification checks their bytes.
pub fn verify_preserved_reply(evidence: &Path, witness: &Witness) -> Result<()> {
    validate_spec(&witness.spec)?;
    let evidence = owned_directory(evidence)?;
    let (values, hashes) = reply_closure(&evidence, &witness.index)?;
    ensure!(
        hashes == witness.reply_files,
        "CMake preserved reply closure differs from original witness"
    );
    let index = values
        .get(&witness.index)
        .context("CMake preserved index missing")?;
    let model = object(index, &values, "codemodel", 2)?;
    same_recorded_tree(model, witness)?;
    let configurations = array(model, "configurations")?
        .iter()
        .filter(|c| c["name"].as_str() == Some(witness.spec.configuration.as_str()))
        .collect::<Vec<_>>();
    ensure!(
        configurations.len() == 1,
        "CMake preserved configuration is missing or ambiguous"
    );
    let mut targets = BTreeMap::new();
    let mut names: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for reference in array(configurations[0], "targets")? {
        let target = values
            .get(string(reference, "jsonFile")?)
            .context("CMake preserved target missing")?;
        let id = string(reference, "id")?;
        let name = string(reference, "name")?;
        ensure!(
            string(target, "id")? == id && string(target, "name")? == name,
            "CMake preserved target identity differs"
        );
        ensure!(
            targets.insert(id.to_string(), target).is_none(),
            "duplicate CMake preserved target id"
        );
        names.entry(name.into()).or_default().push(id.into());
    }
    ensure!(
        witness.artifacts.len() == witness.spec.binary_targets.len(),
        "CMake preserved artifact count differs"
    );
    let mut paths = BTreeSet::new();
    for (mapping, artifact) in witness.spec.binary_targets.iter().zip(&witness.artifacts) {
        let ids = names
            .get(&mapping.target)
            .context("CMake preserved mapped target missing")?;
        ensure!(ids.len() == 1, "CMake preserved mapped target ambiguous");
        let id = &ids[0];
        let target = targets[id];
        ensure!(
            string(target, "type")? == "EXECUTABLE",
            "CMake preserved target is not EXECUTABLE"
        );
        let mut has_c = false;
        check_target_closure(id, &targets, &mut BTreeSet::new(), &mut has_c)?;
        ensure!(has_c, "CMake preserved target has no C compilation closure");
        let primary = string(target, "nameOnDisk")?;
        config::relative(primary)?;
        ensure!(
            !primary.contains('/'),
            "invalid CMake preserved primary artifact name"
        );
        let extension = Path::new(primary)
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        ensure!(
            !matches!(
                extension.as_str(),
                "pdb" | "lib" | "a" | "exp" | "ilk" | "manifest" | "dsym"
            ),
            "CMake preserved primary artifact is not an executable"
        );
        let mut candidates = Vec::new();
        for candidate in array(target, "artifacts")? {
            let path = recorded_relative(&witness.reported_build, string(candidate, "path")?)?;
            if path.rsplit('/').next() == Some(primary) {
                candidates.push(path);
            }
        }
        ensure!(
            candidates.len() == 1,
            "CMake preserved executable artifact missing or ambiguous"
        );
        ensure!(
            artifact.binary == mapping.binary
                && artifact.target == mapping.target
                && artifact.target_id == *id
                && artifact.path == candidates[0],
            "CMake preserved binary/target/artifact mapping differs"
        );
        ensure!(
            paths.insert(&artifact.path),
            "duplicate CMake preserved artifact path"
        );
        ensure!(
            artifact.sha256.len() == 64
                && artifact
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "invalid CMake executable digest"
        );
    }
    let mut cache = BTreeMap::new();
    for entry in array(object(index, &values, "cache", 2)?, "entries")? {
        ensure!(
            cache
                .insert(
                    string(entry, "name")?.to_owned(),
                    string(entry, "value")?.to_owned()
                )
                .is_none(),
            "duplicate CMake preserved cache entry"
        );
    }
    ensure!(
        cache == witness.cache,
        "CMake preserved cache observation differs"
    );
    validate_project_version(&witness.spec, &cache)?;
    validate_configuration(&witness.spec, &cache)?;
    let mut languages = BTreeSet::new();
    let mut toolchains = Vec::new();
    for entry in array(object(index, &values, "toolchains", 1)?, "toolchains")? {
        let language = string(entry, "language")?;
        ensure!(
            languages.insert(language.to_owned()),
            "duplicate CMake preserved compiler language"
        );
        toolchains.push(ToolchainObservation {
            language: language.into(),
            compiler: entry
                .get("compiler")
                .context("missing CMake preserved compiler")?
                .clone(),
        });
    }
    ensure!(
        languages.contains("C") && toolchains == witness.toolchains,
        "CMake preserved toolchain observation differs"
    );
    let files = object(index, &values, "cmakeFiles", 1)?;
    same_recorded_tree(files, witness)?;
    for input in array(files, "inputs")? {
        configure_input(
            index,
            input,
            &witness.reported_source,
            &witness.reported_build,
        )?;
    }
    ensure!(
        string(&index["cmake"]["version"], "string")? == witness.cmake_version
            && string(&index["cmake"]["generator"], "name")? == witness.generator
            && index["cmake"]["generator"]["multiConfig"].as_bool() == Some(witness.multi_config),
        "CMake preserved generator/version observation differs"
    );
    if let Some(generator) = &witness.spec.generator {
        ensure!(
            generator == &witness.generator,
            "CMake preserved generator conflicts with source specification"
        );
    }
    Ok(())
}

pub fn load_preserved_reply(evidence: &Path) -> Result<Witness> {
    let evidence = owned_directory(evidence)?;
    let (bytes, _) = read_json(&config::safe_join(&evidence, "witness.json")?)?;
    let witness: Witness = serde_json::from_slice(&bytes)?;
    verify_preserved_reply(&evidence, &witness)?;
    Ok(witness)
}

/// Copy only witnessed executables. No CMake install script is executed.
pub fn stage(build: &Path, payload: &Path, witness: &Witness) -> Result<Vec<StagedArtifact>> {
    let names = witness
        .artifacts
        .iter()
        .map(|artifact| {
            let suffix = if Path::new(&artifact.path)
                .extension()
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.eq_ignore_ascii_case("exe"))
                && !artifact.binary.to_ascii_lowercase().ends_with(".exe")
            {
                ".exe"
            } else {
                ""
            };
            (
                artifact.binary.clone(),
                format!("{}{suffix}", artifact.binary),
            )
        })
        .collect();
    stage_named(build, payload, witness, &names)
}

/// Stage with exact payload names supplied by the saved target contract.
pub fn stage_named(
    build: &Path,
    payload: &Path,
    witness: &Witness,
    payload_names: &BTreeMap<String, String>,
) -> Result<Vec<StagedArtifact>> {
    verify_witness(build, witness)?;
    ensure!(
        payload_names.len() == witness.artifacts.len()
            && witness
                .artifacts
                .iter()
                .all(|artifact| payload_names.contains_key(&artifact.binary)),
        "CMake payload names must exactly cover witnessed binaries"
    );
    let mut names = BTreeSet::new();
    for name in payload_names.values() {
        config::identifier(name)?;
        ensure!(
            names.insert(name.to_ascii_lowercase()),
            "duplicate CMake staged binary name"
        );
    }
    if optional_exists(payload)? {
        ensure!(
            !fs::symlink_metadata(payload)?.file_type().is_symlink(),
            "CMake payload directory is a symlink"
        );
    }
    fs::create_dir_all(payload)?;
    let payload = owned_directory(payload)?;
    ensure!(
        payload != witness.build
            && !witness.build.starts_with(&payload)
            && !payload.starts_with(&witness.build),
        "CMake payload must be separate from build tree"
    );
    let mut outputs = Vec::new();
    for artifact in &witness.artifacts {
        let (_, from) = bound_path(&witness.build, &artifact.path)?;
        let name = payload_names[&artifact.binary].clone();
        let to = config::safe_join(&payload, &name)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&to)
            .with_context(|| {
                format!("CMake payload destination already exists or cannot be created: {name}")
            })?;
        let mut input = fs::File::open(&from)?;
        std::io::copy(&mut input, &mut output)?;
        output.flush()?;
        fs::set_permissions(&to, fs::metadata(&from)?.permissions())?;
        ensure!(
            source::file_digest(&to)? == artifact.sha256
                && fs::metadata(&to)?.len() == artifact.size,
            "CMake staged artifact differs from witness"
        );
        outputs.push(StagedArtifact {
            binary: artifact.binary.clone(),
            path: name,
            sha256: artifact.sha256.clone(),
            size: artifact.size,
        });
    }
    verify_witness(build, witness)?;
    Ok(outputs)
}
