use super::model::{BinaryOutput, Builder, CommandSpec, Product, Recipe, Resolution, Target};
use crate::{config, process, source};
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

fn directory(root: &Path, name: &str) -> Result<PathBuf> {
    let path = if name == "." {
        root.to_path_buf()
    } else {
        config::safe_join(root, name)?
    };
    ensure!(path.is_dir(), "product directory does not exist: {name}");
    Ok(path)
}

fn relative(root: &Path, path: &Path) -> Result<String> {
    let name = path
        .strip_prefix(root)
        .context("builder input leaves the tracked Git source tree")?
        .to_str()
        .context("non-UTF8 builder input")?
        .replace('\\', "/");
    config::safe_join(root, &name)?;
    Ok(name)
}

fn input(root: &Path, path: &Path, files: &BTreeMap<String, String>) -> Result<String> {
    let name = relative(root, path)?;
    ensure!(
        files.contains_key(&name),
        "builder input is not tracked: {name}"
    );
    ensure!(
        fs::metadata(path)?.is_file(),
        "builder input is not a regular file: {name}"
    );
    Ok(name)
}

fn joined(base: &Path, value: &str) -> Result<PathBuf> {
    config::relative(value)?;
    Ok(base.join(value))
}

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("metadata missing {key}"))
}

fn read_manifest(
    root: &Path,
    path: &Path,
    files: &BTreeMap<String, String>,
) -> Result<toml::Value> {
    input(root, path, files)?;
    toml::from_str(&fs::read_to_string(path)?)
        .with_context(|| format!("read manifest {}", path.display()))
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn cargo_inputs(root: &Path, cwd: &Path, files: &BTreeMap<String, String>) -> Result<()> {
    for ancestor in cwd.ancestors() {
        for name in [".cargo/config", ".cargo/config.toml"] {
            let path = ancestor.join(name);
            if ancestor.starts_with(root) {
                // Check the path before resolving it: a symlink alias is an input too.
                relative(root, &path)?;
                if exists(&path)? {
                    input(root, &path, files)?;
                }
            } else {
                ensure!(
                    !exists(&path)?,
                    "external Cargo configuration: {}",
                    path.display()
                );
            }
        }
    }
    let home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|value| PathBuf::from(value).join(".cargo")));
    if let Some(home) = home {
        let home = if home.is_absolute() {
            home
        } else {
            cwd.join(home)
        };
        for name in ["config", "config.toml"] {
            let path = home.join(name);
            if exists(&path)? {
                input(root, &path, files).with_context(|| {
                    format!(
                        "external or unsafe CARGO_HOME configuration: {}",
                        path.display()
                    )
                })?;
            }
        }
    }
    Ok(())
}

fn cargo_metadata(
    cwd: &Path,
    manifest: &str,
    features: &[String],
    defaults: bool,
) -> Result<Value> {
    let mut argv = vec![
        "cargo".into(),
        "metadata".into(),
        "--format-version".into(),
        "1".into(),
        "--locked".into(),
        "--manifest-path".into(),
        manifest.into(),
    ];
    if !defaults {
        argv.push("--no-default-features".into());
    }
    if !features.is_empty() {
        argv.extend(["--features".into(), features.join(",")]);
    }
    serde_json::from_str(&process::capture(cwd, &argv, 1200)?).context("invalid Cargo metadata")
}

fn cargo_metadata_inputs(
    root: &Path,
    cwd: &Path,
    data: &Value,
    files: &BTreeMap<String, String>,
) -> Result<()> {
    ensure!(
        Path::new(text(data, "workspace_root")?).canonicalize()? == cwd.canonicalize()?,
        "product.directory must be the Cargo workspace root"
    );
    input(root, &cwd.join("Cargo.toml"), files)?;
    input(root, &cwd.join("Cargo.lock"), files)?;
    for package in data["packages"]
        .as_array()
        .context("Cargo packages missing")?
    {
        if !package["source"].is_null() {
            continue;
        }
        input(root, Path::new(text(package, "manifest_path")?), files)?;
        for target in package["targets"]
            .as_array()
            .context("Cargo targets missing")?
        {
            input(root, Path::new(text(target, "src_path")?), files)?;
        }
    }
    Ok(())
}

fn is_bin(target: &Value) -> bool {
    target["kind"]
        .as_array()
        .is_some_and(|kinds| kinds.iter().any(|kind| kind.as_str() == Some("bin")))
}

fn rust_resolve(root: &Path, p: &Product, files: &BTreeMap<String, String>) -> Result<Resolution> {
    let Builder::Rust {
        package,
        manifest,
        features,
        default_features,
    } = &p.build
    else {
        unreachable!()
    };
    let cwd = directory(root, &p.directory)?;
    cargo_inputs(root, &cwd, files)?;
    input(root, &joined(&cwd, manifest)?, files)?;
    input(root, &cwd.join("Cargo.toml"), files)?;
    input(root, &cwd.join("Cargo.lock"), files)?;
    let data = cargo_metadata(&cwd, manifest, features, *default_features)?;
    cargo_metadata_inputs(root, &cwd, &data, files)?;
    let members = data["workspace_members"]
        .as_array()
        .context("Cargo workspace members missing")?;
    let selected = data["packages"]
        .as_array()
        .context("Cargo packages missing")?
        .iter()
        .find(|candidate| {
            candidate["name"].as_str() == Some(package)
                && members.iter().any(|member| member == &candidate["id"])
        })
        .with_context(|| format!("selected Rust package is not a workspace member: {package}"))?;
    let selected_manifest = input(root, Path::new(text(selected, "manifest_path")?), files)?;
    ensure!(
        selected_manifest == relative(root, &joined(&cwd, manifest)?)?,
        "build.manifest is not the selected Cargo package manifest"
    );
    let available = selected["targets"]
        .as_array()
        .context("Cargo targets missing")?;
    let active: BTreeSet<&str> = data["resolve"]["nodes"]
        .as_array()
        .context("Cargo resolve nodes missing")?
        .iter()
        .find(|node| node["id"] == selected["id"])
        .context("selected Cargo resolve node missing")?["features"]
        .as_array()
        .context("Cargo enabled features missing")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for feature in features {
        ensure!(
            selected["features"].get(feature).is_some(),
            "unknown Rust feature {feature}"
        );
    }
    for binary in &p.binaries {
        let bin = available
            .iter()
            .find(|target| is_bin(target) && target["name"].as_str() == Some(binary))
            .with_context(|| format!("unknown Rust binary {binary}"))?;
        if let Some(required) = bin["required-features"].as_array() {
            for feature in required.iter().filter_map(Value::as_str) {
                ensure!(
                    active.contains(feature),
                    "Rust binary {binary} requires disabled feature {feature}"
                );
            }
        }
    }
    let resolution = Resolution {
        version: text(selected, "version")?.into(),
        manifest: selected_manifest,
        workspace_manifest: Some(relative(root, &cwd.join("Cargo.toml"))?),
    };
    validate_offline(root, p, &resolution, files)?;
    Ok(resolution)
}

fn go_env() -> BTreeMap<String, String> {
    [
        ("GOENV", "off"),
        ("GOWORK", "off"),
        ("GOTOOLCHAIN", "local"),
        ("CGO_ENABLED", "0"),
    ]
    .into_iter()
    .map(|(key, value)| (key.into(), value.into()))
    .collect()
}

fn package_directory(cwd: &Path, package: &str) -> Result<PathBuf> {
    if package == "." {
        return Ok(cwd.into());
    }
    let name = package
        .strip_prefix("./")
        .context("Go packages must be '.' or explicit './directory' paths")?;
    config::relative(name)?;
    ensure!(!name.contains("..."), "Go package patterns are unsupported");
    Ok(cwd.join(name))
}

// A small lexer covers Go module directives and package/import declarations.
// Quoted tokens retain delimiters so identifiers cannot be confused with literals.
fn go_tokens(source: &str) -> Result<Vec<String>> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            if c == '\n' {
                tokens.push("\n".into());
            }
            i += 1;
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            ensure!(i + 1 < chars.len(), "unterminated Go comment");
            i += 2;
            continue;
        }
        if matches!(c, '"' | '`' | '\'') {
            let start = i;
            i += 1;
            while i < chars.len() && chars[i] != c {
                if chars[i] == '\\' && c != '`' {
                    i += 1;
                }
                i += 1;
            }
            ensure!(i < chars.len(), "unterminated Go string");
            i += 1;
            tokens.push(chars[start..i].iter().collect());
        } else if matches!(c, '(' | ')' | ';') {
            tokens.push(c.to_string());
            i += 1;
        } else {
            let start = i;
            while i < chars.len()
                && !chars[i].is_whitespace()
                && !matches!(chars[i], '(' | ')' | ';' | '"' | '`' | '\'')
            {
                if chars[i] == '/' && matches!(chars.get(i + 1), Some('/' | '*')) {
                    break;
                }
                i += 1;
            }
            ensure!(i > start, "invalid Go token");
            tokens.push(chars[start..i].iter().collect());
        }
    }
    Ok(tokens)
}

fn unquote(token: &str) -> &str {
    if (token.starts_with('"') && token.ends_with('"'))
        || (token.starts_with('`') && token.ends_with('`'))
    {
        &token[1..token.len() - 1]
    } else {
        token
    }
}

fn go_module(root: &Path, cwd: &Path, files: &BTreeMap<String, String>) -> Result<String> {
    let manifest = input(root, &cwd.join("go.mod"), files)?;
    for ancestor in cwd.ancestors().take_while(|path| path.starts_with(root)) {
        ensure!(
            !exists(&ancestor.join("go.work"))? && !exists(&ancestor.join("go.work.sum"))?,
            "Go workspaces are unsupported: {}",
            ancestor.display()
        );
    }
    ensure!(
        !exists(&cwd.join("vendor"))?,
        "vendored Go dependencies are unsupported"
    );
    let prefix = if cwd == root {
        String::new()
    } else {
        format!("{}/", relative(root, cwd)?)
    };
    for name in files.keys().filter(|name| name.starts_with(&prefix)) {
        let local = &name[prefix.len()..];
        ensure!(
            name == &manifest || !local.ends_with("/go.mod"),
            "nested Go modules are unsupported: {name}"
        );
        ensure!(
            local != "go.work" && !local.ends_with("/go.work"),
            "Go workspaces are unsupported: {name}"
        );
        ensure!(
            !local.split('/').any(|part| part == "vendor"),
            "vendored Go dependencies are unsupported: {name}"
        );
    }
    let tokens = go_tokens(&fs::read_to_string(cwd.join("go.mod"))?)?;
    let mut module = None;
    let mut dependencies = false;
    let mut directive = "";
    let mut block = false;
    let mut line: Vec<&str> = Vec::new();
    let check = |kind: &str,
                 words: &[&str],
                 module: &mut Option<String>,
                 dependencies: &mut bool|
     -> Result<()> {
        if words.is_empty() {
            return Ok(());
        }
        match kind {
            "module" => {
                ensure!(
                    words.len() == 1 && module.is_none(),
                    "invalid Go module directive"
                );
                *module = Some(unquote(words[0]).into());
            }
            "require" => {
                *dependencies = true;
            }
            "replace" => {
                let arrow = words
                    .iter()
                    .position(|word| *word == "=>")
                    .context("invalid Go replace directive")?;
                let replacement = &words[arrow + 1..];
                ensure!(
                    replacement.len() == 2,
                    "local Go module replacements are unsupported"
                );
                let destination = unquote(replacement[0]);
                ensure!(
                    !destination.starts_with(['.', '/', '\\'])
                        && !destination.contains(':')
                        && replacement[1].starts_with('v'),
                    "external/local-path Go replacements are unsupported"
                );
            }
            _ => (),
        }
        Ok(())
    };
    for token in &tokens {
        match token.as_str() {
            "\n" | ";" => {
                check(directive, &line, &mut module, &mut dependencies)?;
                line.clear();
                if !block {
                    directive = "";
                }
            }
            "(" => {
                ensure!(
                    !directive.is_empty() && line.is_empty() && !block,
                    "invalid Go module block"
                );
                block = true;
            }
            ")" => {
                check(directive, &line, &mut module, &mut dependencies)?;
                line.clear();
                block = false;
                directive = "";
            }
            word => {
                if directive.is_empty() {
                    directive = word;
                } else {
                    line.push(word);
                }
            }
        }
    }
    check(directive, &line, &mut module, &mut dependencies)?;
    if dependencies {
        input(root, &cwd.join("go.sum"), files).context(
            "Go dependencies require a tracked go.sum; prepare module inputs before planning",
        )?;
    }
    module.context("go.mod must declare a module")
}

fn go_list(cwd: &Path, packages: &[String]) -> Result<Vec<Value>> {
    let mut argv = vec![
        "go".into(),
        "list".into(),
        "-mod=readonly".into(),
        "-deps".into(),
        "-json".into(),
    ];
    argv.extend_from_slice(packages);
    let output = process::capture_spec(cwd, &argv, &go_env(), 1200)?;
    serde_json::Deserializer::from_str(&output)
        .into_iter::<Value>()
        .map(|item| item.context("invalid Go package metadata"))
        .collect()
}

fn go_metadata_inputs(
    root: &Path,
    cwd: &Path,
    data: &[Value],
    files: &BTreeMap<String, String>,
) -> Result<()> {
    for package in data {
        ensure!(
            package["Error"].is_null() && package["DepsErrors"].is_null(),
            "Go package metadata contains unresolved errors"
        );
        if package["Standard"].as_bool() == Some(true) {
            continue;
        }
        let module = &package["Module"];
        ensure!(!module.is_null(), "Go package is outside a declared module");
        if !module["Replace"].is_null() {
            ensure!(
                module["Replace"]["Version"].as_str().is_some(),
                "local Go module replacements are unsupported"
            );
        }
        for key in [
            "CgoFiles",
            "CFiles",
            "CXXFiles",
            "MFiles",
            "FFiles",
            "SwigFiles",
            "SwigCXXFiles",
            "SysoFiles",
        ] {
            ensure!(
                package[key].as_array().is_none_or(Vec::is_empty),
                "pure Go builder does not support {key}"
            );
        }
        if module["Main"].as_bool() != Some(true) {
            continue;
        }
        ensure!(
            Path::new(text(module, "GoMod")?) == cwd.join("go.mod"),
            "Go package belongs to another local module"
        );
        let dir = Path::new(text(package, "Dir")?);
        ensure!(dir.starts_with(cwd), "Go source leaves product module");
        for key in [
            "GoFiles",
            "IgnoredGoFiles",
            "SFiles",
            "HFiles",
            "EmbedFiles",
            "TestGoFiles",
            "XTestGoFiles",
        ] {
            if let Some(names) = package[key].as_array() {
                for name in names {
                    input(
                        root,
                        &joined(dir, name.as_str().context("invalid Go source filename")?)?,
                        files,
                    )?;
                }
            }
        }
    }
    Ok(())
}

fn go_source_check(
    root: &Path,
    cwd: &Path,
    packages: &[String],
    files: &BTreeMap<String, String>,
) -> Result<()> {
    for package in packages {
        let dir = package_directory(cwd, package)?;
        let prefix = if dir == root {
            String::new()
        } else {
            format!("{}/", relative(root, &dir)?)
        };
        let mut main = false;
        for name in files.keys().filter(|name| name.starts_with(&prefix)) {
            let local = &name[prefix.len()..];
            if local.contains('/') || !local.ends_with(".go") || local.ends_with("_test.go") {
                continue;
            }
            let path = root.join(name);
            input(root, &path, files)?;
            let tokens = go_tokens(&fs::read_to_string(path)?)?;
            let tokens: Vec<_> = tokens
                .iter()
                .filter(|token| token.as_str() != "\n")
                .map(String::as_str)
                .collect();
            main |= tokens.windows(2).any(|pair| pair == ["package", "main"]);
            let mut importing = false;
            let mut block = false;
            for token in tokens {
                match token {
                    "import" => importing = true,
                    "(" if importing => block = true,
                    ")" if importing => {
                        block = false;
                        importing = false;
                    }
                    value if importing && (value.starts_with('"') || value.starts_with('`')) => {
                        ensure!(unquote(value) != "C", "cgo sources are unsupported: {name}");
                        if !block {
                            importing = false;
                        }
                    }
                    _ => (),
                }
            }
        }
        ensure!(main, "Go package has no tracked main source: {package}");
    }
    Ok(())
}

pub fn resolve(root: &Path, p: &Product, files: &BTreeMap<String, String>) -> Result<Resolution> {
    match &p.build {
        Builder::Rust { .. } => rust_resolve(root, p, files),
        Builder::Go {
            version, packages, ..
        } => {
            let cwd = directory(root, &p.directory)?;
            go_module(root, &cwd, files)?;
            ensure!(
                packages.len() == p.binaries.len(),
                "Go packages must correspond positionally to product binaries"
            );
            go_source_check(root, &cwd, packages, files)?;
            let data = go_list(&cwd, packages)?;
            go_metadata_inputs(root, &cwd, &data, files)?;
            for package in packages {
                let expected = package_directory(&cwd, package)?;
                ensure!(
                    data.iter().any(|item| item["Dir"]
                        .as_str()
                        .is_some_and(|dir| Path::new(dir) == expected)
                        && item["Name"].as_str() == Some("main")),
                    "selected Go package is not a main package: {package}"
                );
            }
            let resolution = Resolution {
                version: version.clone(),
                manifest: relative(root, &cwd.join("go.mod"))?,
                workspace_manifest: None,
            };
            validate_offline(root, p, &resolution, files)?;
            Ok(resolution)
        }
    }
}

fn rust_features(manifest: &toml::Value) -> BTreeMap<String, Vec<String>> {
    let mut features: BTreeMap<String, Vec<String>> = manifest
        .get("features")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flatten()
        .map(|(name, values)| {
            (
                name.clone(),
                values
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(toml::Value::as_str)
                    .map(str::to_owned)
                    .collect(),
            )
        })
        .collect();
    let explicit: BTreeSet<String> = features
        .values()
        .flatten()
        .filter_map(|value| value.strip_prefix("dep:").map(str::to_owned))
        .collect();
    let mut groups = vec![manifest];
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        groups.extend(targets.values());
    }
    for group in groups {
        if let Some(deps) = group.get("dependencies").and_then(toml::Value::as_table) {
            for (name, dep) in deps {
                if dep.get("optional").and_then(toml::Value::as_bool) == Some(true)
                    && !explicit.contains(name)
                {
                    features
                        .entry(name.clone())
                        .or_insert_with(|| vec![format!("dep:{name}")]);
                }
            }
        }
    }
    features
}

fn rust_binary_inputs(
    root: &Path,
    manifest_path: &Path,
    manifest: &toml::Value,
    workspace: &toml::Value,
    package: &str,
    files: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, Vec<String>>> {
    let base = manifest_path
        .parent()
        .context("Cargo manifest parent missing")?;
    let explicit = manifest.get("bin").and_then(toml::Value::as_array);
    let edition = manifest.get("package").and_then(|p| p.get("edition"));
    let edition = if edition
        .and_then(|v| v.get("workspace"))
        .and_then(toml::Value::as_bool)
        == Some(true)
    {
        workspace
            .get("workspace")
            .and_then(|w| w.get("package"))
            .and_then(|p| p.get("edition"))
            .and_then(toml::Value::as_str)
            .context("Cargo workspace edition missing")?
    } else {
        edition.and_then(toml::Value::as_str).unwrap_or("2015")
    };
    let autodiscover = manifest
        .get("package")
        .and_then(|p| p.get("autobins"))
        .and_then(toml::Value::as_bool)
        .unwrap_or(edition != "2015" || explicit.is_none());
    let mut bins = BTreeMap::new();
    if autodiscover {
        let prefix = if base == root {
            String::new()
        } else {
            format!("{}/", relative(root, base)?)
        };
        if files.contains_key(&format!("{prefix}src/main.rs")) {
            input(root, &base.join("src/main.rs"), files)?;
            bins.insert(package.into(), vec![]);
        }
        for name in files.keys() {
            if let Some(local) = name.strip_prefix(&format!("{prefix}src/bin/")) {
                let binary = if !local.contains('/') {
                    local.strip_suffix(".rs")
                } else {
                    local
                        .strip_suffix("/main.rs")
                        .filter(|name| !name.contains('/'))
                };
                if let Some(binary) = binary {
                    input(root, &root.join(name), files)?;
                    bins.insert(binary.into(), vec![]);
                }
            }
        }
    }
    for bin in explicit.into_iter().flatten() {
        let name = bin
            .get("name")
            .and_then(toml::Value::as_str)
            .context("Cargo binary name missing")?;
        if let Some(path) = bin.get("path").and_then(toml::Value::as_str) {
            // Cargo accepts parent components; normalize them before enforcing Git bounds.
            input(root, &normalize(&base.join(path))?, files)?;
        } else if !bins.contains_key(name) {
            let candidates = [
                base.join("src/bin").join(format!("{name}.rs")),
                base.join("src/bin").join(name).join("main.rs"),
                base.join("src/main.rs"),
            ];
            let candidate = candidates
                .iter()
                .find(|path| path.is_file())
                .context("Cargo binary has no tracked source path")?;
            input(root, candidate, files)?;
        }
        bins.insert(
            name.into(),
            bin.get("required-features")
                .and_then(toml::Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .collect(),
        );
    }
    Ok(bins)
}

fn normalize(path: &Path) -> Result<PathBuf> {
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => (),
            Component::ParentDir => {
                ensure!(result.pop(), "path leaves filesystem root");
            }
            part => result.push(part.as_os_str()),
        }
    }
    Ok(result)
}

pub fn validate_offline(
    root: &Path,
    p: &Product,
    r: &Resolution,
    files: &BTreeMap<String, String>,
) -> Result<()> {
    validate_offline_source(root, p, r, files, true)
}

pub(crate) fn validate_offline_source(
    root: &Path,
    p: &Product,
    r: &Resolution,
    files: &BTreeMap<String, String>,
    check_environment: bool,
) -> Result<()> {
    let cwd = directory(root, &p.directory)?;
    match &p.build {
        Builder::Rust {
            package,
            manifest,
            features,
            default_features,
        } => {
            if check_environment {
                cargo_inputs(root, &cwd, files)?;
            }
            let path = joined(&cwd, manifest)?;
            let workspace_path = cwd.join("Cargo.toml");
            ensure!(
                r.manifest == relative(root, &path)?
                    && r.workspace_manifest.as_deref()
                        == Some(relative(root, &workspace_path)?.as_str()),
                "Rust resolution manifest differs from product contract"
            );
            let manifest = read_manifest(root, &path, files)?;
            let workspace = read_manifest(root, &workspace_path, files)?;
            input(root, &cwd.join("Cargo.lock"), files)?;
            let metadata = manifest.get("package").context("Cargo package missing")?;
            ensure!(
                metadata.get("name").and_then(toml::Value::as_str) == Some(package),
                "Rust resolution package differs from tracked manifest"
            );
            let version = metadata
                .get("version")
                .context("Cargo package version missing")?;
            let version = if version.get("workspace").and_then(toml::Value::as_bool) == Some(true) {
                workspace
                    .get("workspace")
                    .and_then(|w| w.get("package"))
                    .and_then(|p| p.get("version"))
                    .and_then(toml::Value::as_str)
                    .context("Cargo workspace version missing")?
            } else {
                version.as_str().context("invalid Cargo package version")?
            };
            ensure!(
                r.version == version,
                "Rust resolution version differs from tracked manifest"
            );
            let definitions = rust_features(&manifest);
            let mut active = BTreeSet::new();
            let mut pending = features.clone();
            if *default_features && definitions.contains_key("default") {
                pending.push("default".into());
            }
            for feature in features {
                ensure!(
                    definitions.contains_key(feature),
                    "unknown Rust feature {feature}"
                );
            }
            while let Some(feature) = pending.pop() {
                if !active.insert(feature.clone()) {
                    continue;
                }
                if let Some(values) = definitions.get(&feature) {
                    for value in values {
                        if definitions.contains_key(value) {
                            pending.push(value.clone());
                        } else if let Some((dependency, _)) = value.split_once('/')
                            && definitions.contains_key(dependency)
                        {
                            pending.push(dependency.into());
                        }
                    }
                }
            }
            let available = rust_binary_inputs(root, &path, &manifest, &workspace, package, files)?;
            for bin in &p.binaries {
                let required = available
                    .get(bin)
                    .with_context(|| format!("unknown tracked Rust binary {bin}"))?;
                for feature in required {
                    ensure!(
                        active.contains(feature),
                        "Rust binary {bin} requires disabled feature {feature}"
                    );
                }
            }
        }
        Builder::Go {
            version, packages, ..
        } => {
            ensure!(
                r.version == *version
                    && r.manifest == relative(root, &cwd.join("go.mod"))?
                    && r.workspace_manifest.is_none(),
                "Go resolution differs from product contract"
            );
            ensure!(
                p.binaries.len() == packages.len(),
                "Go packages must correspond positionally to product binaries"
            );
            go_module(root, &cwd, files)?;
            go_source_check(root, &cwd, packages, files)?;
        }
    }
    Ok(())
}

fn rust_target(t: &Target) -> Result<String> {
    ensure!(
        matches!(t.arch.as_str(), "x86_64" | "aarch64"),
        "unsupported Rust architecture"
    );
    let suffix = match (t.os.as_str(), t.abi.as_deref()) {
        ("linux", Some("gnu")) => "unknown-linux-gnu",
        ("linux", Some("musl")) => "unknown-linux-musl",
        ("windows", Some("msvc")) => "pc-windows-msvc",
        ("macos", None) => "apple-darwin",
        _ => bail!("unsupported Rust target: {}", t.key()),
    };
    Ok(format!("{}-{suffix}", t.arch))
}

fn go_target(t: &Target) -> Result<(&str, &str)> {
    ensure!(t.abi.is_none(), "pure Go targets must omit ABI");
    let os = match t.os.as_str() {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "windows",
        _ => bail!("unsupported Go operating system"),
    };
    let arch = match t.arch.as_str() {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => bail!("unsupported Go architecture"),
    };
    Ok((os, arch))
}

pub fn recipe(p: &Product, r: &Resolution, t: &Target, build_dir: &str) -> Result<Recipe> {
    match &p.build {
        Builder::Rust {
            package,
            manifest,
            features,
            default_features,
        } => {
            let target = rust_target(t)?;
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
                target.clone(),
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
                    env: BTreeMap::new(),
                }],
                binaries: p
                    .binaries
                    .iter()
                    .map(|bin| {
                        let path = t.binary_name(bin);
                        BinaryOutput {
                            source: format!("{build_dir}/{target}/release/{path}"),
                            path,
                        }
                    })
                    .collect(),
                compiler_target: target,
            })
        }
        Builder::Go {
            packages, ldflags, ..
        } => {
            ensure!(
                packages.len() == p.binaries.len(),
                "Go packages must correspond positionally to product binaries"
            );
            let (os, arch) = go_target(t)?;
            let mut env = go_env();
            env.extend([("GOOS".into(), os.into()), ("GOARCH".into(), arch.into())]);
            let mut commands = vec![];
            let mut binaries = vec![];
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
                            .map(|flag| flag.replace("{version}", &r.version))
                            .collect::<Vec<_>>()
                            .join(" "),
                    ]);
                }
                argv.push(package.clone());
                commands.push(CommandSpec {
                    argv,
                    cwd: p.directory.clone(),
                    env: env.clone(),
                });
                binaries.push(BinaryOutput {
                    source: output,
                    path,
                });
            }
            Ok(Recipe {
                commands,
                binaries,
                compiler_target: format!("{os}/{arch}"),
            })
        }
    }
}

pub fn probes(products: &[Product]) -> Vec<(String, CommandSpec)> {
    let mut values = BTreeMap::new();
    for p in products {
        let commands: &[(&str, &[&str])] = match p.build {
            Builder::Rust { .. } => &[
                ("cargo", &["cargo", "--version"]),
                ("rustc", &["rustc", "-vV"]),
            ],
            Builder::Go { .. } => &[("go", &["go", "version"])],
        };
        for (tool, argv) in commands {
            values.insert(
                format!("{tool}:{}", p.directory),
                CommandSpec {
                    argv: argv.iter().map(|arg| (*arg).into()).collect(),
                    cwd: p.directory.clone(),
                    env: if *tool == "go" {
                        go_env()
                    } else {
                        BTreeMap::new()
                    },
                },
            );
        }
    }
    values.into_iter().collect()
}

fn tracked(root: &Path) -> Result<BTreeMap<String, String>> {
    Ok(source::git(root, &["ls-files", "-z"])?
        .split('\0')
        .filter(|name| !name.is_empty())
        .map(|name| (name.into(), String::new()))
        .collect())
}

fn product(id: String, directory: &str, binaries: Vec<String>, build: Builder) -> Product {
    Product {
        id,
        directory: directory.into(),
        binaries,
        build,
        targets: vec![],
        assets: vec![],
        prepare: vec![],
        checks: vec![],
        version_args: vec!["--version".into()],
        version_binaries: None,
    }
}

pub fn discover(
    root: &Path,
    directory_name: &str,
    kind: &str,
    version: Option<&str>,
) -> Result<Vec<Product>> {
    let cwd = directory(root, directory_name)?;
    let files = tracked(root)?;
    let mut products = vec![];
    match kind {
        "rust" => {
            cargo_inputs(root, &cwd, &files)?;
            input(root, &cwd.join("Cargo.toml"), &files)?;
            input(root, &cwd.join("Cargo.lock"), &files)?;
            let data = cargo_metadata(&cwd, "Cargo.toml", &[], true)?;
            cargo_metadata_inputs(root, &cwd, &data, &files)?;
            let members = data["workspace_members"]
                .as_array()
                .context("Cargo workspace members missing")?;
            for package in data["packages"]
                .as_array()
                .context("Cargo packages missing")?
            {
                if !members.iter().any(|member| member == &package["id"]) {
                    continue;
                }
                let binaries: Vec<_> = package["targets"]
                    .as_array()
                    .context("Cargo targets missing")?
                    .iter()
                    .filter(|target| is_bin(target))
                    .map(|target| text(target, "name").map(str::to_owned))
                    .collect::<Result<_>>()?;
                if binaries.is_empty() {
                    continue;
                }
                let name = text(package, "name")?.to_owned();
                let manifest = Path::new(text(package, "manifest_path")?)
                    .strip_prefix(&cwd)?
                    .to_str()
                    .context("non-UTF8 Cargo manifest")?
                    .replace('\\', "/");
                products.push(product(
                    name.clone(),
                    directory_name,
                    binaries,
                    Builder::Rust {
                        package: name,
                        manifest,
                        features: vec![],
                        default_features: true,
                    },
                ));
            }
        }
        "go" => {
            let version = version
                .context("Go application discovery requires an explicit application version")?;
            let module = go_module(root, &cwd, &files)?;
            let data = go_list(&cwd, &["./...".into()])?;
            go_metadata_inputs(root, &cwd, &data, &files)?;
            for package in &data {
                if package["Name"].as_str() != Some("main")
                    || package["Module"]["Main"].as_bool() != Some(true)
                {
                    continue;
                }
                let dir = Path::new(text(package, "Dir")?);
                let (name, selected) = if dir == cwd {
                    (
                        module
                            .rsplit('/')
                            .next()
                            .context("Go module name missing")?
                            .to_owned(),
                        ".".into(),
                    )
                } else {
                    (
                        dir.file_name()
                            .and_then(|name| name.to_str())
                            .context("Go package directory name missing")?
                            .to_owned(),
                        format!(
                            "./{}",
                            dir.strip_prefix(&cwd)?
                                .to_str()
                                .context("non-UTF8 Go package path")?
                                .replace('\\', "/")
                        ),
                    )
                };
                products.push(product(
                    name.clone(),
                    directory_name,
                    vec![name],
                    Builder::Go {
                        version: version.into(),
                        packages: vec![selected],
                        ldflags: vec![],
                    },
                ));
            }
        }
        _ => bail!("unsupported builder kind: {kind}"),
    }
    ensure!(!products.is_empty(), "no binary products discovered");
    products.sort_by(|left, right| left.id.cmp(&right.id));
    ensure!(
        products.windows(2).all(|pair| pair[0].id != pair[1].id),
        "discovery found duplicate product names; declare explicit product IDs"
    );
    Ok(products)
}

pub fn native_target(kind: &str) -> Result<Target> {
    native_target_at(&std::env::current_dir()?, kind)
}

pub fn native_target_at(cwd: &Path, kind: &str) -> Result<Target> {
    if kind == "go" {
        let target = Target {
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            abi: None,
        };
        go_target(&target)?;
        return Ok(target);
    }
    ensure!(kind == "rust", "unsupported builder kind: {kind}");
    let host = crate::plan::host(cwd)?;
    for os in ["linux", "windows", "macos"] {
        for arch in ["x86_64", "aarch64"] {
            let abis: &[Option<&str>] = match os {
                "linux" => &[Some("gnu"), Some("musl")],
                "windows" => &[Some("msvc")],
                _ => &[None],
            };
            for abi in abis {
                let target = Target {
                    os: os.into(),
                    arch: arch.into(),
                    abi: abi.map(str::to_owned),
                };
                if rust_target(&target)? == host {
                    return Ok(target);
                }
            }
        }
    }
    bail!("unsupported rustc host: {host}")
}

pub fn can_run(t: &Target, recipe: &Recipe, toolchain: &BTreeMap<String, String>) -> bool {
    let Some(command) = recipe.commands.first() else {
        return false;
    };
    if command.argv.first().is_some_and(|tool| tool == "cargo") {
        let key = format!("rustc:{}", command.cwd);
        return toolchain
            .get(&key)
            .and_then(|output| output.lines().find_map(|line| line.strip_prefix("host: ")))
            .is_some_and(|host| host == recipe.compiler_target);
    }
    if command.argv.first().is_none_or(|tool| tool != "go") {
        return false;
    }
    let Ok((os, arch)) = go_target(t) else {
        return false;
    };
    let key = format!("go:{}", command.cwd);
    toolchain
        .get(&key)
        .and_then(|output| output.split_whitespace().last())
        .is_some_and(|host| host == format!("{os}/{arch}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(root: &Path, values: &[(&str, &str)]) -> BTreeMap<String, String> {
        let mut files = BTreeMap::new();
        for (name, contents) in values {
            let path = root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
            files.insert((*name).into(), String::new());
        }
        files
    }

    #[test]
    fn offline_rust_inheritance_and_required_binary_features() {
        let temp = tempfile::tempdir().unwrap();
        let source = files(
            temp.path(),
            &[
                (
                    "Cargo.toml",
                    "[workspace]\nmembers=['app']\n[workspace.package]\nversion='1.2.3'\n",
                ),
                ("Cargo.lock", "version = 4\n"),
                (
                    "app/Cargo.toml",
                    "[package]\nname='app'\nversion.workspace=true\nedition='2024'\n[features]\ncli=[]\n[[bin]]\nname='tool'\npath='main.rs'\nrequired-features=['cli']\n",
                ),
                ("app/main.rs", "fn main() {}"),
            ],
        );
        let mut p = product(
            "app".into(),
            ".",
            vec!["tool".into()],
            Builder::Rust {
                package: "app".into(),
                manifest: "app/Cargo.toml".into(),
                features: vec![],
                default_features: false,
            },
        );
        let resolution = Resolution {
            version: "1.2.3".into(),
            manifest: "app/Cargo.toml".into(),
            workspace_manifest: Some("Cargo.toml".into()),
        };
        assert!(
            validate_offline(temp.path(), &p, &resolution, &source)
                .unwrap_err()
                .to_string()
                .contains("disabled feature")
        );
        if let Builder::Rust { features, .. } = &mut p.build {
            features.push("cli".into());
        }
        validate_offline(temp.path(), &p, &resolution, &source).unwrap();
        let mut forged = resolution;
        forged.version = "9.0.0".into();
        assert!(validate_offline(temp.path(), &p, &forged, &source).is_err());
    }

    #[test]
    fn offline_go_rejects_cgo_and_local_module_replacements() {
        let temp = tempfile::tempdir().unwrap();
        let source = files(
            temp.path(),
            &[
                ("go.mod", "module example.com/app\ngo 1.22\n"),
                (
                    "cmd/tool/main.go",
                    "package main\nimport \"C\"\nfunc main() {}",
                ),
            ],
        );
        let p = product(
            "app".into(),
            ".",
            vec!["tool".into()],
            Builder::Go {
                version: "1.0.0".into(),
                packages: vec!["./cmd/tool".into()],
                ldflags: vec![],
            },
        );
        let r = Resolution {
            version: "1.0.0".into(),
            manifest: "go.mod".into(),
            workspace_manifest: None,
        };
        assert!(
            validate_offline(temp.path(), &p, &r, &source)
                .unwrap_err()
                .to_string()
                .contains("cgo")
        );
        fs::write(
            temp.path().join("cmd/tool/main.go"),
            "package main\nfunc main() {}\n",
        )
        .unwrap();
        validate_offline(temp.path(), &p, &r, &source).unwrap();
        fs::write(
            temp.path().join("go.mod"),
            "module example.com/app\nreplace example.com/lib => ../lib\n",
        )
        .unwrap();
        assert!(
            validate_offline(temp.path(), &p, &r, &source)
                .unwrap_err()
                .to_string()
                .contains("replacements")
        );
    }

    #[test]
    fn runtime_gating_keeps_rust_abis_distinct_and_go_abi_absent() {
        let p = product(
            "app".into(),
            "workspace",
            vec!["tool".into()],
            Builder::Rust {
                package: "app".into(),
                manifest: "Cargo.toml".into(),
                features: vec![],
                default_features: true,
            },
        );
        let r = Resolution {
            version: "1".into(),
            manifest: "workspace/Cargo.toml".into(),
            workspace_manifest: Some("workspace/Cargo.toml".into()),
        };
        let target = Target {
            os: "linux".into(),
            arch: "x86_64".into(),
            abi: Some("musl".into()),
        };
        let recipe = recipe(&p, &r, &target, "{attempt}/work/build-0").unwrap();
        let mut evidence = BTreeMap::from([(
            "rustc:workspace".into(),
            "host: x86_64-unknown-linux-gnu\n".into(),
        )]);
        assert!(!can_run(&target, &recipe, &evidence));
        evidence.insert(
            "rustc:workspace".into(),
            "host: x86_64-unknown-linux-musl\n".into(),
        );
        assert!(can_run(&target, &recipe, &evidence));
        assert!(go_target(&target).is_err());
    }

    #[test]
    fn go_runtime_uses_recorded_worker_host_instead_of_verifier_host() {
        let p = product(
            "app".into(),
            "tools/go",
            vec!["tool".into()],
            Builder::Go {
                version: "1.0.0".into(),
                packages: vec![".".into()],
                ldflags: vec![],
            },
        );
        let r = Resolution {
            version: "1.0.0".into(),
            manifest: "tools/go/go.mod".into(),
            workspace_manifest: None,
        };
        let target = Target {
            os: "linux".into(),
            arch: "x86_64".into(),
            abi: None,
        };
        let build = recipe(&p, &r, &target, "{attempt}/work/build-0").unwrap();
        let mut evidence = BTreeMap::from([(
            "go:tools/go".into(),
            "go version go1.27.3 darwin/arm64\n".into(),
        )]);
        assert!(!can_run(&target, &build, &evidence));
        evidence.insert(
            "go:tools/go".into(),
            "go version go1.27.3 linux/amd64\n".into(),
        );
        assert!(can_run(&target, &build, &evidence));
        let mut abi = target;
        abi.abi = Some("gnu".into());
        assert!(!can_run(&abi, &build, &evidence));
    }
}
