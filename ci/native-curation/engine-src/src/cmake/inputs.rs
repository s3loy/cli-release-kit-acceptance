//! Resolved File API input checks for configured C/ASM targets.
use super::{
    MAX_FILES, MAX_JSON, REPLY_DIR, Spec, Witness, array, check_target_closure, object,
    owned_directory, path_text, reply_closure, same_recorded_tree, string, validate_spec,
};
use crate::config;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

/// Resolved configure-time inputs, in their original execution-environment namespace.
/// The same selection can be reproduced from preserved replies without the SDK or build tree.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InputSelection {
    pub paths: BTreeSet<String>,
}

// File API command fragments are argument strings, not shell programs. Keep the
// accepted quoting grammar small and reject indirection that would conceal inputs.
fn input_tokens(fragment: &str, windows: bool) -> Result<Vec<String>> {
    ensure!(
        fragment.len() <= MAX_JSON as usize,
        "CMake input fragment exceeds bound"
    );
    let chars = fragment.chars().collect::<Vec<_>>();
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let mut active = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        ensure!(
            !c.is_control() || c == '\t',
            "unsupported CMake input fragment control character"
        );
        ensure!(
            !matches!(c, '$' | '`'),
            "unsupported CMake input fragment expansion"
        );
        ensure!(
            !windows || !matches!(c, '%' | '!' | '^'),
            "unsupported CMake Windows input fragment expansion or escape"
        );
        if windows && c == '\\' {
            let start = i;
            while i < chars.len() && chars[i] == '\\' {
                i += 1;
            }
            let count = i - start;
            if chars.get(i) == Some(&'"') {
                token.extend(std::iter::repeat_n('\\', count / 2));
                if count % 2 == 1 {
                    token.push('"');
                } else {
                    quote = if quote.is_some() { None } else { Some('"') };
                }
                i += 1;
            } else {
                token.extend(std::iter::repeat_n('\\', count));
            }
            active = true;
            continue;
        }
        if !windows && c == '\\' && quote != Some('\'') {
            i += 1;
            let next = *chars
                .get(i)
                .context("unsupported trailing CMake input escape")?;
            ensure!(!next.is_control(), "unsupported CMake input escape");
            token.push(next);
            active = true;
        } else if c == '"' || (!windows && c == '\'') {
            if quote == Some(c) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(c);
            } else {
                token.push(c);
            }
            active = true;
        } else if c.is_whitespace() && quote.is_none() {
            if active {
                tokens.push(std::mem::take(&mut token));
                active = false;
            }
        } else {
            ensure!(
                quote.is_some() || !matches!(c, ';' | '|' | '&' | '<' | '>' | '*' | '?' | '['),
                "unsupported CMake input fragment shell syntax"
            );
            token.push(c);
            active = true;
        }
        i += 1;
    }
    ensure!(
        quote.is_none(),
        "unsupported unterminated CMake input fragment quote"
    );
    if active {
        tokens.push(token);
    }
    ensure!(
        tokens.len() <= MAX_FILES,
        "CMake input fragment exceeds token bound"
    );
    Ok(tokens)
}

fn input_absolute(path: &str, windows: bool) -> bool {
    path.starts_with('/') || (windows && path.as_bytes().get(1) == Some(&b':'))
}

fn normalize_input(raw: &str, base: &str, windows: bool) -> Result<String> {
    ensure!(
        !raw.is_empty() && !raw.chars().any(char::is_control),
        "invalid CMake input path"
    );
    let raw = raw.replace('\\', "/");
    let raw = raw.strip_prefix("//?/").unwrap_or(&raw);
    ensure!(!raw.starts_with("//"), "unsupported CMake UNC input path");
    let joined = if input_absolute(raw, windows) {
        raw.to_owned()
    } else {
        ensure!(
            !raw.contains(':') && !raw.starts_with('~'),
            "unsupported CMake input path: {raw}"
        );
        format!("{base}/{raw}")
    };
    let (prefix, tail) = if windows && joined.as_bytes().get(1) == Some(&b':') {
        ensure!(
            joined.as_bytes()[0].is_ascii_alphabetic() && joined.as_bytes().get(2) == Some(&b'/'),
            "CMake input requires an absolute Windows path"
        );
        (joined[..2].to_ascii_lowercase(), &joined[3..])
    } else {
        ensure!(
            joined.starts_with('/'),
            "CMake input requires an absolute path"
        );
        (String::new(), joined.trim_start_matches('/'))
    };
    let mut parts = Vec::new();
    for part in tail.split('/') {
        match part {
            "" | "." => (),
            ".." => {
                ensure!(
                    parts.pop().is_some(),
                    "CMake input path escapes filesystem root"
                );
            }
            value => parts.push(value),
        }
    }
    let normalized = format!("{prefix}/{}", parts.join("/"));
    Ok(if windows {
        normalized.to_lowercase()
    } else {
        normalized
    })
}

fn input_within(path: &str, root: &str) -> bool {
    path == root
        || root == "/"
        || path
            .strip_prefix(root)
            .is_some_and(|tail| tail.starts_with('/'))
}

struct InputBounds {
    roots: Vec<String>,
    canonical_roots: Vec<PathBuf>,
    source: String,
    build: String,
    windows: bool,
    online: bool,
    paths: BTreeSet<String>,
    search_directories: BTreeSet<String>,
    bare_libraries: bool,
}

impl InputBounds {
    fn new(roots: &[PathBuf], source: &str, build: &str, os: &str, online: bool) -> Result<Self> {
        ensure!(
            matches!(os, "linux" | "macos" | "windows"),
            "unsupported CMake input OS: {os}"
        );
        let windows = os == "windows";
        let source = normalize_input(source, "", windows)?;
        let build = normalize_input(build, "", windows)?;
        let mut normalized = BTreeSet::new();
        let mut canonical_roots = Vec::new();
        for root in roots {
            normalized.insert(normalize_input(&path_text(root)?, "", windows)?);
            if online {
                canonical_roots.push(fs::canonicalize(root).with_context(|| {
                    format!(
                        "CMake allowed input root is unavailable: {}",
                        root.display()
                    )
                })?);
            }
        }
        ensure!(
            !normalized.is_empty(),
            "CMake allowed input roots are empty"
        );
        Ok(Self {
            roots: normalized.into_iter().collect(),
            canonical_roots,
            source,
            build,
            windows,
            online,
            paths: BTreeSet::new(),
            search_directories: BTreeSet::new(),
            bare_libraries: false,
        })
    }

    fn add(&mut self, raw: &str, base: &str, search: bool) -> Result<()> {
        let normalized = normalize_input(raw, base, self.windows)?;
        ensure!(
            self.roots
                .iter()
                .any(|root| input_within(&normalized, root)),
            "CMake resolved input is outside declared input roots: {normalized}"
        );
        if self.online {
            let replaced = raw.replace('\\', "/");
            let path = if input_absolute(&replaced, self.windows) {
                PathBuf::from(raw)
            } else {
                Path::new(base).join(raw)
            };
            let actual = match fs::canonicalize(&path) {
                Ok(actual) => actual,
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound
                        && input_within(&normalized, &self.build) =>
                {
                    // Generated files need not exist before the build. Existing ancestors
                    // still have to stay inside the approved closure.
                    let mut ancestor = path.as_path();
                    loop {
                        match fs::canonicalize(ancestor) {
                            Ok(actual) => break actual,
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                                ensure!(
                                    !fs::symlink_metadata(ancestor)
                                        .is_ok_and(|meta| meta.file_type().is_symlink()),
                                    "CMake generated input contains an unresolved symlink: {}",
                                    ancestor.display()
                                );
                                ancestor = ancestor
                                    .parent()
                                    .context("CMake generated input lacks an existing ancestor")?;
                            }
                            Err(error) => {
                                return Err(error)
                                    .context("cannot resolve CMake generated input ancestor");
                            }
                        }
                    }
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("CMake resolved input is unavailable: {}", path.display())
                    });
                }
            };
            ensure!(
                self.canonical_roots
                    .iter()
                    .any(|root| actual.starts_with(root)),
                "CMake resolved input symlink escapes declared input roots: {}",
                path.display()
            );
            if search && path.exists() {
                ensure!(
                    path.is_dir(),
                    "CMake library search input is not a directory: {}",
                    path.display()
                );
            }
        }
        if search {
            self.search_directories.insert(normalized.clone());
        }
        self.paths.insert(normalized);
        Ok(())
    }

    fn fragments(&mut self, fragments: &Value, base: &str) -> Result<()> {
        let mut tokens = Vec::new();
        for fragment in fragments
            .as_array()
            .context("invalid CMake commandFragments")?
        {
            tokens.extend(input_tokens(string(fragment, "fragment")?, self.windows)?);
        }
        self.arguments(&tokens, base)
    }

    fn arguments(&mut self, tokens: &[String], base: &str) -> Result<()> {
        let mut i = 0;
        while i < tokens.len() {
            let token = &tokens[i];
            ensure!(
                !token.starts_with('@'),
                "unsupported CMake input response-file indirection"
            );
            if let Some(linker) = token.strip_prefix("-Wl,") {
                let arguments = linker.split(',').map(str::to_owned).collect::<Vec<_>>();
                ensure!(
                    arguments.iter().all(|s| !s.is_empty()),
                    "unsupported ambiguous CMake linker fragment"
                );
                self.arguments(&arguments, base)?;
                i += 1;
                continue;
            }
            let separate = match token.as_str() {
                "-I" | "-isystem" | "-iquote" | "-idirafter" | "-include" | "-imacros"
                | "-isysroot" | "--sysroot" | "-syslibroot" | "-B" => Some(false),
                "-L" | "-F" | "-iframework" | "-rpath-link" => Some(true),
                "-rpath" | "-R" => Some(false),
                _ => None,
            };
            if let Some(search) = separate {
                i += 1;
                let path = tokens
                    .get(i)
                    .context("CMake input path option lacks its argument")?;
                self.add(path, base, search)?;
            } else if self.windows
                && (token.eq_ignore_ascii_case("/I") || token.eq_ignore_ascii_case("/external:I"))
            {
                i += 1;
                self.add(
                    tokens
                        .get(i)
                        .context("CMake include option lacks its argument")?,
                    base,
                    false,
                )?;
            } else if let Some(path) = token.strip_prefix("-L").filter(|s| !s.is_empty()) {
                self.add(path, base, true)?;
            } else if let Some(path) = token.strip_prefix("-F").filter(|s| !s.is_empty()) {
                self.add(path, base, true)?;
            } else if matches!(
                token.as_str(),
                "-Bsymbolic" | "-Bsymbolic-functions" | "-Bstatic" | "-Bdynamic" | "-Bshareable"
            ) {
                // Linker binding flags share the compiler's -B path prefix.
            } else if let Some(path) = [
                "-isystem",
                "-iquote",
                "-idirafter",
                "-iframework",
                "-isysroot",
                "-I",
                "-B",
            ]
            .iter()
            .find_map(|prefix| token.strip_prefix(prefix).filter(|s| !s.is_empty()))
            {
                self.add(path.strip_prefix('=').unwrap_or(path), base, false)?;
            } else if self.windows && token.to_ascii_uppercase().starts_with("/LIBPATH:") {
                self.add(&token[9..], base, true)?;
            } else if self.windows
                && [
                    "/EXTERNAL:I",
                    "/I",
                    "/DEF:",
                    "/MANIFESTINPUT:",
                    "/WHOLEARCHIVE:",
                ]
                .iter()
                .any(|prefix| token.to_ascii_uppercase().starts_with(prefix))
            {
                let upper = token.to_ascii_uppercase();
                if [
                    "/INCREMENTAL",
                    "/IGNORE:",
                    "/IMPLIB:",
                    "/INFERASANLIBS",
                    "/INCLUDE:",
                    "/INTEGRITYCHECK",
                    "/IGNOREIDL",
                    "/IDLOUT:",
                ]
                .iter()
                .any(|prefix| upper.starts_with(prefix))
                {
                    i += 1;
                    continue;
                }
                let prefix = [
                    "/EXTERNAL:I",
                    "/I",
                    "/DEF:",
                    "/MANIFESTINPUT:",
                    "/WHOLEARCHIVE:",
                ]
                .into_iter()
                .find(|prefix| upper.starts_with(prefix))
                .unwrap();
                let path = &token[prefix.len()..];
                if prefix == "/WHOLEARCHIVE:" && !path.contains(['/', '\\', ':']) {
                    self.bare_libraries = true;
                } else {
                    self.add(path, base, false)?;
                }
            } else if self.windows && token.to_ascii_uppercase().starts_with("/DEFAULTLIB:") {
                let library = &token[12..];
                if library.contains(['/', '\\', ':']) {
                    self.add(library, base, false)?;
                } else {
                    self.bare_libraries = true;
                }
            } else if token.starts_with("-l") || token == "-framework" {
                ensure!(
                    !token.contains(['/', '\\']),
                    "unsupported CMake bare library path syntax"
                );
                self.bare_libraries = true;
            } else if let Some((_, path)) = token
                .split_once('=')
                .filter(|(_, path)| input_absolute(path, self.windows))
            {
                self.add(path, base, false)?;
            } else if input_absolute(token, self.windows)
                && !(self.windows && token.starts_with('/') && !token.starts_with("//"))
            {
                self.add(token, base, false)?;
            } else if !(token.starts_with('-') || self.windows && token.starts_with('/')) {
                let lower = token.to_ascii_lowercase();
                if self.windows && !token.contains(['/', '\\']) && lower.ends_with(".lib") {
                    self.bare_libraries = true;
                } else if token.contains(['/', '\\'])
                    || [".a", ".o", ".obj", ".so", ".dylib", ".lib"]
                        .iter()
                        .any(|suffix| lower.ends_with(suffix))
                {
                    self.add(token, base, false)?;
                }
            }
            i += 1;
        }
        Ok(())
    }
}

fn select_input_targets<'a>(
    model: &Value,
    values: &'a BTreeMap<String, Value>,
    spec: &Spec,
) -> Result<(BTreeMap<String, &'a Value>, BTreeSet<String>)> {
    let configurations = array(model, "configurations")?
        .iter()
        .filter(|c| c["name"].as_str() == Some(spec.configuration.as_str()))
        .collect::<Vec<_>>();
    ensure!(
        configurations.len() == 1,
        "CMake input configuration is missing or ambiguous"
    );
    let mut targets = BTreeMap::new();
    let mut names: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for reference in array(configurations[0], "targets")? {
        let target = values
            .get(string(reference, "jsonFile")?)
            .context("CMake input target is missing")?;
        let id = string(reference, "id")?;
        let name = string(reference, "name")?;
        ensure!(
            string(target, "id")? == id && string(target, "name")? == name,
            "CMake input target identity differs"
        );
        ensure!(
            targets.insert(id.to_owned(), target).is_none(),
            "duplicate CMake input target id"
        );
        names.entry(name.into()).or_default().push(id.into());
    }
    let mut selected = BTreeSet::new();
    for mapping in &spec.binary_targets {
        let ids = names
            .get(&mapping.target)
            .context("CMake mapped input target is missing")?;
        ensure!(ids.len() == 1, "CMake mapped input target is ambiguous");
        ensure!(
            string(targets[&ids[0]], "type")? == "EXECUTABLE",
            "CMake mapped input target is not executable"
        );
        let mut has_c = false;
        let mut closure = BTreeSet::new();
        check_target_closure(&ids[0], &targets, &mut closure, &mut has_c)?;
        ensure!(has_c, "CMake input closure has no C compilation");
        selected.extend(closure);
    }
    Ok((targets, selected))
}

fn resolved_inputs(
    index: &Value,
    values: &BTreeMap<String, Value>,
    spec: &Spec,
    roots: &[PathBuf],
    os: &str,
    declared_search_dirs: &[PathBuf],
    online: bool,
) -> Result<InputSelection> {
    validate_spec(spec)?;
    let model = object(index, values, "codemodel", 2)?;
    let mut bounds = InputBounds::new(
        roots,
        string(&model["paths"], "source")?,
        string(&model["paths"], "build")?,
        os,
        online,
    )?;
    let (targets, selected) = select_input_targets(model, values, spec)?;
    let source = bounds.source.clone();
    let build = bounds.build.clone();
    for directory in declared_search_dirs {
        bounds.add(&path_text(directory)?, &build, true)?;
    }
    let mut languages = BTreeSet::new();
    for id in selected {
        let target = targets[&id];
        if let Some(sources) = target.get("sources") {
            for input in sources.as_array().context("invalid CMake input sources")? {
                // File API source paths are source-relative even for GENERATED
                // files. Files outside the source tree have absolute paths.
                bounds.add(string(input, "path")?, &source, false)?;
            }
        }
        if let Some(groups) = target.get("compileGroups") {
            for group in groups
                .as_array()
                .context("invalid CMake input compileGroups")?
            {
                languages.insert(string(group, "language")?.to_owned());
                if let Some(includes) = group.get("includes") {
                    for include in includes
                        .as_array()
                        .context("invalid CMake input includes")?
                    {
                        bounds.add(string(include, "path")?, &source, false)?;
                    }
                }
                if let Some(frameworks) = group.get("frameworks") {
                    for framework in frameworks
                        .as_array()
                        .context("invalid CMake input frameworks")?
                    {
                        bounds.add(string(framework, "path")?, &source, true)?;
                    }
                }
                if let Some(headers) = group.get("precompileHeaders") {
                    for header in headers
                        .as_array()
                        .context("invalid CMake precompile headers")?
                    {
                        let header = string(header, "header")?;
                        if !(header.starts_with('<') && header.ends_with('>')) {
                            bounds.add(header, &source, false)?;
                        }
                    }
                }
                if let Some(fragments) = group.get("compileCommandFragments") {
                    bounds.fragments(fragments, &build)?;
                }
                if let Some(sysroot) = group.get("sysroot") {
                    bounds.add(string(sysroot, "path")?, &build, false)?;
                }
            }
        }
        for key in ["link", "archive"] {
            if let Some(step) = target.get(key) {
                if let Some(fragments) = step.get("commandFragments") {
                    bounds.fragments(fragments, &build)?;
                }
                if let Some(sysroot) = step.get("sysroot") {
                    bounds.add(string(sysroot, "path")?, &build, false)?;
                }
            }
        }
    }
    for toolchain in array(object(index, values, "toolchains", 1)?, "toolchains")? {
        if !languages.contains(string(toolchain, "language")?) {
            continue;
        }
        let compiler = toolchain
            .get("compiler")
            .context("CMake input toolchain lacks compiler")?;
        bounds.add(string(compiler, "path")?, &build, false)?;
        if let Some(fragment) = compiler.get("commandFragment") {
            let tokens = input_tokens(
                fragment
                    .as_str()
                    .context("invalid CMake compiler commandFragment")?,
                bounds.windows,
            )?;
            bounds.arguments(&tokens, &build)?;
        }
        if let Some(implicit) = compiler.get("implicit") {
            for key in [
                "includeDirectories",
                "linkDirectories",
                "linkFrameworkDirectories",
                "frameworkDirectories",
            ] {
                if let Some(directories) = implicit.get(key) {
                    for directory in directories
                        .as_array()
                        .context("invalid CMake implicit search directories")?
                    {
                        bounds.add(
                            directory
                                .as_str()
                                .context("invalid CMake implicit directory")?,
                            &build,
                            key != "includeDirectories",
                        )?;
                    }
                }
            }
            if let Some(libraries) = implicit.get("linkLibraries") {
                for library in libraries
                    .as_array()
                    .context("invalid CMake implicit libraries")?
                {
                    let library = library.as_str().context("invalid CMake implicit library")?;
                    if input_absolute(library, bounds.windows) || library.contains(['/', '\\']) {
                        bounds.add(library, &build, false)?;
                    } else if !library.is_empty() {
                        bounds.bare_libraries = true;
                    }
                }
            }
        }
    }
    for entry in array(object(index, values, "cache", 2)?, "entries")? {
        let name = string(entry, "name")?;
        let kind = string(entry, "type")?;
        if !matches!(kind, "FILEPATH" | "PATH") {
            continue;
        }
        let special = matches!(
            name,
            "CMAKE_SYSROOT"
                | "CMAKE_SYSROOT_COMPILE"
                | "CMAKE_SYSROOT_LINK"
                | "CMAKE_OSX_SYSROOT"
                | "CMAKE_TOOLCHAIN_FILE"
        );
        if (name.starts_with("CMAKE_") && !special)
            || name.ends_with("_BINARY_DIR")
            || name.ends_with("_SOURCE_DIR")
            || name.ends_with("INSTALL_PREFIX")
            || name.ends_with("INSTALL_DIRECTORY")
            || name.ends_with("OUTPUT_DIRECTORY")
        {
            continue;
        }
        for path in string(entry, "value")?.split(';') {
            if path.is_empty() || path.ends_with("-NOTFOUND") || path == "NOTFOUND" {
                continue;
            }
            bounds
                .add(path, &source, false)
                .with_context(|| format!("CMake dependency cache input {name}"))?;
        }
    }
    ensure!(
        !bounds.bare_libraries || !bounds.search_directories.is_empty(),
        "CMake bare libraries lack a declared compiler/SDK library search directory"
    );
    Ok(InputSelection {
        paths: bounds.paths,
    })
}

/// Check the selected C/ASM closure immediately after configure, before artifacts exist.
/// Allowed roots include the reported source/build trees and pinned SDK/dependency/tool roots.
pub fn validate_configured_inputs(
    build: &Path,
    spec: &Spec,
    allowed_roots: &[PathBuf],
    os: &str,
    declared_search_dirs: &[PathBuf],
) -> Result<InputSelection> {
    let build = owned_directory(build)?;
    let reply = config::safe_join(&build, REPLY_DIR)?;
    let mut indexes = Vec::new();
    for entry in fs::read_dir(&reply)? {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF8 CMake input reply name"))?;
        if name.starts_with("index-") && name.ends_with(".json") {
            indexes.push(name);
        }
    }
    indexes.sort();
    let name = indexes
        .last()
        .context("CMake File API input index is absent")?;
    let (values, _) = reply_closure(&reply, name)?;
    let index = values.get(name).context("CMake input index is absent")?;
    // Linux replies use the container namespace. Its image filesystem and mounted
    // input roots are plan-bound; host canonicalization would inspect another tree.
    resolved_inputs(
        index,
        &values,
        spec,
        allowed_roots,
        os,
        declared_search_dirs,
        os != "linux",
    )
}

/// Reproduce input selection from exact preserved bytes; never open original input roots.
pub fn validate_preserved_inputs(
    evidence: &Path,
    witness: &Witness,
    allowed_roots: &[PathBuf],
    os: &str,
    declared_search_dirs: &[PathBuf],
) -> Result<InputSelection> {
    let evidence = owned_directory(evidence)?;
    let (values, hashes) = reply_closure(&evidence, &witness.index)?;
    ensure!(
        hashes == witness.reply_files,
        "CMake preserved input reply closure differs from witness"
    );
    let index = values
        .get(&witness.index)
        .context("CMake preserved input index is absent")?;
    same_recorded_tree(object(index, &values, "codemodel", 2)?, witness)?;
    resolved_inputs(
        index,
        &values,
        &witness.spec,
        allowed_roots,
        os,
        declared_search_dirs,
        false,
    )
}
