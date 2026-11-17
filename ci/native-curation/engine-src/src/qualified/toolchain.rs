use crate::compatibility::NativeSdkExpectation;
use anyhow::{Context, Result, bail, ensure};
use std::{collections::BTreeMap, path::Path};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeToolchain {
    pub program: String,
    pub environment: BTreeMap<String, String>,
    pub probes: Vec<(String, Vec<String>)>,
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or("")
}

fn tool_name(path: &str) -> String {
    let name = basename(path).to_ascii_lowercase();
    name.strip_suffix(".exe").unwrap_or(&name).into()
}

fn unique_tool(sdk: &NativeSdkExpectation, name: &str) -> Result<String> {
    let paths = sdk
        .tool_sha256
        .keys()
        .filter(|path| tool_name(path) == name)
        .collect::<Vec<_>>();
    ensure!(
        paths.len() == 1,
        "native {name} requires exactly one pinned {name} executable; found {}",
        paths.len()
    );
    Ok(paths[0].clone())
}

// SDK paths belong to the target OS, which can differ from the planning host.
fn portable_key(path: &str) -> String {
    let key = path.replace('\\', "/");
    if key.as_bytes().get(1) == Some(&b':') {
        key.to_ascii_lowercase()
    } else {
        key
    }
}

/// Bind CMake's C compiler and generator backend to reviewed executable pins.
pub fn native_cmake_tools(sdk: &NativeSdkExpectation, generator: &str) -> Result<(String, String)> {
    sdk.validate()?;
    let backend_names: &[&str] = match generator {
        "Ninja" | "Ninja Multi-Config" => &["ninja"],
        "Unix Makefiles" => &["make", "gmake"],
        "NMake Makefiles" => &["nmake.exe"],
        _ => bail!("native CMake generator {generator:?} has no supported pinned native backend"),
    };
    let backends = sdk
        .tool_sha256
        .keys()
        .filter(|path| {
            if generator == "NMake Makefiles" {
                basename(path).eq_ignore_ascii_case("nmake.exe")
            } else {
                backend_names.contains(&tool_name(path).as_str())
            }
        })
        .collect::<Vec<_>>();
    ensure!(
        backends.len() == 1,
        "native CMake generator {generator:?} requires exactly one pinned native backend ({}); found {}",
        backend_names.join(" or "),
        backends.len()
    );
    let eligible = |path: &str| {
        matches!(tool_name(path).as_str(), "clang" | "gcc" | "cc")
            || basename(path).eq_ignore_ascii_case("cl.exe")
    };
    let compilers = sdk
        .tool_sha256
        .keys()
        .filter(|path| eligible(path))
        .filter(|path| {
            sdk.environment
                .get("CC")
                .is_none_or(|cc| portable_key(path) == portable_key(cc))
        })
        .collect::<Vec<_>>();
    ensure!(
        compilers.len() == 1,
        "native CMake requires exactly one pinned C compiler (clang, gcc, cc, or cl.exe){}; found {}",
        if sdk.environment.contains_key("CC") {
            " matching the reviewed absolute CC path"
        } else {
            "; set the reviewed absolute CC path to resolve multiple compilers"
        },
        compilers.len()
    );
    Ok((compilers[0].clone(), backends[0].clone()))
}

fn parent(path: &str) -> Result<&str> {
    let separator = path
        .rfind(['/', '\\'])
        .context("native tool has no parent")?;
    ensure!(
        separator > 0,
        "native toolchain prefix must not be the filesystem root"
    );
    Ok(&path[..separator])
}

fn prefix(program: &str) -> Result<&str> {
    let bin = parent(program)?;
    ensure!(
        basename(bin).eq_ignore_ascii_case("bin"),
        "native tool must be installed in a toolchain bin directory: {program}"
    );
    let prefix = parent(bin)?;
    ensure!(
        !prefix.ends_with(':'),
        "native toolchain prefix must not be the filesystem root"
    );
    Ok(prefix)
}

fn child(prefix: &str, relative: &str) -> String {
    let separator = if prefix.contains('\\') { '\\' } else { '/' };
    format!(
        "{prefix}{separator}{}",
        relative.replace('/', &separator.to_string())
    )
}

fn covered(sdk: &NativeSdkExpectation, path: &str) -> bool {
    let path = portable_key(path);
    sdk.roots.keys().any(|root| {
        let root = portable_key(root);
        path == root
            || path
                .strip_prefix(root.trim_end_matches('/'))
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

fn rust_libraries(prefix: &str, target: &str) -> Result<String> {
    ensure!(
        !target.is_empty()
            && target
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_')),
        "native Rust compiler target must be a normalized target triple"
    );
    Ok(child(prefix, &format!("lib/rustlib/{target}/lib")))
}

/// Select pinned native executables without consulting PATH or the local filesystem.
/// Call `validate_native_filesystem` on the native worker before execution.
pub fn native_selection(
    sdk: &NativeSdkExpectation,
    kind: &str,
    compiler_target: &str,
) -> Result<NativeToolchain> {
    sdk.validate()?;
    let mut environment = sdk.environment.clone();
    let (program, probes) = match kind {
        "rust" => {
            let cargo = unique_tool(sdk, "cargo")?;
            let rustc = unique_tool(sdk, "rustc")?;
            let root = prefix(&cargo)?;
            ensure!(
                portable_key(root) == portable_key(prefix(&rustc)?),
                "native cargo and rustc must belong to the same pinned toolchain prefix"
            );
            let libraries = rust_libraries(root, compiler_target)?;
            ensure!(
                covered(sdk, root) && covered(sdk, &libraries),
                "native Rust SDK roots must cover the toolchain prefix and target libraries: {libraries}"
            );
            environment.insert("RUSTC".into(), rustc.clone());
            (
                cargo.clone(),
                vec![
                    (cargo, vec!["--version".into()]),
                    (rustc, vec!["--version".into()]),
                ],
            )
        }
        "go" => {
            let go = unique_tool(sdk, "go")?;
            let root = prefix(&go)?;
            ensure!(
                covered(sdk, root)
                    && covered(sdk, &child(root, "src"))
                    && covered(sdk, &child(root, "pkg")),
                "native Go SDK roots must cover the toolchain prefix, src, and pkg directories"
            );
            environment.extend([
                ("GOROOT".into(), root.into()),
                ("GOTOOLCHAIN".into(), "local".into()),
                ("CGO_ENABLED".into(), "0".into()),
            ]);
            (go.clone(), vec![(go, vec!["version".into()])])
        }
        _ => bail!("unsupported native toolchain kind: {kind}"),
    };
    Ok(NativeToolchain {
        program,
        environment,
        probes,
    })
}

/// Check the selected closure on its actual worker, after SDK identity verification.
/// This check is deliberately separate from offline selection and plan verification.
pub fn validate_native_filesystem(
    toolchain: &NativeToolchain,
    kind: &str,
    compiler_target: &str,
) -> Result<()> {
    for (program, _) in &toolchain.probes {
        ensure!(
            Path::new(program).is_file(),
            "pinned native executable is not a regular file: {program}"
        );
    }
    let root = prefix(&toolchain.program)?;
    let directories = match kind {
        "rust" => vec![rust_libraries(root, compiler_target)?],
        "go" => vec![child(root, "src"), child(root, "pkg")],
        _ => bail!("unsupported native toolchain kind: {kind}"),
    };
    for directory in directories {
        ensure!(
            Path::new(&directory).is_dir(),
            "pinned native toolchain closure directory is missing: {directory}"
        );
    }
    Ok(())
}

pub fn validate_version(tool: &str, output: &str) -> Result<()> {
    let name = tool_name(tool);
    let expected = match name.as_str() {
        "cargo" | "rustc" => "1.96.0",
        "go" => "go1.27.4",
        _ => bail!("unsupported native version probe tool: {tool}"),
    };
    let output = output.trim();
    ensure!(
        !output.is_empty() && !output.contains(['\n', '\r', '\0']),
        "native {name} version probe must return one nonempty line"
    );
    let mut words = output.split_whitespace();
    let found = if name == "go" {
        ensure!(
            words.next() == Some("go") && words.next() == Some("version"),
            "native Go version probe has an unexpected format"
        );
        words.next()
    } else {
        ensure!(
            words.next() == Some(name.as_str()),
            "native {name} version probe has an unexpected tool name"
        );
        words.next()
    };
    ensure!(
        found == Some(expected),
        "native {name} requires version {expected}; observed {}",
        found.unwrap_or("<missing>")
    );
    Ok(())
}
