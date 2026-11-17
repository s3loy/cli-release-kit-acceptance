use crate::{config, model::SourceIdentity, process};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn file_digest(path: &Path) -> Result<String> {
    let mut input = File::open(path).with_context(|| format!("read {}", path.display()))?;
    let mut state = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        state.update(&buffer[..count]);
    }
    Ok(format!("{:x}", state.finalize()))
}

pub fn git(root: &Path, args: &[&str]) -> Result<String> {
    let argv: Vec<String> = ["git", "--no-optional-locks"]
        .iter()
        .chain(args.iter())
        .map(|s| (*s).into())
        .collect();
    process::capture(root, &argv, 60)
}

pub fn root(path: &Path) -> Result<PathBuf> {
    let root = path
        .canonicalize()
        .context("project directory does not exist")?;
    let top = git(&root, &["rev-parse", "--show-toplevel"])?;
    ensure!(
        Path::new(top.trim()).canonicalize()? == root,
        "project must be the Git top-level"
    );
    Ok(root)
}

pub fn cargo_configs(root: &Path) -> Result<Vec<String>> {
    let mut inputs = Vec::new();
    // Cargo searches ancestors and CARGO_HOME; inputs outside the source identity
    // cannot silently change a saved plan. Toolchain and SDK environment remains
    // explicit ambient execution evidence, not a hermetic build guarantee.
    for ancestor in root.ancestors().skip(1) {
        for name in [".cargo/config", ".cargo/config.toml"] {
            ensure!(
                !ancestor.join(name).exists(),
                "external Cargo configuration: {}",
                ancestor.join(name).display()
            );
        }
    }
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    if let Some(home) = cargo_home {
        let home = if home.is_absolute() {
            home
        } else {
            root.join(home)
        };
        for name in ["config", "config.toml"] {
            let path = home.join(name);
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    let relative = path
                        .strip_prefix(root)
                        .with_context(|| {
                            format!("external Cargo configuration: {}", path.display())
                        })?
                        .to_str()
                        .context("non-UTF8 Cargo config")?
                        .replace('\\', "/");
                    // Validate the path Cargo actually opens, before canonicalization
                    // could conceal an untracked symlink alias into a tracked file.
                    config::safe_join(root, &relative)?;
                    inputs.push(relative);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error.into()),
            }
        }
    }
    for name in [".cargo/config", ".cargo/config.toml"] {
        if config::safe_join(root, name)?.exists() {
            inputs.push(name.into());
        }
    }
    Ok(inputs)
}

pub fn snapshot(root: &Path) -> Result<SourceIdentity> {
    ensure!(self::root(root)? == root, "source root must be canonical");
    snapshot_with_configs(root, cargo_configs(root)?)
}

/// Capture language-neutral source identity without invoking language tools.
pub fn snapshot_plain(root: &Path) -> Result<SourceIdentity> {
    snapshot_with_configs(root, vec![])
}

fn snapshot_with_configs(root: &Path, cargo_configs: Vec<String>) -> Result<SourceIdentity> {
    ensure!(self::root(root)? == root, "source root must be canonical");
    let status = git(root, &["status", "--porcelain=v1", "--untracked-files=all"])?;
    ensure!(
        status.trim().is_empty(),
        "release planning requires a clean committed source tree: {status}"
    );
    let ignored = git(
        root,
        &[
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--directory",
            "-z",
        ],
    )?;
    for name in ignored.split('\0').filter(|s| !s.is_empty()) {
        ensure!(
            name == "target/" || name.starts_with("target/"),
            "ignored input outside target/ is not covered by source identity: {name}"
        );
    }
    let entries = git(root, &["ls-tree", "-r", "HEAD", "-z"])?;
    let mut files = BTreeMap::new();
    let mut blobs = Vec::new();
    for entry in entries.split('\0').filter(|s| !s.is_empty()) {
        let (metadata, name) = entry.split_once('\t').context("invalid Git index entry")?;
        let mode = metadata
            .split_whitespace()
            .next()
            .context("missing index mode")?;
        if mode == "120000" {
            config::relative(name)?;
            let path = match name.rsplit_once('/') {
                Some((parent, leaf)) => config::safe_join(root, parent)?.join(leaf),
                None => root.join(name),
            };
            ensure!(
                fs::symlink_metadata(&path)?.file_type().is_symlink(),
                "tracked source link is not a symlink: {name}"
            );
            let target = fs::read_link(&path)?;
            let text = target
                .to_str()
                .context("source symlink text must be UTF-8")?;
            let blob = metadata
                .split_whitespace()
                .nth(2)
                .context("missing HEAD link blob")?;
            let committed = git(root, &["cat-file", "blob", blob])?;
            ensure!(
                text == committed,
                "source symlink text differs from committed blob: {name}"
            );
            files.insert(name.to_owned(), digest(text.as_bytes()));
            continue;
        }
        ensure!(
            matches!(mode, "100644" | "100755"),
            "unsupported source entry (submodule or special mode): {name}"
        );
        let path = config::safe_join(root, name)?;
        let info = fs::metadata(&path)?;
        ensure!(
            info.is_file(),
            "source input must be a regular file: {name}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                (info.permissions().mode() & 0o111 != 0) == (mode == "100755"),
                "source executable mode differs from Git index: {name}"
            );
        }
        files.insert(name.to_owned(), file_digest(&path)?);
        blobs.push((
            name,
            metadata
                .split_whitespace()
                .nth(2)
                .context("missing HEAD blob")?,
        ));
    }
    // Read actual file bytes even when status trusts assume-unchanged, fsmonitor,
    // skip-worktree or cached stat data. Automatic checkout filters are unsupported.
    for chunk in blobs.chunks(100) {
        let mut args = vec!["hash-object", "--no-filters", "--"];
        args.extend(chunk.iter().map(|(name, _)| *name));
        let hashes = git(root, &args)?;
        let actual: Vec<_> = hashes.lines().collect();
        ensure!(actual.len() == chunk.len(), "incomplete source blob hashes");
        for ((name, expected), actual) in chunk.iter().zip(actual) {
            ensure!(
                *expected == actual,
                "working bytes differ from committed blob (checkout filters unsupported): {name}"
            );
        }
    }
    for name in cargo_configs {
        ensure!(
            files.contains_key(&name),
            "effective Cargo configuration must be tracked: {name}"
        );
    }
    ensure!(!files.is_empty(), "empty source tree");
    Ok(SourceIdentity {
        commit: git(root, &["rev-parse", "HEAD"])?.trim().into(),
        tree: git(root, &["rev-parse", "HEAD^{tree}"])?.trim().into(),
        files,
    })
}
