use crate::{config, model, v2};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::BTreeSet,
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use toml_edit::{DocumentMut, InlineTable, Item, Table, TableLike, Value};

#[derive(Clone, Copy, Debug)]
pub struct Capability {
    pub id: &'static str,
    pub label: &'static str,
    pub available: bool,
    pub reason: Option<&'static str>,
}

const fn supported(id: &'static str, label: &'static str) -> Capability {
    Capability {
        id,
        label,
        available: true,
        reason: None,
    }
}

const fn unavailable(id: &'static str, label: &'static str, reason: &'static str) -> Capability {
    Capability {
        id,
        label,
        available: false,
        reason: Some(reason),
    }
}

pub fn operating_systems() -> &'static [Capability] {
    const REASON: &str =
        "The current release schemas and builders do not support this operating system.";
    const VALUES: &[Capability] = &[
        supported("linux", "Linux"),
        supported("windows", "Windows"),
        supported("macos", "macOS"),
        unavailable("freebsd", "FreeBSD", REASON),
        unavailable("openbsd", "OpenBSD", REASON),
        unavailable("netbsd", "NetBSD", REASON),
        unavailable("dragonfly", "DragonFly BSD", REASON),
        unavailable("android", "Android", REASON),
        unavailable("ios", "iOS", REASON),
        unavailable("solaris", "Solaris", REASON),
        unavailable("wasi", "WASI", REASON),
    ];
    VALUES
}

pub fn architectures() -> &'static [Capability] {
    const ARM32: &str = "ARM32 variants are unsupported; the contract has no ARM version, float ABI, or GOARM fields.";
    const OTHER: &str = "The current release schemas and builders support only x86_64 and aarch64.";
    const VALUES: &[Capability] = &[
        supported("x86_64", "x86_64 / x64 / amd64"),
        supported("aarch64", "aarch64 / arm64"),
        unavailable("arm", "ARM32 (unspecified variant)", ARM32),
        unavailable("armv6", "ARMv6 / armv6l", ARM32),
        unavailable("armv7", "ARMv7 / armv7l", ARM32),
        unavailable("armhf", "ARM hard-float", ARM32),
        unavailable("armel", "ARM soft-float", ARM32),
        unavailable("x86", "x86 / i686", OTHER),
        unavailable("riscv64", "RISC-V 64", OTHER),
        unavailable("loongarch64", "LoongArch64", OTHER),
        unavailable("ppc64le", "PowerPC 64 little-endian", OTHER),
        unavailable("s390x", "IBM Z / s390x", OTHER),
    ];
    VALUES
}

pub fn package_formats() -> &'static [Capability] {
    const REASON: &str = "Unavailable in archive-only settings; review the explicit native-package configuration upgrade for Linux formats.";
    const VALUES: &[Capability] = &[
        supported("tar.gz", "tar.gz (Linux and macOS default)"),
        supported("zip", "zip (Windows default)"),
        unavailable("deb", "deb", REASON),
        unavailable("rpm", "rpm", REASON),
        unavailable("apk", "apk", REASON),
        unavailable("pacman", "pacman", REASON),
        unavailable("ipk", "ipk", REASON),
        unavailable("pkg", "pkg", REASON),
        unavailable("dmg", "dmg", REASON),
        unavailable("msi", "msi", REASON),
        unavailable("msix", "msix", REASON),
        unavailable("exe", "exe installer", REASON),
    ];
    VALUES
}

pub fn normalize_arch(value: &str) -> Result<&'static str> {
    match value.to_ascii_lowercase().as_str() {
        "x86_64" | "x64" | "amd64" => Ok("x86_64"),
        "aarch64" | "arm64" => Ok("aarch64"),
        arch if arch.starts_with("arm") || arch.starts_with("aarch32") => {
            bail!(
                "unsupported ARM32 architecture {value:?}; select aarch64/arm64 for ARM64; ARM32 needs an explicit variant and ABI contract"
            )
        }
        _ => bail!("unsupported architecture: {value:?}"),
    }
}

#[derive(Clone, Debug)]
pub struct TargetChoice {
    pub key: String,
    pub os: String,
    pub arch: String,
    pub abi: Option<String>,
    pub selected: bool,
    pub available: bool,
    pub reason: Option<String>,
    pub builders: Vec<&'static str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductScope {
    pub product: String,
    pub builder: &'static str,
    pub explicit: bool,
    pub targets: Vec<String>,
    pub compatible_targets: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductSelection {
    pub product: String,
    pub targets: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductChange {
    pub product: String,
    pub old_targets: Vec<String>,
    pub new_targets: Vec<String>,
    pub old_explicit: bool,
    pub new_explicit: bool,
}

#[derive(Clone, Debug)]
enum Parsed {
    V1(model::Config),
    V2(v2::model::Config),
    V3(crate::delivery::model::Config),
}

fn parse(text: &str) -> Result<Parsed> {
    let header: toml::Value = toml::from_str(text).context("parse release.toml")?;
    match header.get("schema").and_then(toml::Value::as_integer) {
        Some(1) => {
            let value: model::Config =
                toml::from_str(text).context("parse schema 1 release.toml")?;
            config::validate(&value)?;
            Ok(Parsed::V1(value))
        }
        Some(2) => {
            let value: v2::model::Config =
                toml::from_str(text).context("parse schema 2 release.toml")?;
            v2::contract::validate(&value)?;
            Ok(Parsed::V2(value))
        }
        Some(3) => {
            let value: crate::delivery::model::Config = toml::from_str(text)?;
            crate::delivery::config::validate(&value)?;
            Ok(Parsed::V3(value))
        }
        _ => bail!("unsupported release.toml schema; expected 1, 2 or 3"),
    }
}

pub struct Snapshot {
    path: PathBuf,
    root_metadata: Metadata,
    original: String,
    metadata: Metadata,
}

impl Snapshot {
    pub fn load(root: &Path) -> Result<Self> {
        let root = absolute_safe_root(root)?;
        let root_metadata = fs::metadata(&root)?;
        let path = root.join("release.toml");
        let (original, metadata) = read_regular(&path)?;
        let snapshot = Self {
            path,
            root_metadata,
            original,
            metadata,
        };
        snapshot.unchanged()?;
        Ok(snapshot)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn text(&self) -> &str {
        &self.original
    }

    pub fn save<F>(&self, proposed: &str, mut validate: F) -> Result<()>
    where
        F: FnMut(&str) -> Result<()>,
    {
        validate(proposed).context("validate settings before saving")?;
        self.unchanged()?;
        if proposed == self.original {
            return Ok(());
        }

        let parent = self.path.parent().context("release.toml has no parent")?;
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).context("generate temporary settings filename")?;
        let nonce: String = random.iter().map(|v| format!("{v:02x}")).collect();
        let temporary = parent.join(format!(".release.toml.relship-{nonce}.tmp"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        nofollow(&mut options);
        let mut file = options
            .open(&temporary)
            .context("create temporary settings file")?;
        let result = (|| {
            file.set_permissions(self.metadata.permissions())?;
            file.write_all(proposed.as_bytes())?;
            file.sync_all()?;
            let (candidate, metadata) = read_regular(&temporary)?;
            ensure!(
                candidate == proposed && same_snapshot(&metadata, &file.metadata()?),
                "temporary settings changed while saving"
            );
            validate(&candidate).context("validate temporary settings")?;
            // Recheck after preparing the replacement, immediately before the commit.
            self.unchanged()?;
            fs::rename(&temporary, &self.path).context("replace release.toml")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn unchanged(&self) -> Result<()> {
        let parent = self.path.parent().context("release.toml has no parent")?;
        ensure!(
            absolute_safe_root(parent)? == parent,
            "settings directory changed"
        );
        ensure!(
            same_identity(&self.root_metadata, &fs::metadata(parent)?),
            "settings directory changed on disk; reload settings before saving"
        );
        let (text, metadata) = read_regular(&self.path)?;
        ensure!(
            text == self.original && same_snapshot(&metadata, &self.metadata),
            "release.toml changed on disk; reload settings before saving"
        );
        Ok(())
    }
}

pub struct Document {
    snapshot: Snapshot,
    parsed: Parsed,
    editable: DocumentMut,
}

#[derive(Clone, Debug)]
pub struct Proposal {
    path: PathBuf,
    old_text: String,
    new_text: String,
    product_changes: Vec<ProductChange>,
}

impl Proposal {
    pub fn old_text(&self) -> &str {
        &self.old_text
    }
    pub fn new_text(&self) -> &str {
        &self.new_text
    }
    pub fn product_changes(&self) -> &[ProductChange] {
        &self.product_changes
    }
    pub fn changed(&self) -> bool {
        self.old_text != self.new_text
    }
}

impl Document {
    pub fn load(root: &Path) -> Result<Self> {
        let snapshot = Snapshot::load(root)?;
        let parsed = parse(snapshot.text())?;
        let editable = snapshot
            .text()
            .parse()
            .context("parse editable release.toml")?;
        Ok(Self {
            snapshot,
            parsed,
            editable,
        })
    }

    pub fn path(&self) -> &Path {
        self.snapshot.path()
    }

    pub fn schema(&self) -> u32 {
        match self.parsed {
            Parsed::V1(_) => 1,
            Parsed::V2(_) => 2,
            Parsed::V3(_) => 3,
        }
    }

    pub fn current_targets(&self) -> Vec<String> {
        match &self.parsed {
            Parsed::V1(c) => c.targets.clone(),
            Parsed::V2(c) => c.targets.iter().map(v2::model::Target::key).collect(),
            Parsed::V3(c) => c.targets.iter().map(v2::model::Target::key).collect(),
        }
    }

    fn base_config(&self) -> Option<v2::model::Config> {
        match &self.parsed {
            Parsed::V1(_) => None,
            Parsed::V2(config) => Some(config.clone()),
            Parsed::V3(config) => Some(crate::delivery::config::base_config(config)),
        }
    }

    pub fn text(&self) -> &str {
        self.snapshot.text()
    }

    /// Bind an explicitly reviewed migration or packaging edit to this snapshot.
    pub fn proposal_text(&self, new_text: String) -> Result<Proposal> {
        parse(&new_text).context("validate proposed release.toml")?;
        Ok(Proposal {
            path: self.snapshot.path().to_path_buf(),
            old_text: self.snapshot.text().to_owned(),
            new_text,
            product_changes: Vec::new(),
        })
    }

    pub fn product_scopes(&self) -> Vec<ProductScope> {
        let choices = self.target_choices();
        let base = self.base_config();
        match &self.parsed {
            Parsed::V1(c) => c
                .products
                .iter()
                .map(|p| ProductScope {
                    product: p.package.clone(),
                    builder: "rust",
                    explicit: false,
                    targets: c.targets.clone(),
                    compatible_targets: choices
                        .iter()
                        .filter(|t| t.builders.contains(&"rust"))
                        .map(|t| t.key.clone())
                        .collect(),
                })
                .collect(),
            Parsed::V2(_) | Parsed::V3(_) => {
                let c = base.as_ref().expect("schema 2/3 base config");
                c.products
                    .iter()
                    .map(|p| ProductScope {
                        product: p.id.clone(),
                        builder: p.build.name(),
                        explicit: !p.targets.is_empty(),
                        targets: if p.targets.is_empty() {
                            c.targets.iter().map(v2::model::Target::key).collect()
                        } else {
                            p.targets.clone()
                        },
                        compatible_targets: choices
                            .iter()
                            .filter(|t| t.builders.contains(&p.build.name()))
                            .map(|t| t.key.clone())
                            .collect(),
                    })
                    .collect()
            }
        }
    }

    pub fn target_choices(&self) -> Vec<TargetChoice> {
        let selected = self.current_targets();
        let (rust, go) = match &self.parsed {
            Parsed::V1(_) => (true, false),
            Parsed::V2(c) => (
                c.products.iter().any(|p| p.build.name() == "rust"),
                c.products.iter().any(|p| p.build.name() == "go"),
            ),
            Parsed::V3(c) => (
                c.products.iter().any(|p| p.build.name() == "rust"),
                c.products.iter().any(|p| p.build.name() == "go"),
            ),
        };
        let mut result = Vec::new();
        for os in ["linux", "windows", "macos"] {
            for arch in ["x86_64", "aarch64"] {
                let abis: &[Option<&str>] = match (self.schema(), os) {
                    (1, "linux") => &[Some("gnu"), Some("musl")],
                    (1, "windows") => &[Some("msvc")],
                    (_, "linux") => &[Some("gnu"), Some("musl"), None],
                    (_, "windows") => &[Some("msvc"), None],
                    _ => &[None],
                };
                for abi in abis {
                    let target = v2::model::Target {
                        os: os.into(),
                        arch: arch.into(),
                        abi: abi.map(str::to_owned),
                    };
                    let key = if self.schema() == 1 {
                        rust_triple(&target).expect("catalog contains Rust targets")
                    } else {
                        target.key()
                    };
                    let mut builders = Vec::new();
                    if rust && (os == "macos" || abi.is_some()) {
                        builders.push("rust");
                    }
                    if go && abi.is_none() {
                        builders.push("go");
                    }
                    let available = !builders.is_empty();
                    result.push(TargetChoice {
                        selected: selected.contains(&key),
                        key,
                        os: os.into(),
                        arch: arch.into(),
                        abi: abi.map(str::to_owned),
                        available,
                        reason: (!available).then(|| {
                            "No configured product builder supports this target/ABI.".into()
                        }),
                        builders,
                    });
                }
            }
        }
        result
    }

    pub fn proposal(&self, selected: &[String]) -> Result<Proposal> {
        self.proposal_with_scopes(selected, &[])
    }

    pub fn proposal_with_scopes(
        &self,
        selected: &[String],
        scopes: &[ProductSelection],
    ) -> Result<Proposal> {
        ensure!(!selected.is_empty(), "select at least one target");
        ensure!(
            self.schema() >= 2 || scopes.is_empty(),
            "schema 1 shares global targets across all products"
        );
        let mut seen = BTreeSet::new();
        let products = self.product_scopes();
        for scope in scopes {
            ensure!(
                seen.insert(&scope.product),
                "duplicate product scope: {}",
                scope.product
            );
            ensure!(
                products.iter().any(|p| p.product == scope.product),
                "unknown product scope: {}",
                scope.product
            );
        }
        let mut keys = Vec::new();
        for input in selected {
            let key = normalize_target(input, self.schema())?;
            if !keys.contains(&key) {
                keys.push(key);
            }
        }
        let choices = self.target_choices();
        for key in &keys {
            ensure!(
                choices.iter().any(|c| c.key == *key && c.available),
                "no configured builder supports target: {key}"
            );
        }
        let mut editable = self.editable.clone();
        let mut product_changes = Vec::new();
        let base = self.base_config();
        match &self.parsed {
            Parsed::V1(_) => {
                update_string_array(
                    editable.get_mut("targets").context("missing targets")?,
                    &keys,
                )?;
            }
            Parsed::V2(_) | Parsed::V3(_) => {
                let c = base.as_ref().context("missing schema 2/3 base config")?;
                let keep: BTreeSet<_> = keys.iter().cloned().collect();
                update_targets(
                    editable.get_mut("targets").context("missing targets")?,
                    &keys,
                )?;
                for (index, product) in c.products.iter().enumerate() {
                    let requested = scopes.iter().find(|s| s.product == product.id);
                    let remaining = match requested {
                        Some(ProductSelection {
                            targets: Some(targets),
                            ..
                        }) => {
                            ensure!(
                                !targets.is_empty(),
                                "explicit product scope must select at least one target: {}",
                                product.id
                            );
                            let mut normalized = Vec::new();
                            for target in targets {
                                let key = normalize_target(target, self.schema())?;
                                ensure!(
                                    keep.contains(&key),
                                    "product {} selects a target outside global selection: {key}",
                                    product.id
                                );
                                if !normalized.contains(&key) {
                                    normalized.push(key);
                                }
                            }
                            normalized
                        }
                        Some(ProductSelection { targets: None, .. }) => Vec::new(),
                        None if product.targets.is_empty() => Vec::new(),
                        None => {
                            let remaining: Vec<_> = product
                                .targets
                                .iter()
                                .filter(|key| keep.contains(*key))
                                .cloned()
                                .collect();
                            ensure!(
                                !remaining.is_empty(),
                                "product {} would have no selected targets; retain one of its explicit targets or edit its scope deliberately",
                                product.id
                            );
                            remaining
                        }
                    };
                    if remaining != product.targets {
                        let table = product_table_mut(&mut editable, index)?;
                        if remaining.is_empty() {
                            table.remove("targets");
                        } else if let Some(item) = table.get_mut("targets") {
                            update_string_array(item, &remaining)?;
                        } else {
                            let array: toml_edit::Array = remaining
                                .iter()
                                .map(|key| Value::from(key.as_str()))
                                .collect();
                            table.insert("targets", Item::Value(Value::Array(array)));
                        }
                        product_changes.push(ProductChange {
                            product: product.id.clone(),
                            old_targets: product.targets.clone(),
                            old_explicit: !product.targets.is_empty(),
                            new_explicit: !remaining.is_empty(),
                            new_targets: remaining,
                        });
                    }
                }
            }
        }
        let new_text = editable.to_string();
        parse(&new_text).context("validate proposed release.toml")?;
        Ok(Proposal {
            path: self.snapshot.path().to_path_buf(),
            old_text: self.snapshot.text().to_owned(),
            new_text,
            product_changes,
        })
    }

    pub fn save(&self, proposal: &Proposal) -> Result<()> {
        ensure!(
            proposal.path == self.snapshot.path() && proposal.old_text == self.snapshot.text(),
            "proposal belongs to a different settings snapshot"
        );
        self.snapshot
            .save(&proposal.new_text, |candidate| parse(candidate).map(|_| ()))
    }
}

fn rust_triple(target: &v2::model::Target) -> Result<String> {
    let suffix = match (target.os.as_str(), target.abi.as_deref()) {
        ("linux", Some("gnu")) => "unknown-linux-gnu",
        ("linux", Some("musl")) => "unknown-linux-musl",
        ("windows", Some("msvc")) => "pc-windows-msvc",
        ("macos", None) => "apple-darwin",
        _ => bail!("unsupported Rust target: {}", target.key()),
    };
    Ok(format!("{}-{suffix}", target.arch))
}

fn normalize_target(input: &str, schema: u32) -> Result<String> {
    let input = input.to_ascii_lowercase();
    if schema == 1 {
        for suffix in [
            "-unknown-linux-gnu",
            "-unknown-linux-musl",
            "-pc-windows-msvc",
            "-apple-darwin",
        ] {
            if let Some(arch) = input.strip_suffix(suffix) {
                return Ok(format!("{}{suffix}", normalize_arch(arch)?));
            }
        }
        bail!("unsupported schema 1 target: {input}");
    }
    let mut parts = input.split('-');
    let os = parts.next().context("missing target OS")?;
    let arch = normalize_arch(parts.next().context("missing target architecture")?)?;
    let abi = parts.next();
    ensure!(parts.next().is_none(), "invalid target: {input}");
    ensure!(
        matches!(os, "linux" | "windows" | "macos"),
        "unsupported target OS: {os}"
    );
    Ok(v2::model::Target {
        os: os.into(),
        arch: arch.into(),
        abi: abi.map(str::to_owned),
    }
    .key())
}

fn target_from_key(key: &str) -> v2::model::Target {
    let mut parts = key.split('-');
    v2::model::Target {
        os: parts.next().expect("normalized OS").into(),
        arch: parts.next().expect("normalized architecture").into(),
        abi: parts.next().map(str::to_owned),
    }
}

fn update_string_array(item: &mut Item, keys: &[String]) -> Result<()> {
    let array = item.as_array_mut().context("targets must be an array")?;
    array.retain(|v| v.as_str().is_some_and(|s| keys.iter().any(|key| key == s)));
    for key in keys {
        if !array.iter().any(|v| v.as_str() == Some(key)) {
            array.push(key.as_str());
        }
    }
    Ok(())
}

fn update_targets(item: &mut Item, keys: &[String]) -> Result<()> {
    match item {
        Item::ArrayOfTables(tables) => {
            tables.retain(|table| table_target_key(table).is_some_and(|key| keys.contains(&key)));
            for key in keys {
                if !tables
                    .iter()
                    .any(|table| table_target_key(table).as_ref() == Some(key))
                {
                    let target = target_from_key(key);
                    let mut table = Table::new();
                    table.insert("os", toml_edit::value(target.os));
                    table.insert("arch", toml_edit::value(target.arch));
                    if let Some(abi) = target.abi {
                        table.insert("abi", toml_edit::value(abi));
                    }
                    tables.push(table);
                }
            }
        }
        Item::Value(Value::Array(array)) => {
            array.retain(|value| {
                value
                    .as_inline_table()
                    .and_then(|table| table_target_key(table))
                    .is_some_and(|key| keys.contains(&key))
            });
            for key in keys {
                if !array.iter().any(|value| {
                    value
                        .as_inline_table()
                        .and_then(|table| table_target_key(table))
                        .as_ref()
                        == Some(key)
                }) {
                    let target = target_from_key(key);
                    let mut table = InlineTable::new();
                    table.insert("os", target.os.into());
                    table.insert("arch", target.arch.into());
                    if let Some(abi) = target.abi {
                        table.insert("abi", abi.into());
                    }
                    table.fmt();
                    array.push(Value::InlineTable(table));
                }
            }
        }
        _ => bail!("targets must be an array of target tables"),
    }
    Ok(())
}

fn table_target_key(table: &dyn TableLike) -> Option<String> {
    Some(
        v2::model::Target {
            os: table.get("os")?.as_str()?.into(),
            arch: table.get("arch")?.as_str()?.into(),
            abi: table.get("abi").and_then(Item::as_str).map(str::to_owned),
        }
        .key(),
    )
}

fn product_table_mut(document: &mut DocumentMut, index: usize) -> Result<&mut dyn TableLike> {
    let item = document.get_mut("products").context("missing products")?;
    match item {
        Item::ArrayOfTables(tables) => {
            Ok(tables.get_mut(index).context("missing product table")?)
        }
        Item::Value(Value::Array(array)) => Ok(array
            .get_mut(index)
            .and_then(Value::as_inline_table_mut)
            .context("missing inline product table")?),
        _ => bail!("products must be an array of product tables"),
    }
}

fn absolute_safe_root(root: &Path) -> Result<PathBuf> {
    let absolute = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()?.join(root)
    };
    let mut checked = PathBuf::new();
    for component in absolute.components() {
        ensure!(
            !matches!(component, Component::ParentDir),
            "settings path must not contain '..'"
        );
        if component == Component::CurDir {
            continue;
        }
        checked.push(component);
        let metadata = fs::symlink_metadata(&checked)
            .with_context(|| format!("inspect settings path {}", checked.display()))?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "symlink settings path: {}",
            checked.display()
        );
        ensure!(
            metadata.is_dir(),
            "settings path is not a directory: {}",
            checked.display()
        );
    }
    Ok(checked)
}

fn nofollow(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = options;
}

fn read_regular(path: &Path) -> Result<(String, Metadata)> {
    let before = fs::symlink_metadata(path).context("inspect release.toml")?;
    ensure!(
        !before.file_type().is_symlink(),
        "release.toml must not be a symlink"
    );
    ensure!(before.is_file(), "release.toml must be a regular file");
    let mut options = OpenOptions::new();
    options.read(true);
    nofollow(&mut options);
    let mut file: File = options.open(path).context("open release.toml")?;
    let metadata = file.metadata()?;
    ensure!(
        same_snapshot(&before, &metadata),
        "release.toml changed while opening"
    );
    let mut text = String::new();
    file.read_to_string(&mut text)
        .context("read release.toml")?;
    ensure!(
        same_snapshot(&metadata, &file.metadata()?),
        "release.toml changed while reading"
    );
    Ok((text, metadata))
}

fn same_snapshot(a: &Metadata, b: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.mode() == b.mode()
            && a.len() == b.len()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        a.len() == b.len()
            && a.modified().ok() == b.modified().ok()
            && a.created().ok() == b.created().ok()
            && a.permissions().readonly() == b.permissions().readonly()
    }
}

fn same_identity(a: &Metadata, b: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(not(unix))]
    {
        a.created().ok() == b.created().ok()
    }
}
