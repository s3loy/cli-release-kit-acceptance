//! Checkpointed execution. Compilers never receive a signing key.
use super::sdk_progress::Progress;
use super::{model::*, plan};
use crate::{
    cohort::{self, io},
    compatibility::*,
    delivery::{
        self,
        model::{PayloadEntry, PayloadManifest},
    },
    process, source,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

fn private(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn env_tools(p: &Profile) -> &[ToolInput] {
    match &p.environment {
        Environment::LinuxContainer { tools, .. } | Environment::NativeSdk { tools, .. } => tools,
    }
}
fn save(out: &Path, r: &Receipt) -> Result<()> {
    io::write_json_atomic(&out.join("receipt.json"), r)
}
pub fn status(out: &Path) -> Result<Receipt> {
    let r: Receipt = io::read_json(&out.join("receipt.json"))?;
    ensure!(
        r.schema == SCHEMA && !r.publication_ready,
        "invalid qualified receipt"
    );
    Ok(r)
}
fn image(pin: &ImagePin, logs: &Path) -> Result<(HostIdentity, ContainerImageObservation)> {
    ensure!(
        std::env::consts::OS == "linux",
        "container baseline execution requires a native Linux worker"
    );
    let mut c = process::Commands::new(logs, &logs.join("image-logs"), 300)?;
    let info = c.run(
        &[
            "docker".into(),
            "info".into(),
            "--format".into(),
            "{{.OSType}} {{.Architecture}}".into(),
        ],
        "daemon",
        &BTreeMap::new(),
    )?;
    let parts = info.split_whitespace().collect::<Vec<_>>();
    ensure!(parts.len() == 2, "invalid Docker daemon observation");
    let host = HostIdentity {
        os: std::env::consts::OS.into(),
        arch: Architecture::parse(std::env::consts::ARCH)?,
        daemon_os: parts[0].into(),
        daemon_arch: Architecture::parse(parts[1])?,
    };
    ensure!(
        host.arch.platform() == pin.platform && host.arch == host.daemon_arch,
        "native host/daemon differs from planned image; emulation is forbidden"
    );
    c.run(
        &["docker".into(), "pull".into(), pin.reference.clone()],
        "pull",
        &BTreeMap::new(),
    )?;
    let value = c.run(
        &[
            "docker".into(),
            "image".into(),
            "inspect".into(),
            pin.reference.clone(),
        ],
        "inspect",
        &BTreeMap::new(),
    )?;
    Ok((
        host,
        ContainerImageObservation::from_docker_inspect(&value, pin)?,
    ))
}
/// SDK directory links are identities, not a reason to follow aliases outside a root.
pub fn sdk_tree(root: &Path) -> Result<String> {
    fn walk(
        root: &Path,
        at: &Path,
        entries: &mut BTreeMap<String, (String, String)>,
        progress: &mut Progress,
    ) -> Result<()> {
        let mut children = fs::read_dir(at)?.collect::<std::io::Result<Vec<_>>>()?;
        children.sort_by_key(|e| e.file_name());
        for e in children {
            let p = e.path();
            let m = fs::symlink_metadata(&p)?;
            let name = p
                .strip_prefix(root)?
                .to_str()
                .context("non-UTF8 SDK path")?
                .replace('\\', "/");
            ensure!(entries.len() < 300_000, "SDK inventory exceeds bound");
            if m.file_type().is_symlink() {
                entries.insert(
                    name,
                    (
                        "link".into(),
                        source::digest(fs::read_link(&p)?.to_string_lossy().as_bytes()),
                    ),
                );
            } else if m.is_dir() {
                walk(root, &p, entries, progress)?;
            } else {
                ensure!(m.is_file(), "SDK contains a special file");
                entries.insert(name, ("file".into(), source::file_digest(&p)?));
            }
            progress.visit(&p, &m);
        }
        Ok(())
    }
    ensure!(root.is_absolute(), "SDK input must be an absolute path");
    let mut progress = Progress::new(root, "inventory");
    if root.is_file() {
        let result = plan::content_id(b"relship/native-sdk-file/v1\0", &source::file_digest(root)?);
        progress.visit(root, &fs::metadata(root)?);
        progress.finish();
        return result;
    }
    ensure!(
        root.is_dir(),
        "SDK input must be a regular file or directory"
    );
    let mut entries = BTreeMap::new();
    walk(root, root, &mut entries, &mut progress)?;
    let result = plan::content_id(b"relship/native-sdk-tree/v1\0", &entries);
    progress.finish();
    result
}
pub fn inspect_sdk(
    id: &str,
    version: &str,
    roots: &[PathBuf],
    tools: &[PathBuf],
) -> Result<NativeSdkExpectation> {
    let roots = roots
        .iter()
        .map(|p| Ok((portable_path(&p.canonicalize()?), sdk_tree(p)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    validate_sdk_links(&roots)?;
    let tool_sha256 = tools
        .iter()
        .map(|p| Ok((portable_path(&p.canonicalize()?), source::file_digest(p)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut environment: BTreeMap<String, String> = process::environment()
        .into_iter()
        .filter(|(k, _)| {
            matches!(
                k.as_str(),
                "PATH"
                    | "SDKROOT"
                    | "DEVELOPER_DIR"
                    | "MACOSX_DEPLOYMENT_TARGET"
                    | "CC"
                    | "AR"
                    | "LD"
            )
        })
        .chain(
            ["INCLUDE", "LIB", "LIBPATH"]
                .into_iter()
                .filter_map(|k| std::env::var(k).ok().map(|v| (k.into(), v))),
        )
        .collect();
    if std::env::consts::OS == "macos" && !environment.contains_key("SDKROOT") {
        let sdkroots = roots
            .keys()
            .filter(|p| p.ends_with(".sdk"))
            .collect::<Vec<_>>();
        if sdkroots.len() == 1 {
            environment.insert("SDKROOT".into(), sdkroots[0].clone());
        }
    }
    let result = NativeSdkExpectation {
        sdk_id: id.into(),
        sdk_version: version.into(),
        sdk_content_sha256: NativeSdkExpectation::roots_digest(&roots)?,
        roots,
        tool_sha256,
        environment,
    };
    result.validate()?;
    Ok(result)
}
fn native_sdk(
    sdk: &NativeSdkExpectation,
    p: &Profile,
    logs: &Path,
) -> Result<NativeSdkObservation> {
    let mut roots = BTreeMap::new();
    for path in sdk.roots.keys() {
        roots.insert(path.clone(), sdk_tree(Path::new(path))?);
    }
    validate_sdk_links(&roots)?;
    let mut tools = BTreeMap::new();
    let mut versions = BTreeMap::new();
    let mut runner = process::Commands::new(logs, &logs.join("sdk-logs"), 60)?;
    for (i, path) in sdk.tool_sha256.keys().enumerate() {
        let sha = source::file_digest(Path::new(path))?;
        ensure!(
            sdk.tool_sha256.get(path) == Some(&sha),
            "native SDK tool bytes changed before version probe"
        );
        tools.insert(path.clone(), sha);
        let name = Path::new(path)
            .file_name()
            .and_then(|x| x.to_str())
            .unwrap_or("");
        if p.os == "macos" && name == "ar" {
            versions.insert(
                path.clone(),
                "Version query unavailable for Apple ar; executable SHA256 verified before use"
                    .into(),
            );
            continue;
        }
        let flag = if matches!(name, "go" | "go.exe") {
            "version"
        } else if matches!(name, "cargo" | "cargo.exe" | "rustc" | "rustc.exe") {
            "--version"
        } else if p.os == "windows"
            && matches!(
                name,
                "cl.exe" | "link.exe" | "lib.exe" | "rc.exe" | "mt.exe" | "nmake.exe"
            )
        {
            "/?"
        } else if p.os == "macos" && name == "ld" {
            "-version_details"
        } else {
            "--version"
        };
        versions.insert(
            path.clone(),
            runner.run_exact(&[path.clone(), flag.into()], &format!("tool-{i}"), &{
                let mut e = runtime_environment();
                e.extend(sdk.environment.clone());
                e
            })?,
        );
    }
    for name in ["INCLUDE", "LIB", "LIBPATH", "SDKROOT"] {
        if let Some(value) = sdk.environment.get(name) {
            for path in value.split(if p.os == "windows" { ';' } else { ':' }) {
                if path.is_empty() {
                    continue;
                }
                ensure!(
                    sdk.roots.keys().any(|r| fs::canonicalize(path)
                        .and_then(|p| fs::canonicalize(r).map(|root| p.starts_with(root)))
                        .unwrap_or(false)),
                    "{name} references a path outside the pinned SDK roots"
                );
            }
        }
    }
    let observed = NativeSdkObservation {
        sdk_id: sdk.sdk_id.clone(),
        sdk_version: sdk.sdk_version.clone(),
        sdk_content_sha256: NativeSdkExpectation::roots_digest(&roots)?,
        roots,
        environment: sdk.environment.clone(),
        tool_sha256: tools,
        tool_versions: versions,
        host_os: std::env::consts::OS.into(),
        host_arch: Architecture::parse(std::env::consts::ARCH)?,
    };
    sdk.verify(&observed, &p.os, p.arch)?;
    io::write_json_atomic(&logs.join("native-sdk.json"), &observed)?;
    Ok(observed)
}
struct Driver<'a> {
    source: PathBuf,
    work: PathBuf,
    payload: PathBuf,
    owned: PathBuf,
    inputs: BTreeMap<String, PathBuf>,
    container: Option<(ImagePin, HostIdentity, ContainerImageObservation)>,
    env: BTreeMap<String, String>,
    timeout: u64,
    logs: PathBuf,
    product: &'a Product,
    context: BTreeMap<String, String>,
}
impl Driver<'_> {
    fn text(&self, value: &str) -> String {
        let guest = self.container.is_some();
        let project = if guest {
            PathBuf::from("/source")
        } else {
            self.source.clone()
        };
        let product = if self.product.directory == "." {
            project.clone()
        } else {
            project.join(&self.product.directory)
        };
        let work = if guest {
            PathBuf::from("/work")
        } else {
            self.work.clone()
        };
        let payload = if guest {
            PathBuf::from("/payload")
        } else {
            self.payload.clone()
        };
        let mut s = value.to_owned();
        for (name, replacement) in &self.context {
            s = s.replace(&format!("{{{name}}}"), replacement);
        }
        let mut s = s
            .replace("{project}", &project.to_string_lossy())
            .replace("{product}", &product.to_string_lossy())
            .replace("{work}", &work.to_string_lossy())
            .replace("{archive}", &payload.to_string_lossy())
            .replace(
                "{binary}",
                &payload
                    .join(format!(
                        "{}{}",
                        self.product.binaries[0],
                        if std::env::consts::OS == "windows" {
                            ".exe"
                        } else {
                            ""
                        }
                    ))
                    .to_string_lossy(),
            );
        for (name, path) in &self.inputs {
            s = s.replace(
                &format!("{{input:{name}}}"),
                &if guest {
                    format!("/inputs/{name}")
                } else {
                    path.to_string_lossy().into_owned()
                },
            );
        }
        s
    }
    fn run(
        &self,
        args: &[String],
        label: &str,
        extra: &BTreeMap<String, String>,
    ) -> Result<String> {
        let args = args.iter().map(|s| self.text(s)).collect::<Vec<_>>();
        let mut env = self
            .env
            .iter()
            .map(|(k, v)| (k.clone(), self.text(v)))
            .collect::<BTreeMap<_, _>>();
        for (name, path) in &self.inputs {
            env.insert(
                format!("KIT_INPUT_{}", name.to_ascii_uppercase().replace('-', "_")),
                if self.container.is_some() {
                    format!("/inputs/{name}")
                } else {
                    path.to_string_lossy().into_owned()
                },
            );
        }
        env.extend(extra.iter().map(|(k, v)| (k.clone(), self.text(v))));
        env.extend([
            ("KIT_PROJECT_DIR".into(), self.text("{project}")),
            ("KIT_PRODUCT_DIR".into(), self.text("{product}")),
            ("KIT_ARCHIVE_DIR".into(), self.text("{archive}")),
            ("KIT_BINARY".into(), self.text("{binary}")),
        ]);
        let cwd = if self.container.is_none() {
            self.source.join(&self.product.directory)
        } else {
            self.source.clone()
        };
        let mut commands = process::Commands::new(&cwd, &self.logs, self.timeout)?;
        if let Some((image, host, observed)) = &self.container {
            let mut argv = vec!["env".into()];
            argv.extend(env.into_iter().map(|(k, v)| format!("{k}={v}")));
            argv.extend(args);
            #[cfg(unix)]
            let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
            #[cfg(not(unix))]
            let (uid, gid) = (1, 1);
            let req = ContainerRequest {
                image: image.clone(),
                arch: host.arch,
                source: self.source.clone(),
                owned_root: self.owned.clone(),
                work: self.work.clone(),
                output: self.payload.clone(),
                inputs: self
                    .inputs
                    .iter()
                    .map(|(name, path)| ReadOnlyMount {
                        source: path.clone(),
                        destination: format!("/inputs/{name}"),
                    })
                    .collect(),
                uid,
                gid,
                memory_mib: 4096,
                cpus: 2,
                pids_limit: 512,
                argv,
            };
            req.run(&mut commands, label, host, observed)
        } else {
            for name in ["SYSTEMROOT", "COMSPEC", "PATHEXT", "TEMP", "TMP", "TMPDIR"] {
                if let Ok(value) = std::env::var(name) {
                    env.entry(name.into()).or_insert(value);
                }
            }
            commands.run_exact(&args, label, &env)
        }
    }
}
fn bootstrap(driver: &mut Driver<'_>, kind: &str, native_program: Option<&str>) -> Result<()> {
    if let Some((_, container_host, _)) = &driver.container {
        let container_arch = container_host.arch;
        driver.env.insert("PATH".into(),"/work/sdk/bin:/inputs/go/bin:/inputs/cmake/bin:/opt/rh/devtoolset-10/root/usr/bin:/usr/local/bin:/usr/bin:/bin".into());
        driver.env.insert("LD_LIBRARY_PATH".into(),"/opt/rh/devtoolset-10/root/usr/lib64:/opt/rh/devtoolset-10/root/usr/lib:/usr/local/lib64".into());
        if kind != "go" {
            let arch = container_arch;
            for (i, mut command) in crate::compatibility::perl::bootstrap_commands(arch)?
                .into_iter()
                .enumerate()
            {
                command[0] = "/opt/python/cp311-cp311/bin/python3".into();
                driver.run(&command, &format!("perl-sdk-{i}"), &BTreeMap::new())?;
            }
            driver.env.extend(crate::compatibility::perl::environment());
        }
        if kind == "rust" {
            for name in ["rustc", "cargo", "rust-std"] {
                ensure!(
                    driver.inputs.contains_key(name),
                    "missing pinned Rust component {name}"
                );
                driver.run(
                    &[
                        "sh".into(),
                        format!("/inputs/{name}/install.sh"),
                        "--prefix=/work/sdk".into(),
                        "--disable-ldconfig".into(),
                    ],
                    &format!("install-{name}"),
                    &BTreeMap::new(),
                )?;
            }
            let registry = driver.source.parent().unwrap().join("registry");
            private(&registry)?;
            let cargo = driver.work.join("sdk/bin/cargo");
            let env = BTreeMap::from([
                ("CARGO_HOME".into(), registry.to_string_lossy().into_owned()),
                ("RUSTUP_TOOLCHAIN".into(), "1.96.0".into()),
            ]);
            let cwd = driver.source.join(&driver.product.directory);
            process::Commands::new(&cwd, &driver.logs, driver.timeout)?.run(
                &[
                    cargo.to_string_lossy().into_owned(),
                    "fetch".into(),
                    "--locked".into(),
                ],
                "fetch-locked",
                &env,
            )?;
            driver.inputs.insert("cargo-registry".into(), registry);
            driver.run(
                &[
                    "cp".into(),
                    "-R".into(),
                    "/inputs/cargo-registry".into(),
                    "/work/cargo-home".into(),
                ],
                "stage-registry",
                &BTreeMap::new(),
            )?;
            driver.env.extend([
                ("CARGO_HOME".into(), "/work/cargo-home".into()),
                ("CARGO_NET_OFFLINE".into(), "true".into()),
                ("RUSTC".into(), "/work/sdk/bin/rustc".into()),
            ]);
        }
    }
    if kind == "rust" && driver.container.is_none() {
        let cargo_home = driver.work.join("cargo-home");
        private(&cargo_home)?;
        driver.env.insert(
            "CARGO_HOME".into(),
            cargo_home.to_string_lossy().into_owned(),
        );
        driver.run(
            &[
                native_program
                    .context("missing pinned native Cargo executable")?
                    .into(),
                "fetch".into(),
                "--locked".into(),
            ],
            "fetch-locked",
            &BTreeMap::new(),
        )?;
        driver.env.insert("CARGO_NET_OFFLINE".into(), "true".into());
    }
    if kind == "go" {
        let guest = driver.container.is_some();
        let modules = driver
            .source
            .parent()
            .context("source checkout lacks parent")?
            .join("go-modules");
        let cache = driver.work.join("go-cache");
        let gopath = driver.work.join("go-path");
        private(&modules)?;
        private(&cache)?;
        private(&gopath)?;
        let program = if guest {
            driver
                .inputs
                .get("go")
                .context("missing pinned Go archive")?
                .join("bin/go")
        } else {
            PathBuf::from(native_program.context("missing pinned native Go executable")?)
        };
        let goroot = program
            .parent()
            .and_then(Path::parent)
            .context("Go executable lacks SDK prefix")?;
        let mut env = if guest {
            runtime_environment()
        } else {
            driver
                .env
                .iter()
                .map(|(k, v)| (k.clone(), driver.text(v)))
                .collect()
        };
        env.extend([
            ("GOROOT".into(), goroot.to_string_lossy().into_owned()),
            ("GOTOOLCHAIN".into(), "local".into()),
            ("CGO_ENABLED".into(), "0".into()),
            ("GOMODCACHE".into(), modules.to_string_lossy().into_owned()),
            ("GOCACHE".into(), cache.to_string_lossy().into_owned()),
            ("GOPATH".into(), gopath.to_string_lossy().into_owned()),
            ("GOPROXY".into(), "https://proxy.golang.org".into()),
            ("GOSUMDB".into(), "sum.golang.org".into()),
        ]);
        process::Commands::new(
            &driver.source.join(&driver.product.directory),
            &driver.logs,
            driver.timeout,
        )?
        .run_exact(
            &[
                program.to_string_lossy().into_owned(),
                "mod".into(),
                "download".into(),
            ],
            "fetch-go-modules",
            &env,
        )?;
        driver.env.extend(env.into_iter().filter(|(k, _)| {
            matches!(
                k.as_str(),
                "GOROOT" | "GOTOOLCHAIN" | "CGO_ENABLED" | "GOMODCACHE" | "GOCACHE" | "GOPATH"
            )
        }));
        if guest {
            driver.inputs.insert("go-modules".into(), modules);
            driver.env.extend([
                ("GOROOT".into(), "/inputs/go".into()),
                ("GOMODCACHE".into(), "/inputs/go-modules".into()),
                ("GOCACHE".into(), "/work/go-cache".into()),
                ("GOPATH".into(), "/work/go-path".into()),
            ]);
        }
        driver.env.extend([
            ("GOPROXY".into(), "off".into()),
            ("GOSUMDB".into(), "off".into()),
        ]);
    }
    Ok(())
}
fn payload_manifest(path: &Path) -> Result<PayloadManifest> {
    let inventory = io::inventory(path)?;
    inventory
        .into_iter()
        .map(|(name, e)| {
            let meta = fs::symlink_metadata(crate::config::safe_join(path, &name)?)?;
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode() & 0o777
            };
            #[cfg(not(unix))]
            let mode = if name.ends_with(".exe") { 0o755 } else { 0o644 };
            let _ = meta;
            Ok((
                name,
                PayloadEntry {
                    size: e.size,
                    sha256: e.sha256,
                    mode,
                },
            ))
        })
        .collect()
}
fn stage(root: &Path, p: &Plan, bi: usize, out: &Path, inv: &Path) -> Result<PayloadRecord> {
    let b = &p.builds[bi];
    let product = &p.config.products[b.product];
    let descriptor = plan::descriptor(&b.target, &product.build)?;
    crate::v5::runtime::native_host(&descriptor)?;
    let checkout =
        cohort::run::clone_source_at(root, &p.source.commit, p.config.timeout_seconds, inv)?;
    ensure!(
        source::snapshot_plain(&checkout)? == p.source,
        "isolated checkout differs from source identity"
    );
    let owned = inv.join("owned");
    let work = owned.join("work");
    let payload = owned.join("payload");
    private(&work)?;
    private(&payload)?;
    let mut tools = env_tools(&b.profile).to_vec();
    tools.extend(product.inputs.clone());
    let inputs = acquire_tools(&tools, &out.join("inputs").join(&b.id))?;
    let environment;
    let container = match &b.profile.environment {
        Environment::LinuxContainer { image: pin, .. } => {
            let (h, o) = image(pin, inv)?;
            environment = EnvironmentObservation::Container {
                host: h.clone(),
                image: o.clone(),
            };
            Some((pin.clone(), h, o))
        }
        Environment::NativeSdk { sdk, .. } => {
            environment = EnvironmentObservation::NativeSdk {
                sdk: native_sdk(sdk, &b.profile, inv)?,
            };
            None
        }
    };
    let mut env = descriptor.compile_env.clone();
    if let Environment::NativeSdk { sdk, .. } = &b.profile.environment {
        env.extend(sdk.environment.clone());
    }
    env.insert("SOURCE_DATE_EPOCH".into(), p.source_epoch.to_string());
    env.insert("TZ".into(), "UTC".into());
    env.extend([
        ("KIT_TARGET".into(), b.target.clone()),
        ("KIT_VERSION".into(), p.resolved[b.product].version.clone()),
        ("KIT_PRODUCT".into(), product.id.clone()),
        ("KIT_GENERATED_DIR".into(), "{work}/generated".into()),
    ]);
    let native_toolchain = if let Environment::NativeSdk { sdk, .. } = &b.profile.environment {
        if matches!(product.build.name(), "rust" | "go") {
            let selection = super::toolchain::native_selection(
                sdk,
                product.build.name(),
                &descriptor.compiler_target,
            )?;
            super::toolchain::validate_native_filesystem(
                &selection,
                product.build.name(),
                &descriptor.compiler_target,
            )?;
            if let EnvironmentObservation::NativeSdk { sdk: observed } = &environment {
                for (path, _) in &selection.probes {
                    super::toolchain::validate_version(
                        path,
                        observed
                            .tool_versions
                            .get(path)
                            .context("missing compiler version observation")?,
                    )?;
                }
            }
            env.extend(selection.environment.clone());
            Some(selection)
        } else {
            None
        }
    } else {
        None
    };
    private(&work.join("generated"))?;

    let mut driver = Driver {
        source: checkout.clone(),
        work: work.clone(),
        payload: payload.clone(),
        owned,
        inputs,
        container,
        env,
        timeout: p.config.timeout_seconds,
        logs: inv.join("logs"),
        product,
        context: BTreeMap::new(),
    };
    bootstrap(
        &mut driver,
        product.build.name(),
        native_toolchain.as_ref().map(|t| t.program.as_str()),
    )?;
    ensure!(
        source::snapshot_plain(&checkout)? == p.source,
        "dependency preparation changed source or lockfiles; update the tracked inputs before creating a new plan"
    );
    for (i, h) in product.prepare.iter().enumerate() {
        driver.run(&h.command, &format!("prepare-{i}"), &h.env)?;
    }
    let mut cmake_inputs = None;
    let witness = match &b.recipe {
        Recipe::Cmake { spec } => {
            let build = work.join("build");
            private(&build)?;
            crate::cmake::write_query(&build)?;
            let source = if product.directory == "." {
                checkout.clone()
            } else {
                checkout.join(&product.directory)
            };
            let guestsource = if driver.container.is_some() {
                if product.directory == "." {
                    PathBuf::from("/source")
                } else {
                    PathBuf::from("/source").join(&product.directory)
                }
            } else {
                PathBuf::from(portable_path(&source))
            };
            let guestbuild = if driver.container.is_some() {
                PathBuf::from("/work/build")
            } else {
                PathBuf::from(portable_path(&build))
            };
            let mut args = vec![];
            if b.profile.os == "macos" {
                if let Environment::NativeSdk { sdk, .. } = &b.profile.environment {
                    let sysroot = sdk
                        .environment
                        .get("SDKROOT")
                        .context("macOS SDK profile must declare SDKROOT")?;
                    args.push(format!("-DCMAKE_OSX_SYSROOT={sysroot}"));
                }
                args.push(format!(
                    "-DCMAKE_OSX_ARCHITECTURES={}",
                    if b.profile.arch == Architecture::Aarch64 {
                        "arm64"
                    } else {
                        "x86_64"
                    }
                ));
                if let Some(v) = &b.profile.minimum_os {
                    args.push(format!("-DCMAKE_OSX_DEPLOYMENT_TARGET={v}"));
                }
            }
            if let Environment::NativeSdk { sdk, .. } = &b.profile.environment {
                let selected = crate::cmake::effective_generator(&source, spec)?;
                let generator = selected.as_deref().unwrap_or(if b.profile.os == "windows" {
                    "Ninja"
                } else {
                    "Unix Makefiles"
                });
                let (compiler, backend) = super::toolchain::native_cmake_tools(sdk, generator)?;
                args.push(format!("-DCMAKE_C_COMPILER={compiler}"));
                args.push(format!("-DCMAKE_MAKE_PROGRAM={backend}"));
                if selected.is_none() {
                    args.extend(["-G".into(), generator.into()]);
                }
            }
            if driver.container.is_some() {
                args.push("-DCMAKE_C_COMPILER=/opt/rh/devtoolset-10/root/usr/bin/gcc".into());
            }
            args.extend([
                "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF".into(),
                "-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF".into(),
            ]);
            if driver.container.is_none() {
                args.extend([
                    "-DCMAKE_FIND_USE_SYSTEM_ENVIRONMENT_PATH=OFF".into(),
                    "-DCMAKE_FIND_USE_CMAKE_ENVIRONMENT_PATH=OFF".into(),
                    "-DCMAKE_FIND_USE_CMAKE_SYSTEM_PATH=OFF".into(),
                    "-DCMAKE_FIND_USE_INSTALL_PREFIX=OFF".into(),
                ]);
            }
            if b.profile.os == "windows" {
                use crate::compatibility::windows_crt::WindowsRuntimeMode as Mode;
                let mode = b
                    .profile
                    .windows_runtime
                    .as_ref()
                    .context("missing Windows CRT policy")?
                    .mode;
                if mode != Mode::FollowProject {
                    args.push(format!(
                        "-DCMAKE_MSVC_RUNTIME_LIBRARY={}",
                        if mode == Mode::Static {
                            "MultiThreaded"
                        } else {
                            "MultiThreadedDLL"
                        }
                    ));
                    args.push("-DCMAKE_POLICY_DEFAULT_CMP0091=NEW".into());
                }
            }
            let cmake = driver
                .inputs
                .get("cmake")
                .context("missing pinned CMake input")?;
            let executable = if driver.container.is_some() {
                "/inputs/cmake/bin/cmake".into()
            } else if b.profile.os == "macos" {
                cmake
                    .join("CMake.app/Contents/bin/cmake")
                    .to_string_lossy()
                    .into_owned()
            } else {
                cmake.join("bin/cmake.exe").to_string_lossy().into_owned()
            };
            if b.profile.os == "macos" {
                driver.run(
                    &[
                        "/usr/bin/codesign".into(),
                        "--verify".into(),
                        "--strict".into(),
                        "--deep".into(),
                        cmake.join("CMake.app").to_string_lossy().into_owned(),
                    ],
                    "verify-cmake-bundle",
                    &BTreeMap::new(),
                )?;
            }
            let mut configure = crate::cmake::configure_argv_mapped(
                &source,
                &build,
                spec,
                &args,
                &guestsource,
                &guestbuild,
            )?;
            configure[0] = executable.clone();
            driver.run(&configure, "configure", &BTreeMap::new())?;
            let input_paths = driver
                .inputs
                .iter()
                .map(|(name, path)| {
                    (
                        name.clone(),
                        if driver.container.is_some() {
                            format!("/inputs/{name}")
                        } else {
                            portable_path(path)
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let allowed =
                super::cmake_boundary::roots(p, bi, &guestsource, &guestbuild, &input_paths)?;
            let search_dirs = cmake_search_dirs(&b.profile);
            let before = crate::cmake::validate_configured_inputs(
                &build,
                spec,
                &allowed,
                &b.profile.os,
                &search_dirs,
            )?;
            let mut buildargs = crate::cmake::build_argv(&guestbuild, spec);
            buildargs[0] = executable;
            driver.run(&buildargs, "build", &BTreeMap::new())?;
            let witness =
                crate::cmake::observe_mapped(&source, &build, spec, &guestsource, &guestbuild)?;
            let selection = crate::cmake::validate_configured_inputs(
                &build,
                spec,
                &allowed,
                &b.profile.os,
                &search_dirs,
            )?;
            ensure!(
                selection == before,
                "CMake resolved inputs changed during the build"
            );
            cmake_inputs = Some(super::cmake_boundary::CmakeBoundary {
                inputs: input_paths,
                selection,
            });
            let expected_cmake = env_tools(&b.profile)
                .iter()
                .find_map(|tool| {
                    if let ToolInput::Archive { name, version, .. } = tool {
                        (name == "cmake").then_some(version)
                    } else {
                        None
                    }
                })
                .context("missing CMake tool pin")?;
            ensure!(
                &witness.cmake_version == expected_cmake,
                "CMake version differs from pinned archive"
            );
            for toolchain in witness.toolchains.iter().filter(|t| t.language == "C") {
                let compiler = toolchain
                    .compiler
                    .get("path")
                    .and_then(|v| v.as_str())
                    .context("CMake did not identify its C compiler")?;
                if let Environment::NativeSdk { sdk, .. } = &b.profile.environment {
                    ensure!(
                        sdk.tool_sha256.contains_key(compiler),
                        "CMake selected a compiler outside the pinned native SDK tool set"
                    );
                } else {
                    ensure!(
                        compiler == "/opt/rh/devtoolset-10/root/usr/bin/gcc",
                        "CMake selected a compiler outside the pinned GNU profile"
                    );
                }
            }
            crate::cmake::stage_named(
                &build,
                &payload,
                &witness,
                &product
                    .binaries
                    .iter()
                    .map(|b| (b.clone(), descriptor.binary_name(b)))
                    .collect(),
            )?;
            let evidence = out.join(format!("evidence/cmake-{bi}"));
            crate::cmake::preserve_reply(&build, &evidence, &witness)?;
            Some(witness)
        }
        Recipe::Fixed { recipe } => {
            for (i, c) in recipe.commands.iter().enumerate() {
                let mut argv = c.argv.clone();
                let directory = if product.directory == "." {
                    "{project}".to_owned()
                } else {
                    format!("{{project}}/{}", product.directory)
                };
                // A fixed argv wrapper selects the source directory without shell parsing.
                if driver.container.is_some() {
                    argv.splice(
                        0..0,
                        [
                            "sh".into(),
                            "-c".into(),
                            "cd \"$1\"; shift; exec \"$@\"".into(),
                            "relship-build".into(),
                            directory,
                        ],
                    );
                }
                driver.run(&argv, &format!("build-{i}"), &c.env)?;
            }
            for binary in &recipe.binaries {
                let source_path =
                    PathBuf::from(binary.source.replace("{work}", &work.to_string_lossy()));
                crate::cohort::io::copy_file_checked(
                    &source_path,
                    &payload.join(&binary.path),
                    &crate::cohort::model::FileEntry {
                        size: fs::metadata(&source_path)?.len(),
                        sha256: source::file_digest(&source_path)?,
                    },
                )?;
                delivery::run::set_mode(&payload.join(&binary.path), 0o755)?;
            }
            None
        }
    };
    for asset in &product.assets {
        let path = if let Some(x) = asset.source.strip_prefix("input:") {
            let (name, relative) = x.split_once('/').context("invalid input asset")?;
            crate::config::safe_join(
                driver.inputs.get(name).context("unknown input asset")?,
                relative,
            )?
        } else {
            crate::config::safe_join(&checkout, &asset.source)?
        };
        let dest = crate::config::safe_join(&payload, &asset.path)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(path, &dest)?;
        delivery::run::set_mode(&dest, 0o644)?;
    }
    let mut observations = vec![];
    for binary in &product.binaries {
        let observation = observe_binary(
            &payload.join(descriptor.binary_name(binary)),
            &descriptor.os,
            b.profile.arch,
        )?;
        validate_observation(&observation, &b.profile)?;
        if descriptor.os == "linux" && product.build.name() == "go" {
            ensure!(
                observation.interpreter.is_none()
                    && observation.needed.is_empty()
                    && observation.required_versions.is_empty(),
                "pure Go product unexpectedly depends on a dynamic loader or libc"
            );
        }
        observations.push(observation);
    }
    let windows_runtime = if b.profile.os == "windows" {
        if let Environment::NativeSdk { sdk, .. } = &b.profile.environment {
            let policy = b
                .profile
                .windows_runtime
                .as_ref()
                .context("Windows runtime policy missing")?;
            let witness =
                crate::compatibility::windows_crt::stage(policy, sdk, &observations, &payload)?;
            for library in witness.libraries.values() {
                validate_observation(library, &b.profile)?;
            }
            Some(witness)
        } else {
            anyhow::bail!("Windows CRT delivery requires a native SDK")
        }
    } else {
        None
    };
    let files = payload_manifest(&payload)?;
    ensure!(
        source::snapshot_plain(&checkout)? == p.source,
        "build changed tracked source or left undeclared generated inputs"
    );
    let record = PayloadRecord {
        build_id: b.id.clone(),
        files,
        witness,
        cmake_inputs,
        observations,
        environment,
        windows_runtime,
    };
    let dest = out.join(format!("payloads/{bi}"));
    ensure!(!dest.exists(), "completed payload already exists");
    fs::rename(&payload, &dest)?;
    Ok(record)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationEvidence {
    spec: Validation,
    package_sha256: String,
    environment_id: String,
    observed_environment: EnvironmentObservation,
    logs: BTreeMap<String, cohort::model::FileEntry>,
    checks: usize,
}
fn version(output: &str, expected: &str) -> Result<()> {
    ensure!(
        output
            .split_whitespace()
            .any(|word| word == expected || word.strip_prefix('v') == Some(expected)),
        "application version output does not contain the planned version"
    );
    Ok(())
}
fn validate_package(
    root: &Path,
    p: &Plan,
    v: &Validation,
    out: &Path,
    receipt: &Receipt,
    inv: &Path,
) -> Result<ValidationRecord> {
    let pkg = &p.packages[v.package];
    let build = &p.builds[pkg.build];
    let product = &p.config.products[build.product];
    let desc = plan::descriptor(&build.target, &product.build)?;
    let package = receipt
        .packages
        .get(&v.package)
        .context("package checkpoint missing")?;
    let dir = out.join(format!("validations/{}", v.id));
    private(&dir)?;
    let invocation = dir.join(io::random_id()?);
    private(&invocation)?;
    let logs = invocation.join("logs");
    let mut check_count = 0;
    let observed_environment;
    let workspace = inv.join(format!("validation-{}", io::random_id()?));
    private(&workspace)?;
    let checkout =
        cohort::run::clone_source_at(root, &p.source.commit, p.config.timeout_seconds, &workspace)?;
    ensure!(
        source::snapshot_plain(&checkout)? == p.source,
        "validation checkout differs from source identity"
    );
    let check_inputs = acquire_tools(
        &product.inputs,
        &out.join(format!("check-inputs/{}", build.product)),
    )?;
    let environment_id = if let Some(runtime) = p.runtimes.get(&v.environment) {
        let (host, observed) = image(&runtime.image, &invocation)?;
        observed_environment = EnvironmentObservation::Container {
            host: host.clone(),
            image: observed.clone(),
        };
        let actual = out.join(format!("packages/{}/{}", v.package, pkg.filename));
        if v.kind.starts_with("install-") {
            let installed_binary = |binary: &str| -> Result<String> {
                let name = desc.binary_name(binary);
                let mapping = pkg
                    .install
                    .iter()
                    .find(|m| m.source == name)
                    .context("installation map omits a declared executable")?;
                Ok(format!("/{}", mapping.destination))
            };
            let owned = workspace.join("owned");
            let work = owned.join("work");
            let scratch = owned.join("payload");
            private(&work)?;
            private(&scratch)?;
            let driver = Driver {
                source: checkout.clone(),
                work,
                payload: scratch,
                owned,
                inputs: check_inputs.clone(),
                container: Some((runtime.image.clone(), host.clone(), observed.clone())),
                env: BTreeMap::new(),
                timeout: p.config.timeout_seconds,
                logs: logs.clone(),
                product,
                context: BTreeMap::from([
                    ("project".into(), "/inputs/validation-source".into()),
                    (
                        "product".into(),
                        if product.directory == "." {
                            "/inputs/validation-source".into()
                        } else {
                            format!("/inputs/validation-source/{}", product.directory)
                        },
                    ),
                    ("archive".into(), "/".into()),
                    ("binary".into(), installed_binary(&product.binaries[0])?),
                    ("work".into(), "/tmp/relship-checks".into()),
                ]),
            };
            let mut script = if v.kind == "install-deb" {
                format!("dpkg --install /packages/{}\n", pkg.filename)
            } else {
                format!("rpm --install /packages/{}\n", pkg.filename)
            };
            script = format!(
                "mkdir -p /tmp/relship-checks\nprintf keep > /tmp/relship-unrelated\n{script}"
            );
            for mapping in &pkg.install {
                let entry = &receipt.payloads[&pkg.build].files[&mapping.source];
                script.push_str(&format!(
                    "test \"$(sha256sum {} | cut -d ' ' -f1)\" = {}\n",
                    shell(&format!("/{}", mapping.destination)),
                    shell(&entry.sha256)
                ));
                script.push_str(&format!(
                    "test \"$(stat -c %a {})\" = {}\n",
                    shell(&format!("/{}", mapping.destination)),
                    shell(&format!("{:o}", entry.mode))
                ));
            }
            for binary in crate::config::effective_version_binaries(
                &product.binaries,
                product.version_binaries.as_deref(),
            ) {
                let name = installed_binary(binary)?;
                script.push_str(&format!(
                    "version_output=$({} {})\nprintf '%s\\n' \"$version_output\"\nprintf '%s\\n' \"$version_output\" | awk -v expected={} '{{for(i=1;i<=NF;i++) if($i==expected || $i==\"v\" expected) found=1}} END{{exit !found}}'\n",
                    shell(&name),
                    product
                        .version_args
                        .iter()
                        .map(|s| shell(s))
                        .collect::<Vec<_>>()
                        .join(" "),
                    shell(&p.resolved[build.product].version)
                ));
                check_count += 1;
            }
            for hook in &product.checks {
                let mut env = hook
                    .env
                    .iter()
                    .map(|(k, v)| (k.clone(), driver.text(v)))
                    .collect::<BTreeMap<_, _>>();
                env.extend([
                    ("KIT_PROJECT_DIR".into(), driver.text("{project}")),
                    ("KIT_PRODUCT_DIR".into(), driver.text("{product}")),
                    ("KIT_BINARY".into(), driver.text("{binary}")),
                    ("KIT_ARCHIVE_DIR".into(), "/".into()),
                    (
                        "KIT_VERSION".into(),
                        p.resolved[build.product].version.clone(),
                    ),
                    ("KIT_TARGET".into(), build.target.clone()),
                ]);
                let env = env
                    .iter()
                    .map(|(k, v)| shell(&format!("{k}={v}")))
                    .collect::<Vec<_>>()
                    .join(" ");
                script.push_str(&format!(
                    "cd {}\nenv {} {}\n",
                    shell(&driver.text("{product}")),
                    env,
                    hook.command
                        .iter()
                        .map(|x| shell(&driver.text(x)))
                        .collect::<Vec<_>>()
                        .join(" ")
                ));
                check_count += 1;
            }
            if v.kind == "install-deb" {
                script.push_str(&format!("dpkg --remove {}\n", shell(&pkg.metadata.name)));
            } else {
                script.push_str(&format!("rpm --erase {}\n", shell(&pkg.metadata.name)));
            }
            for mapping in &pkg.install {
                script.push_str(&format!(
                    "test ! -e {}\n",
                    shell(&format!("/{}", mapping.destination))
                ));
            }
            script.push_str("test \"$(cat /tmp/relship-unrelated)\" = keep\n");
            let request = InstallRequest {
                image: runtime.image.clone(),
                arch: runtime.arch,
                packages: vec![PackageInput {
                    path: actual,
                    sha256: package.sha256.clone(),
                }],
                inputs: check_inputs
                    .iter()
                    .map(|(name, path)| ReadOnlyMount {
                        source: path.clone(),
                        destination: format!("/inputs/{name}"),
                    })
                    .chain([ReadOnlyMount {
                        source: checkout.clone(),
                        destination: "/inputs/validation-source".into(),
                    }])
                    .collect(),
                memory_mib: 2048,
                cpus: 2,
                pids_limit: 256,
                argv: vec!["sh".into(), "-eu".into(), "-c".into(), script],
            };
            let mut commands = process::Commands::new(out, &logs, p.config.timeout_seconds)?;
            commands.run(
                &request.argv(&host, &observed)?,
                "install-check-remove",
                &BTreeMap::new(),
            )?;
        } else {
            let extraction = workspace.join("extracted");
            private(&extraction)?;
            extract_archive(pkg, &actual, &extraction)?;
            delivery::run::validate_payload_files(
                &extraction,
                &receipt.payloads[&pkg.build].files,
            )?;
            let owned = workspace.join("owned");
            let work = owned.join("work");
            let scratch = owned.join("payload");
            private(&work)?;
            private(&scratch)?;
            let env = BTreeMap::new();
            let driver = Driver {
                source: checkout.clone(),
                work,
                payload: scratch,
                owned,
                inputs: check_inputs
                    .iter()
                    .map(|(n, p)| (n.clone(), p.clone()))
                    .chain([("program".into(), extraction)])
                    .collect(),
                container: Some((runtime.image.clone(), host, observed)),
                env,
                timeout: p.config.timeout_seconds,
                logs: logs.clone(),
                product,
                context: BTreeMap::from([
                    ("archive".into(), "/inputs/program".into()),
                    (
                        "binary".into(),
                        format!("/inputs/program/{}", desc.binary_name(&product.binaries[0])),
                    ),
                ]),
            };
            for (i, binary) in crate::config::effective_version_binaries(
                &product.binaries,
                product.version_binaries.as_deref(),
            )
            .iter()
            .enumerate()
            {
                let mut args = vec![format!("/inputs/program/{}", desc.binary_name(binary))];
                args.extend(product.version_args.clone());
                version(
                    &driver.run(&args, &format!("version-{i}"), &BTreeMap::new())?,
                    &p.resolved[build.product].version,
                )?;
                check_count += 1;
            }
            for (i, h) in product.checks.iter().enumerate() {
                driver.run(&h.command, &format!("check-{i}"), &h.env)?;
                check_count += 1;
            }
        }
        plan::content_id(b"relship/runtime-environment/v1\0", runtime)?
    } else {
        ensure!(
            v.environment == build.profile.id,
            "unknown native validation environment"
        );
        let extracted = workspace.join("extracted");
        private(&extracted)?;
        extract_archive(
            pkg,
            &out.join(format!("packages/{}/{}", v.package, pkg.filename)),
            &extracted,
        )?;
        delivery::run::validate_payload_files(&extracted, &receipt.payloads[&pkg.build].files)?;
        crate::v5::runtime::native_host(&desc)?;
        observed_environment = receipt
            .payloads
            .get(&pkg.build)
            .context("missing native build environment")?
            .environment
            .clone();
        verify_environment(&observed_environment, &build.profile)?;
        let owned = workspace.join("owned");
        let work = owned.join("work");
        let scratch = owned.join("payload");
        private(&work)?;
        private(&scratch)?;
        let driver = Driver {
            source: checkout.clone(),
            work,
            payload: scratch,
            owned,
            inputs: check_inputs,
            container: None,
            env: runtime_environment(),
            timeout: p.config.timeout_seconds,
            logs: logs.clone(),
            product,
            context: BTreeMap::from([
                ("archive".into(), extracted.to_string_lossy().into_owned()),
                (
                    "binary".into(),
                    extracted
                        .join(desc.binary_name(&product.binaries[0]))
                        .to_string_lossy()
                        .into_owned(),
                ),
            ]),
        };
        for (i, binary) in crate::config::effective_version_binaries(
            &product.binaries,
            product.version_binaries.as_deref(),
        )
        .iter()
        .enumerate()
        {
            let mut argv = vec![
                extracted
                    .join(desc.binary_name(binary))
                    .to_string_lossy()
                    .into_owned(),
            ];
            argv.extend(product.version_args.clone());
            version(
                &driver.run(&argv, &format!("version-{i}"), &BTreeMap::new())?,
                &p.resolved[build.product].version,
            )?;
            check_count += 1;
        }
        for (i, h) in product.checks.iter().enumerate() {
            driver.run(&h.command, &format!("check-{i}"), &h.env)?;
            check_count += 1;
        }
        build.profile.identity()?
    };
    ensure!(
        source::snapshot_plain(&checkout)? == p.source,
        "runtime checks changed source inputs"
    );
    let evidence = ValidationEvidence {
        spec: v.clone(),
        package_sha256: package.sha256.clone(),
        environment_id: environment_id.clone(),
        observed_environment,
        logs: io::inventory(&logs)?,
        checks: check_count,
    };
    let path = invocation.join("evidence.json");
    io::write_json_atomic(&path, &evidence)?;
    let _ = inv;
    Ok(ValidationRecord {
        id: v.id.clone(),
        package_sha256: package.sha256.clone(),
        environment_id,
        command_log: path.strip_prefix(out)?.to_string_lossy().replace('\\', "/"),
        evidence_sha256: source::file_digest(&path)?,
    })
}
fn shell(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
fn extract_archive(spec: &delivery::model::PackageSpec, path: &Path, dest: &Path) -> Result<()> {
    match spec.format {
        delivery::model::Format::TarGz => {
            let input = flate2::read::GzDecoder::new(fs::File::open(path)?);
            for e in tar::Archive::new(input).entries()? {
                let mut e = e?;
                ensure!(
                    e.header().entry_type().is_file(),
                    "validated package contains non-file entry"
                );
                let name = e
                    .path()?
                    .to_str()
                    .context("non-UTF8 package path")?
                    .to_owned();
                let target = crate::config::safe_join(dest, &name)?;
                if let Some(p) = target.parent() {
                    fs::create_dir_all(p)?;
                }
                e.unpack(&target)?;
            }
        }
        delivery::model::Format::Zip => {
            let mut zip = zip::ZipArchive::new(fs::File::open(path)?)?;
            for i in 0..zip.len() {
                let mut entry = zip.by_index(i)?;
                let target = crate::config::safe_join(dest, entry.name())?;
                if let Some(p) = target.parent() {
                    fs::create_dir_all(p)?;
                }
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target)?;
                std::io::copy(&mut entry, &mut file)?;
                delivery::run::set_mode(&target, entry.unix_mode().unwrap_or(0o644) & 0o777)?;
            }
        }
        _ => anyhow::bail!("native packages require installation validation"),
    }
    Ok(())
}
pub fn execute(
    root: &Path,
    p: &Plan,
    out: &Path,
    selected: &[usize],
    resume: bool,
    nfpm: Option<&Path>,
) -> Result<Receipt> {
    execute_with_retry(root, p, out, selected, resume, nfpm, &[])
}
pub fn execute_with_retry(
    root: &Path,
    p: &Plan,
    out: &Path,
    selected: &[usize],
    resume: bool,
    nfpm: Option<&Path>,
    allow_retry: &[usize],
) -> Result<Receipt> {
    ensure!(
        allow_retry.iter().all(|i| selected.contains(i)),
        "retry permission is outside the saved selection"
    );
    plan::validate_saved(root, p)?;
    ensure!(
        !selected.is_empty()
            && selected.iter().copied().collect::<BTreeSet<_>>().len() == selected.len()
            && selected.iter().all(|i| *i < p.builds.len()),
        "invalid selected build set"
    );
    let out = cohort::run::attempt_directory(root, out, resume)?;
    let _lock = cohort::run::lock_attempt(&out)?;
    let mut receipt = if resume {
        ensure!(
            plan::load(&out.join("plan.json"))? == *p,
            "immutable resume plan differs"
        );
        let r = status(&out)?;
        ensure!(r.selected == selected, "resume selection changed");
        verify(&out, false)?;
        r
    } else {
        for dir in [
            "payloads",
            "packages",
            "invocations",
            "validations",
            "evidence",
        ] {
            private(&out.join(dir))?;
        }
        io::write_json_atomic(&out.join("plan.json"), p)?;
        Receipt {
            schema: SCHEMA,
            plan_id: p.id.clone(),
            source_commit: p.source.commit.clone(),
            selected: selected.to_vec(),
            payloads: BTreeMap::new(),
            packages: BTreeMap::new(),
            validations: BTreeMap::new(),
            failures: vec![],
            complete: false,
            publication_ready: false,
        }
    };
    save(&out, &receipt)?;
    let invocation = out.join("invocations").join(io::random_id()?);
    private(&invocation)?;
    let mut stage_name = "preflight".to_owned();
    let result = (|| -> Result<()> {
        for &bi in selected {
            if !receipt.payloads.contains_key(&bi) {
                let product = &p.config.products[p.builds[bi].product];
                if resume
                    && !product.prepare.is_empty()
                    && receipt
                        .failures
                        .iter()
                        .any(|f| f.stage == format!("build-{bi}"))
                {
                    ensure!(
                        allow_retry.contains(&bi),
                        "build {bi} previously failed and has preparation hooks; grant explicit --allow-retry before rerunning it"
                    );
                }
                let orphan = out.join(format!("payloads/{bi}"));
                if orphan.exists() {
                    fs::rename(
                        &orphan,
                        invocation.join(format!("uncheckpointed-payload-{bi}")),
                    )?;
                }
                stage_name = format!("build-{bi}");
                let inv = invocation.join(format!("build-{bi}"));
                private(&inv)?;
                let record = stage(root, p, bi, &out, &inv)?;
                receipt.payloads.insert(bi, record);
                save(&out, &receipt)?;
            } else {
                delivery::run::validate_payload_files(
                    &out.join(format!("payloads/{bi}")),
                    &receipt.payloads[&bi].files,
                )?;
            }
            for (pi, pkg) in p.packages.iter().enumerate().filter(|(_, s)| s.build == bi) {
                if !receipt.packages.contains_key(&pi) {
                    stage_name = format!("package-{pi}");
                    let dir = out.join(format!("packages/{pi}"));
                    if dir.exists() {
                        fs::rename(
                            &dir,
                            invocation.join(format!("uncheckpointed-package-{pi}")),
                        )?;
                    }
                    private(&dir)?;
                    let dest = dir.join(&pkg.filename);
                    let files = &receipt.payloads[&bi].files;
                    let target = catalog_target(p, bi)?;
                    let profile = crate::catalog::package_support(&target, pkg.format)?;
                    if pkg.format.is_native() {
                        let tool = delivery::native::resolve_nfpm(nfpm)?;
                        delivery::native::package_with_profile(
                            pkg,
                            &profile,
                            &out.join(format!("payloads/{bi}")),
                            files,
                            &tool,
                            &dest,
                        )?;
                    } else {
                        delivery::native::package_archive(
                            pkg,
                            &out.join(format!("payloads/{bi}")),
                            files,
                            &dest,
                        )?;
                    }
                    receipt.packages.insert(
                        pi,
                        PackageRecord {
                            package_id: pkg.id.clone(),
                            filename: pkg.filename.clone(),
                            sha256: source::file_digest(&dest)?,
                            size: fs::metadata(&dest)?.len(),
                            payload_id: p.builds[bi].id.clone(),
                        },
                    );
                    save(&out, &receipt)?;
                }
                for v in p.validations.iter().filter(|v| v.package == pi) {
                    if !receipt.validations.contains_key(&v.id) {
                        stage_name = format!("validation-{}", v.id);
                        let record = validate_package(root, p, v, &out, &receipt, &invocation)?;
                        receipt.validations.insert(v.id.clone(), record);
                        save(&out, &receipt)?;
                    }
                }
            }
        }
        receipt.complete = true;
        save(&out, &receipt)?;
        verify(&out, true)?;
        Ok(())
    })();
    if let Err(e) = result {
        receipt.complete = false;
        receipt.failures.push(Failure {
            stage: stage_name,
            message: format!("{e:#}"),
            invocation: invocation
                .strip_prefix(&out)?
                .to_string_lossy()
                .into_owned(),
        });
        save(&out, &receipt)?;
        return Err(e);
    }
    Ok(receipt)
}
fn catalog_target(p: &Plan, bi: usize) -> Result<crate::catalog::TargetDescriptor> {
    crate::catalog::resolve(&p.builds[bi].target)
}
pub fn verify(out: &Path, require_complete: bool) -> Result<Receipt> {
    verify_inner(out, require_complete, None)
}
pub fn verify_with_artifacts(
    out: &Path,
    require_complete: bool,
    artifacts: &Path,
) -> Result<Receipt> {
    verify_inner(out, require_complete, Some(artifacts))
}
fn verify_inner(out: &Path, require_complete: bool, artifacts: Option<&Path>) -> Result<Receipt> {
    let p = plan::load(&out.join("plan.json"))?;
    plan::shape(&p)?;
    let r = status(out)?;
    ensure!(
        r.plan_id == p.id
            && r.source_commit == p.source.commit
            && r.selected.iter().copied().collect::<BTreeSet<_>>().len() == r.selected.len()
            && r.selected.iter().all(|i| *i < p.builds.len()),
        "receipt differs from plan selection"
    );
    for (&bi, payload) in &r.payloads {
        ensure!(
            r.selected.contains(&bi) && payload.build_id == p.builds[bi].id,
            "payload scope differs"
        );
        let build = &p.builds[bi];
        let product = &p.config.products[build.product];
        let descriptor = plan::descriptor(&build.target, &product.build)?;
        verify_environment(&payload.environment, &build.profile)?;
        if matches!(product.build.name(), "rust" | "go")
            && let (
                Environment::NativeSdk { sdk, .. },
                EnvironmentObservation::NativeSdk { sdk: observed },
            ) = (&build.profile.environment, &payload.environment)
        {
            let selection = super::toolchain::native_selection(
                sdk,
                product.build.name(),
                &descriptor.compiler_target,
            )?;
            for (tool, _) in selection.probes {
                super::toolchain::validate_version(
                    &tool,
                    observed
                        .tool_versions
                        .get(&tool)
                        .context("missing native compiler version observation")?,
                )?;
            }
        }
        ensure!(
            payload.observations.len() == product.binaries.len(),
            "binary observations do not cover planned executable set"
        );
        for (binary, observation) in product.binaries.iter().zip(&payload.observations) {
            let entry = payload
                .files
                .get(&descriptor.binary_name(binary))
                .context("payload omits planned executable")?;
            ensure!(
                observation.sha256 == entry.sha256 && observation.arch == build.profile.arch,
                "binary observation subject or architecture differs"
            );
            validate_observation(observation, &build.profile)?;
            if build.profile.os == "linux" && product.build.name() == "go" {
                ensure!(
                    observation.interpreter.is_none()
                        && observation.needed.is_empty()
                        && observation.required_versions.is_empty(),
                    "pure Go evidence has an undeclared libc/loader dependency"
                );
            }
        }
        if build.profile.os == "windows" {
            let policy = build
                .profile
                .windows_runtime
                .as_ref()
                .context("Windows runtime policy missing")?;
            let runtime = payload
                .windows_runtime
                .as_ref()
                .context("Windows runtime selection witness missing")?;
            ensure!(
                runtime.mode == policy.mode,
                "Windows runtime policy differs from selection witness"
            );
        } else {
            ensure!(
                payload.windows_runtime.is_none(),
                "Windows DLL evidence on another OS"
            );
        }
        match (&build.recipe, &payload.witness) {
            (Recipe::Cmake { spec }, Some(w)) => ensure!(
                *spec == w.spec,
                "CMake witness recipe differs from immutable plan"
            ),
            (Recipe::Fixed { .. }, None) => (),
            _ => anyhow::bail!(
                "CMake requires a selection witness; fixed recipe must not substitute one"
            ),
        }
        ensure!(
            matches!(build.recipe, Recipe::Cmake { .. }) == payload.cmake_inputs.is_some(),
            "CMake requires a resolved input boundary; fixed recipes cannot substitute one"
        );
        if let Some(w) = &payload.witness {
            let evidence = out.join(format!("evidence/cmake-{bi}"));
            crate::cmake::verify_preserved_reply(&evidence, w)?;
            let boundary = payload
                .cmake_inputs
                .as_ref()
                .context("missing CMake input boundary")?;
            let allowed = super::cmake_boundary::roots(
                &p,
                bi,
                &w.reported_source,
                &w.reported_build,
                &boundary.inputs,
            )?;
            let actual = crate::cmake::validate_preserved_inputs(
                &evidence,
                w,
                &allowed,
                &build.profile.os,
                &cmake_search_dirs(&build.profile),
            )?;
            ensure!(
                actual == boundary.selection,
                "CMake resolved input selection differs from preserved File API evidence"
            );
            for a in &w.artifacts {
                let target = plan::descriptor(
                    &p.builds[bi].target,
                    &p.config.products[p.builds[bi].product].build,
                )?;
                let entry = payload
                    .files
                    .get(&target.binary_name(&a.binary))
                    .context("CMake witness missing payload executable")?;
                ensure!(
                    entry.sha256 == a.sha256 && entry.size == a.size,
                    "CMake witness differs from delivered bytes"
                );
            }
        }
    }
    for (&pi, record) in &r.packages {
        let spec = p.packages.get(pi).context("unknown package checkpoint")?;
        ensure!(
            r.selected.contains(&spec.build)
                && record.package_id == spec.id
                && record.filename == spec.filename
                && record.payload_id == p.builds[spec.build].id,
            "package checkpoint identity differs"
        );
        let path = if let Some(artifacts) = artifacts {
            crate::config::safe_join(artifacts, &spec.filename)?
        } else {
            crate::config::safe_join(out, &format!("packages/{pi}/{}", spec.filename))?
        };
        ensure!(
            source::file_digest(&path)? == record.sha256
                && fs::metadata(&path)?.len() == record.size,
            "package checkpoint bytes changed"
        );
        let payload = r
            .payloads
            .get(&spec.build)
            .context("missing payload checkpoint")?;
        let profile =
            crate::catalog::package_support(&catalog_target(&p, spec.build)?, spec.format)?;
        let build = &p.builds[spec.build];
        let product = &p.config.products[build.product];
        let desc = plan::descriptor(&build.target, &product.build)?;
        let mut requested = product
            .binaries
            .iter()
            .map(|b| {
                let name = desc.binary_name(b);
                if spec.format.is_native() {
                    spec.install
                        .iter()
                        .find(|m| m.source == name)
                        .map(|m| m.destination.clone())
                        .context("missing executable install mapping")
                } else {
                    Ok(name)
                }
            })
            .collect::<Result<BTreeSet<_>>>()?;
        if let Some(runtime) = &payload.windows_runtime {
            requested.extend(runtime.libraries.keys().cloned());
            requested.extend(runtime.licenses.keys().cloned());
        }
        let contents = delivery::inspect::inspect_binary_contents(
            spec,
            &profile,
            &path,
            &payload.files,
            &requested,
        )?;
        for (binary, observed) in product.binaries.iter().zip(&payload.observations) {
            let name = desc.binary_name(binary);
            let name = if spec.format.is_native() {
                &spec
                    .install
                    .iter()
                    .find(|m| m.source == name)
                    .context("missing installed executable")?
                    .destination
            } else {
                &name
            };
            let bytes = contents
                .get(name)
                .context("missing delivered executable bytes")?;
            let actual = inspect_bytes(bytes, &desc.os, build.profile.arch)?;
            ensure!(
                &actual == observed,
                "binary ABI observation differs from delivered package bytes"
            );
        }
        if build.profile.os == "windows" {
            let policy = build
                .profile
                .windows_runtime
                .as_ref()
                .context("Windows CRT policy missing")?;
            let actual = crate::compatibility::windows_crt::verify(
                policy,
                &payload.observations,
                &payload.files,
                &contents,
            )?;
            ensure!(
                payload.windows_runtime.as_ref() == Some(&actual),
                "Windows runtime witness differs from delivered DLL/license bytes"
            );
            for library in actual.libraries.values() {
                validate_observation(library, &build.profile)?;
            }
        }
    }
    for (id, record) in &r.validations {
        let spec = p
            .validations
            .iter()
            .find(|v| v.id == *id)
            .context("unexpected validation checkpoint")?;
        let package = r
            .packages
            .get(&spec.package)
            .context("validation has no package")?;
        ensure!(
            record.id == *id && record.package_sha256 == package.sha256,
            "validation subject differs from final package"
        );
        let build = &p.builds[p.packages[spec.package].build];
        let product = &p.config.products[build.product];
        let expected_environment = if let Some(runtime) = p.runtimes.get(&spec.environment) {
            plan::content_id(b"relship/runtime-environment/v1\0", runtime)?
        } else {
            build.profile.identity()?
        };
        ensure!(
            record.environment_id == expected_environment,
            "validation environment differs from immutable plan"
        );
        let path = crate::config::safe_join(out, &record.command_log)?;
        ensure!(
            source::file_digest(&path)? == record.evidence_sha256,
            "validation evidence changed"
        );
        let e: ValidationEvidence = io::read_json(&path)?;
        ensure!(
            e.spec == *spec
                && e.package_sha256 == package.sha256
                && e.environment_id == record.environment_id
                && e.checks
                    == crate::config::effective_version_binaries(
                        &product.binaries,
                        product.version_binaries.as_deref()
                    )
                    .len()
                        + product.checks.len(),
            "validation evidence does not satisfy planned task"
        );
        if let Some(runtime) = p.runtimes.get(&spec.environment) {
            verify_container(&e.observed_environment, &runtime.image, runtime.arch)?;
        } else {
            verify_environment(&e.observed_environment, &build.profile)?;
        }
        let logs = path.parent().unwrap().join("logs");
        ensure!(io::inventory(&logs)? == e.logs, "validation logs changed");
        let commands: Vec<CommandEvidence> = io::read_json(&logs.join("commands.json"))?;
        let expected_count = if spec.kind.starts_with("install-") {
            1
        } else {
            e.checks
        };
        ensure!(
            commands.len() == expected_count,
            "validation command set is incomplete"
        );
        let mut labels = BTreeSet::new();
        for command in commands {
            ensure!(
                labels.insert(command.label.clone())
                    && command.exit_code == Some(0)
                    && !command.timed_out
                    && command.spawn_error.is_none()
                    && !command.command.is_empty(),
                "validation contains a failed, duplicate or incomplete command"
            );
            ensure!(
                e.logs.contains_key(&format!("{}.stdout", command.label))
                    && e.logs.contains_key(&format!("{}.stderr", command.label)),
                "validation output logs missing"
            );
        }
    }
    if require_complete {
        ensure!(
            r.complete && !r.selected.is_empty(),
            "required execution is incomplete"
        );
        for bi in &r.selected {
            ensure!(r.payloads.contains_key(bi), "missing completed payload");
            for (pi, _) in p
                .packages
                .iter()
                .enumerate()
                .filter(|(_, pkg)| pkg.build == *bi)
            {
                ensure!(r.packages.contains_key(&pi), "missing required package");
                for v in p.validations.iter().filter(|v| v.package == pi) {
                    ensure!(
                        r.validations.contains_key(&v.id),
                        "missing required validation"
                    );
                }
            }
        }
    }
    Ok(r)
}
pub fn export(out: &Path, dest: &Path) -> Result<()> {
    let r = verify(out, true)?;
    ensure!(!dest.exists(), "export destination already exists");
    private(dest)?;
    let mut files = BTreeSet::from(["plan.json".to_owned(), "receipt.json".to_owned()]);
    for (i, package) in &r.packages {
        files.insert(format!("packages/{i}/{}", package.filename));
    }
    for record in r.validations.values() {
        files.insert(record.command_log.clone());
        let path = crate::config::safe_join(out, &record.command_log)?;
        let e: ValidationEvidence = io::read_json(&path)?;
        let parent = Path::new(&record.command_log)
            .parent()
            .context("invalid validation evidence reference")?;
        for name in e.logs.keys() {
            files.insert(
                parent
                    .join("logs")
                    .join(name)
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    for (i, payload) in &r.payloads {
        if let Some(w) = &payload.witness {
            let prefix = format!("evidence/cmake-{i}");
            files.insert(format!("{prefix}/witness.json"));
            for name in w.reply_files.keys() {
                files.insert(format!("{prefix}/{name}"));
            }
        }
    }
    for name in files {
        let from = crate::config::safe_join(out, &name)?;
        let to = crate::config::safe_join(dest, &name)?;
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent)?;
        }
        let metadata = fs::symlink_metadata(&from)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "export input must be a regular file"
        );
        let entry = cohort::model::FileEntry {
            size: metadata.len(),
            sha256: source::file_digest(&from)?,
        };
        io::copy_file_checked(&from, &to, &entry)?;
    }
    verify(dest, true)?;
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandEvidence {
    label: String,
    command: Vec<String>,
    exit_code: Option<i32>,
    timed_out: bool,
    #[serde(rename = "elapsed_ms")]
    _elapsed_ms: u64,
    spawn_error: Option<String>,
}
fn validate_sdk_links(roots: &BTreeMap<String, String>) -> Result<()> {
    fn walk(
        at: &Path,
        roots: &BTreeMap<String, String>,
        count: &mut usize,
        progress: &mut Progress,
    ) -> Result<()> {
        if at.is_file() {
            return Ok(());
        }
        for entry in fs::read_dir(at)? {
            let path = entry?.path();
            *count += 1;
            ensure!(*count < 300_000, "SDK link inspection exceeds bound");
            let m = fs::symlink_metadata(&path)?;
            if m.file_type().is_symlink() {
                let target = fs::canonicalize(&path)
                    .with_context(|| format!("SDK contains a broken link: {}", path.display()))?;
                ensure!(
                    roots
                        .keys()
                        .any(|root| fs::canonicalize(root).is_ok_and(|r| target.starts_with(r))),
                    "SDK link target is outside all pinned SDK roots"
                );
            } else if m.is_dir() {
                walk(&path, roots, count, progress)?;
            }
            progress.visit(&path, &m);
        }
        Ok(())
    }
    let mut count = 0;
    for root in roots.keys() {
        let mut progress = Progress::new(Path::new(root), "links");
        walk(Path::new(root), roots, &mut count, &mut progress)?;
        progress.finish();
    }
    Ok(())
}
fn verify_container(
    observation: &EnvironmentObservation,
    pin: &ImagePin,
    arch: Architecture,
) -> Result<()> {
    if let EnvironmentObservation::Container { host, image } = observation {
        image.verify(pin)?;
        ensure!(
            host.os == "linux"
                && host.daemon_os == "linux"
                && host.arch == arch
                && host.daemon_arch == arch,
            "observed container host is not the planned native architecture"
        );
        Ok(())
    } else {
        anyhow::bail!("container environment observation is required")
    }
}
fn verify_environment(observation: &EnvironmentObservation, profile: &Profile) -> Result<()> {
    match (&profile.environment, observation) {
        (Environment::LinuxContainer { image, .. }, _) => {
            verify_container(observation, image, profile.arch)
        }
        (
            Environment::NativeSdk { sdk, .. },
            EnvironmentObservation::NativeSdk { sdk: observed },
        ) => sdk.verify(observed, &profile.os, profile.arch),
        _ => anyhow::bail!("environment observation type differs from profile"),
    }
}
fn validate_observation(observation: &BinaryObservation, profile: &Profile) -> Result<()> {
    if profile.os == "linux" {
        let allowed = [
            "libc.so.6",
            "libpthread.so.0",
            "libdl.so.2",
            "libm.so.6",
            "librt.so.1",
            "libutil.so.1",
            "libresolv.so.2",
            "libgcc_s.so.1",
            match profile.arch {
                Architecture::X86_64 => "ld-linux-x86-64.so.2",
                Architecture::Aarch64 => "ld-linux-aarch64.so.1",
            },
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        validate_linux_abi(observation, "2.17", &allowed)?;
    } else {
        for name in &observation.needed {
            let allowed = if profile.os == "windows" && profile.windows_runtime.is_some() {
                true
            } else if profile.os == "macos" {
                name.starts_with("/usr/lib/") || name.starts_with("/System/Library/Frameworks/")
            } else {
                let n = name.to_ascii_lowercase();
                n.starts_with("api-ms-win-")
                    || n.starts_with("ext-ms-win-")
                    || [
                        "kernel32.dll",
                        "advapi32.dll",
                        "ws2_32.dll",
                        "bcrypt.dll",
                        "ntdll.dll",
                        "crypt32.dll",
                        "secur32.dll",
                        "user32.dll",
                        "shell32.dll",
                        "ole32.dll",
                        "oleaut32.dll",
                        "normaliz.dll",
                        "iphlpapi.dll",
                        "ucrtbase.dll",
                        "msvcrt.dll",
                    ]
                    .contains(&n.as_str())
            };
            ensure!(
                allowed,
                "undeclared native runtime dependency {name}; a build-machine runtime cannot satisfy package delivery"
            );
        }
        ensure!(
            observation.arch == profile.arch,
            "native binary architecture differs"
        );
        if let Some(max) = &profile.minimum_os {
            let allowed = observation.needed.iter().cloned().collect();
            validate_native_abi(observation, max, &allowed)?;
        }
    }
    Ok(())
}

fn portable_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    value.strip_prefix(r"\\?\").unwrap_or(&value).to_owned()
}

fn runtime_environment() -> BTreeMap<String, String> {
    let mut env = BTreeMap::from([("LANG".into(), "C".into()), ("LC_ALL".into(), "C".into())]);
    if cfg!(windows) {
        if let Ok(root) = std::env::var("SYSTEMROOT") {
            env.insert("PATH".into(), format!("{root}\\System32;{root}"));
            env.insert("SYSTEMROOT".into(), root);
        }
    } else {
        env.insert("PATH".into(), "/usr/bin:/bin".into());
    }
    for k in ["TEMP", "TMP", "TMPDIR"] {
        if let Ok(v) = std::env::var(k) {
            env.insert(k.into(), v);
        }
    }
    env
}

fn cmake_search_dirs(profile: &Profile) -> Vec<PathBuf> {
    if profile.os == "windows"
        && let Environment::NativeSdk { sdk, .. } = &profile.environment
    {
        return sdk
            .environment
            .get("LIB")
            .into_iter()
            .flat_map(|value| value.split(';'))
            .filter(|p| !p.is_empty())
            .map(PathBuf::from)
            .collect();
    }
    vec![]
}

#[cfg(test)]
mod abi_tests {
    use super::*;

    #[test]
    fn linux_loader_dependency_is_arch_specific_and_keeps_the_glibc_floor() {
        for (arch, loader, other) in [
            (
                Architecture::X86_64,
                "ld-linux-x86-64.so.2",
                "ld-linux-aarch64.so.1",
            ),
            (
                Architecture::Aarch64,
                "ld-linux-aarch64.so.1",
                "ld-linux-x86-64.so.2",
            ),
        ] {
            let profile = Profile::linux_glibc217(arch).unwrap();
            let mut observed = BinaryObservation {
                format: "elf".into(),
                arch,
                machine: 0,
                interpreter: None,
                needed: vec!["libc.so.6".into(), loader.into()],
                required_versions: vec![RequiredVersion {
                    library: loader.into(),
                    name: "GLIBC_2.17".into(),
                }],
                provided_versions: vec![],
                minimum_os: None,
                sdk_version: None,
                has_search_path: false,
                has_dynamic_plugins: false,
                sha256: "1".repeat(64),
            };
            validate_observation(&observed, &profile).unwrap();
            observed.needed.push(other.into());
            assert!(validate_observation(&observed, &profile).is_err());
            observed.needed.pop();
            observed.required_versions[0].name = "GLIBC_2.18".into();
            assert!(validate_observation(&observed, &profile).is_err());
        }
    }
}
