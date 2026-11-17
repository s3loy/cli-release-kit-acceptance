use super::{Architecture, ImagePin};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostIdentity {
    pub os: String,
    pub arch: Architecture,
    pub daemon_os: String,
    pub daemon_arch: Architecture,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContainerImageObservation {
    pub manifest_digest: String,
    pub config_digest: String,
    pub os: String,
    pub arch: Architecture,
}
impl ContainerImageObservation {
    /// Docker's image ID is the config digest; a matching RepoDigest alone is
    /// insufficient when an index may contain several architecture manifests.
    pub fn from_docker_inspect(json: &str, pin: &ImagePin) -> Result<Self> {
        let values: Vec<serde_json::Value> = serde_json::from_str(json)?;
        ensure!(values.len() == 1, "expected one inspected container image");
        let value = &values[0];
        ensure!(
            value["RepoDigests"]
                .as_array()
                .is_some_and(|v| v.iter().any(|s| s.as_str() == Some(&pin.reference))),
            "inspected image lacks the exact pinned manifest reference"
        );
        let result = Self {
            manifest_digest: pin.manifest_digest.clone(),
            config_digest: value["Id"]
                .as_str()
                .context("inspected image lacks config ID")?
                .into(),
            os: value["Os"]
                .as_str()
                .context("inspected image lacks OS")?
                .into(),
            arch: Architecture::parse(
                value["Architecture"]
                    .as_str()
                    .context("inspected image lacks architecture")?,
            )?,
        };
        result.verify(pin)?;
        Ok(result)
    }
    pub fn verify(&self, pin: &ImagePin) -> Result<()> {
        pin.validate(self.arch)?;
        ensure!(
            self.os == "linux"
                && self.manifest_digest == pin.manifest_digest
                && self.config_digest == pin.config_digest,
            "local container image identity differs from saved manifest/config/platform"
        );
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct ReadOnlyMount {
    pub source: PathBuf,
    pub destination: String,
}
#[derive(Clone, Debug)]
pub struct ContainerRequest {
    pub image: ImagePin,
    pub arch: Architecture,
    pub source: PathBuf,
    /// All writable host directories must be direct or nested children of this
    /// invocation-owned boundary; source/input trees may never overlap it.
    pub owned_root: PathBuf,
    pub work: PathBuf,
    pub output: PathBuf,
    pub inputs: Vec<ReadOnlyMount>,
    pub uid: u32,
    pub gid: u32,
    pub memory_mib: u32,
    pub cpus: u16,
    pub pids_limit: u32,
    pub argv: Vec<String>,
}
fn safe_host(path: &Path) -> Result<PathBuf> {
    ensure!(
        path.is_absolute()
            && path
                .components()
                .all(|p| !matches!(p, Component::ParentDir | Component::CurDir)),
        "container host path must be absolute and normalized"
    );
    for ancestor in path.ancestors() {
        let meta = fs::symlink_metadata(ancestor)?;
        ensure!(
            !meta.file_type().is_symlink(),
            "container mount path contains a symlink"
        );
    }
    let canonical = fs::canonicalize(path)?;
    ensure!(
        ![
            "/proc",
            "/sys",
            "/dev",
            "/run",
            "/var/run",
            "/etc",
            "/var/lib/docker"
        ]
        .iter()
        .any(|p| canonical.starts_with(p)),
        "container mount targets a sensitive host system directory"
    );
    ensure!(!canonical.components().any(|c| matches!(c, Component::Normal(name) if [".ssh", ".aws", ".azure", ".kube", ".docker", ".gnupg"].iter().any(|v| name == std::ffi::OsStr::new(v)))), "container mount targets a credential directory");
    ensure!(
        canonical.is_dir(),
        "container mount must be a regular directory"
    );
    let value = canonical.to_str().context("non-UTF8 container path")?;
    ensure!(
        !value.contains([',', '\n', '\r', '\0']),
        "unsafe container mount path separator"
    );
    ensure!(
        canonical.parent().is_some(),
        "refusing a root filesystem mount"
    );
    Ok(canonical)
}
fn safe_tree(root: &Path) -> Result<()> {
    let mut pending = vec![root.to_path_buf()];
    let mut count = 0usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            count += 1;
            ensure!(count <= 200_000, "container input inventory exceeds bound");
            let kind = entry.file_type()?;
            ensure!(
                kind.is_file() || kind.is_dir() || kind.is_symlink(),
                "container mounts cannot expose sockets, devices or named pipes"
            );
            if kind.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(())
}
fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
fn readonly_inputs(
    mounts: &[ReadOnlyMount],
    forbidden: Option<&Path>,
) -> Result<Vec<(PathBuf, String)>> {
    ensure!(mounts.len() <= 64, "too many readonly input mounts");
    let mut inputs = Vec::new();
    for input in mounts {
        let path = safe_host(&input.source)?;
        safe_tree(&path)?;
        let relative = input
            .destination
            .strip_prefix("/inputs/")
            .context("readonly inputs must be mounted beneath /inputs")?;
        crate::config::relative(relative)?;
        ensure!(
            !input.destination.contains([',', '\n', '\r', '\0'])
                && forbidden.is_none_or(|root| !overlaps(&path, root)),
            "unsafe input mount"
        );
        ensure!(
            inputs
                .iter()
                .all(|(p, d): &(PathBuf, String)| !overlaps(p, &path)
                    && !overlaps(Path::new(d), Path::new(&input.destination))),
            "overlapping input mounts are unsupported"
        );
        inputs.push((path, input.destination.clone()));
    }
    Ok(inputs)
}
fn mount(argv: &mut Vec<String>, host: &Path, destination: &str, readonly: bool) {
    argv.extend([
        "--mount".into(),
        format!(
            "type=bind,source={},target={destination}{}",
            host.display(),
            if readonly { ",readonly" } else { "" }
        ),
    ]);
}
impl ContainerRequest {
    /// Builds argv only. Execution uses the existing bounded Commands API.
    /// Network access is always disabled; same-container loopback application
    /// checks remain possible without granting an external bridge network.
    pub fn argv(
        &self,
        host: &HostIdentity,
        observed: &ContainerImageObservation,
    ) -> Result<Vec<String>> {
        self.image.validate(self.arch)?;
        observed.verify(&self.image)?;
        ensure!(
            host.os == "linux"
                && host.daemon_os == "linux"
                && host.arch == self.arch
                && host.daemon_arch == self.arch,
            "native container execution requires matching Linux host, daemon and target architecture; emulation is unsupported"
        );
        ensure!(
            self.uid != 0 && self.gid != 0,
            "container execution must use a non-root runner UID/GID"
        );
        ensure!(
            (128..=65536).contains(&self.memory_mib)
                && (1..=64).contains(&self.cpus)
                && (32..=4096).contains(&self.pids_limit),
            "container resource limits are outside the supported bounds"
        );
        ensure!(
            !self.argv.is_empty()
                && self.argv.len() <= 4096
                && self
                    .argv
                    .iter()
                    .all(|s| s.len() <= 128 * 1024 && !s.contains('\0')),
            "invalid container command"
        );
        let source = safe_host(&self.source)?;
        safe_tree(&source)?;
        let owned = safe_host(&self.owned_root)?;
        let work = safe_host(&self.work)?;
        let output = safe_host(&self.output)?;
        ensure!(
            work != owned
                && output != owned
                && work.starts_with(&owned)
                && output.starts_with(&owned)
                && !overlaps(&work, &output),
            "writable mounts must be distinct narrow children of the owned invocation root"
        );
        ensure!(
            !overlaps(&source, &owned),
            "source must not overlap the writable invocation boundary"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            for path in [&owned, &work, &output] {
                let meta = fs::metadata(path)?;
                ensure!(
                    meta.uid() == self.uid && meta.gid() == self.gid && meta.mode() & 0o022 == 0,
                    "writable container directory is not privately owned by the runner UID/GID"
                );
            }
        }
        let inputs = readonly_inputs(&self.inputs, Some(&owned))?;
        let mut argv: Vec<String> = [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--platform",
            self.arch.platform(),
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user",
            &format!("{}:{}", self.uid, self.gid),
            "--memory",
            &format!("{}m", self.memory_mib),
            "--memory-swap",
            &format!("{}m", self.memory_mib),
            "--cpus",
            &self.cpus.to_string(),
            "--pids-limit",
            &self.pids_limit.to_string(),
            "--ulimit",
            "core=0:0",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,mode=1777,size=268435456",
            "--env",
            "HOME=/tmp/home",
            "--env",
            "TMPDIR=/tmp",
            "--env",
            "LANG=C",
            "--env",
            "LC_ALL=C",
            "--workdir",
            "/work",
            "--entrypoint",
            "/bin/sh",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        mount(&mut argv, &source, "/source", true);
        mount(&mut argv, &work, "/work", false);
        mount(&mut argv, &output, "/payload", false);
        for (path, dest) in inputs {
            mount(&mut argv, &path, &dest, true);
        }
        argv.extend([
            self.image.reference.clone(),
            "-c".into(),
            "mkdir -p /tmp/home && exec \"$@\"".into(),
            "relship-container".into(),
        ]);
        argv.extend(self.argv.iter().cloned());
        Ok(argv)
    }
    pub fn run(
        &self,
        runner: &mut crate::process::Commands,
        label: &str,
        host: &HostIdentity,
        observed: &ContainerImageObservation,
    ) -> Result<String> {
        runner.run(&self.argv(host, observed)?, label, &BTreeMap::new())
    }
}

#[derive(Clone, Debug)]
pub struct PackageInput {
    pub path: PathBuf,
    pub sha256: String,
}
/// Package-manager validation is separate from the non-root build contract.
/// The writable root filesystem exists only in the disposable container; the
/// host exposes exact package files read-only and no writable host directories.
#[derive(Clone, Debug)]
pub struct InstallRequest {
    pub image: ImagePin,
    pub arch: Architecture,
    pub packages: Vec<PackageInput>,
    pub inputs: Vec<ReadOnlyMount>,
    pub memory_mib: u32,
    pub cpus: u16,
    pub pids_limit: u32,
    pub argv: Vec<String>,
}
impl InstallRequest {
    pub fn argv(
        &self,
        host: &HostIdentity,
        observed: &ContainerImageObservation,
    ) -> Result<Vec<String>> {
        self.image.validate(self.arch)?;
        observed.verify(&self.image)?;
        ensure!(
            host.os == "linux"
                && host.daemon_os == "linux"
                && host.arch == self.arch
                && host.daemon_arch == self.arch,
            "package installation requires matching native Linux host, daemon and target architecture"
        );
        ensure!(
            (128..=65536).contains(&self.memory_mib)
                && (1..=64).contains(&self.cpus)
                && (32..=4096).contains(&self.pids_limit),
            "install resource limits exceed bounds"
        );
        ensure!(
            !self.packages.is_empty()
                && self.packages.len() <= 64
                && !self.argv.is_empty()
                && self.argv.len() <= 4096
                && self
                    .argv
                    .iter()
                    .all(|s| s.len() <= 128 * 1024 && !s.contains('\0')),
            "invalid install packages or command"
        );
        let mut files = Vec::new();
        let inputs = readonly_inputs(&self.inputs, None)?;
        let mut names = std::collections::BTreeSet::new();
        for package in &self.packages {
            ensure!(package.path.is_absolute(), "package path must be absolute");
            let parent = safe_host(
                package
                    .path
                    .parent()
                    .context("package path lacks a parent")?,
            )?;
            let name = package
                .path
                .file_name()
                .and_then(|v| v.to_str())
                .context("invalid package filename")?;
            crate::config::relative(name)?;
            ensure!(
                !name.contains([',', '\n', '\r', '\0'])
                    && [
                        ".deb",
                        ".rpm",
                        ".apk",
                        ".ipk",
                        ".pkg.tar.zst",
                        ".pkg.tar.xz",
                        ".pkg.tar.gz"
                    ]
                    .iter()
                    .any(|suffix| name.ends_with(suffix))
                    && names.insert(name.to_owned()),
                "unsupported, unsafe or duplicate install package filename"
            );
            let path = parent.join(name);
            let meta = fs::symlink_metadata(&path)?;
            ensure!(
                meta.is_file()
                    && !meta.file_type().is_symlink()
                    && meta.len() <= 1024 * 1024 * 1024,
                "install package must be a bounded regular file"
            );
            super::environment::digest(&format!("sha256:{}", package.sha256))?;
            ensure!(
                crate::source::file_digest(&path)? == package.sha256,
                "install package bytes differ from the expected hash"
            );
            files.push((path, format!("/packages/{name}")));
        }
        let mut argv: Vec<String> = [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--platform",
            self.arch.platform(),
            "--network=none",
            "--cap-drop=ALL",
            "--cap-add=CHOWN",
            "--cap-add=DAC_OVERRIDE",
            "--cap-add=FOWNER",
            "--cap-add=SETUID",
            "--cap-add=SETGID",
            "--cap-add=SETFCAP",
            "--security-opt=no-new-privileges",
            "--user",
            "0:0",
            "--memory",
            &format!("{}m", self.memory_mib),
            "--memory-swap",
            &format!("{}m", self.memory_mib),
            "--cpus",
            &self.cpus.to_string(),
            "--pids-limit",
            &self.pids_limit.to_string(),
            "--ulimit",
            "core=0:0",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,mode=1777,size=268435456",
            "--env",
            "HOME=/tmp/home",
            "--env",
            "TMPDIR=/tmp",
            "--env",
            "LANG=C",
            "--env",
            "LC_ALL=C",
            "--workdir",
            "/tmp",
            "--entrypoint",
            "/bin/sh",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        for (path, destination) in files {
            mount(&mut argv, &path, &destination, true);
        }
        for (path, destination) in inputs {
            mount(&mut argv, &path, &destination, true);
        }
        argv.extend([
            self.image.reference.clone(),
            "-c".into(),
            "mkdir -p /tmp/home && exec \"$@\"".into(),
            "relship-install".into(),
        ]);
        argv.extend(self.argv.iter().cloned());
        Ok(argv)
    }
    pub fn run(
        &self,
        runner: &mut crate::process::Commands,
        label: &str,
        host: &HostIdentity,
        observed: &ContainerImageObservation,
    ) -> Result<String> {
        runner.run(&self.argv(host, observed)?, label, &BTreeMap::new())
    }
}
