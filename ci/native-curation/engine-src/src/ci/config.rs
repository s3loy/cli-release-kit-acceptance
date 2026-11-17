use super::model::*;
use crate::{cohort, source};
use anyhow::{Context, Result, bail, ensure};
use std::{collections::BTreeSet, fs, path::Path};

pub fn load(path: &Path) -> Result<Config> {
    let metadata = fs::symlink_metadata(path).context("inspect CI configuration")?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= 1024 * 1024,
        "CI configuration must be a regular file of at most 1 MiB"
    );
    // TOML diagnostics include source lines. Do not expose a signed URL query
    // when reporting a malformed configuration.
    let text = fs::read_to_string(path).context("read CI configuration")?;
    ensure!(
        text.len() <= 1024 * 1024,
        "CI configuration grew beyond 1 MiB"
    );
    let config: Config = toml::from_str(&text)
        .map_err(|_| anyhow::anyhow!("invalid release-ci.toml structure or unknown field"))?;
    validate(&config)?;
    Ok(config)
}

pub fn id(config: &Config) -> Result<String> {
    validate(config)?;
    let mut bytes = b"cli-release-kit/ci-config/v1\0".to_vec();
    bytes.extend(serde_json::to_vec(config)?);
    Ok(source::digest(&bytes))
}

pub fn assert_current_engine(config: &Config) -> Result<()> {
    validate(config)?;
    ensure!(
        config.engine.version == env!("CARGO_PKG_VERSION")
            && config.engine.source_id == cohort::model::ENGINE_SOURCE_ID
            && config.engine.contract == CONTRACT,
        "CI configuration requires a different engine version, source identity or CI contract"
    );
    Ok(())
}

pub fn validate(config: &Config) -> Result<()> {
    ensure!(
        config.schema == SCHEMA,
        "unsupported release-ci.toml schema"
    );
    ensure!(
        matches!(config.execution_protocol, 3..=6),
        "CI execution-protocol must be 3, 4, 5 or 6"
    );
    ensure!(
        fixed_version(&config.engine.version),
        "engine version must be fixed"
    );
    ensure!(
        cohort::plan::is_digest(&config.engine.source_id),
        "invalid engine source identity"
    );
    ensure!(
        config.engine.contract == CONTRACT,
        "unsupported CI contract"
    );
    ensure!(
        config.execution_protocol == 6 || config.environments.is_empty(),
        "compatibility environments require execution-protocol 6"
    );
    for (target, profile) in &config.environments {
        let host = super::qualified::target_host(target)?;
        profile.validate()?;
        ensure!(
            host == format!("{}-{}", profile.os, profile.arch.name()),
            "compatibility environment target differs from its profile"
        );
    }
    ensure!(
        !config.installs.is_empty(),
        "declare engine install profiles"
    );
    for (host, install) in &config.installs {
        validate_runner_host(host, config.execution_protocol)?;
        validate_install(install)?;
    }
    validate_runner(&config.coordinator, config.execution_protocol)?;
    ensure!(
        config.coordinator.emulators.is_empty() && config.coordinator.rootfs.is_empty(),
        "coordinator cannot select runtime dependencies"
    );
    ensure!(
        config.installs.contains_key(&config.coordinator.host),
        "coordinator host has no engine install"
    );
    ensure!(!config.workers.is_empty(), "declare worker profiles");
    let mut targets = BTreeSet::new();
    for (name, worker) in &config.workers {
        ensure!(identifier(name), "invalid worker profile name");
        validate_runner(&worker.runner, config.execution_protocol)?;
        ensure!(
            config.installs.contains_key(&worker.runner.host),
            "worker host has no engine install"
        );
        ensure!(
            !worker.targets.is_empty(),
            "worker profile must select targets"
        );
        for target in &worker.targets {
            if config.execution_protocol == 5 {
                crate::catalog::resolve(target).context("invalid worker catalog target ID")?;
            } else if config.execution_protocol == 6 {
                super::qualified::target_host(target)?;
            } else {
                ensure!(valid_target_key(target), "invalid worker target key");
            }
            ensure!(
                targets.insert(target),
                "target belongs to more than one worker profile"
            );
        }
    }
    for worker in config.workers.values() {
        for target in worker.runner.rootfs.keys() {
            ensure!(
                worker.targets.contains(target),
                "runtime rootfs target is unavailable in worker profile"
            );
        }
        for emulator in worker.runner.emulators.keys() {
            ensure!(
                worker.targets.iter().any(|id| crate::catalog::resolve(id)
                    .ok()
                    .and_then(|target| crate::catalog::canonical_emulation(&target).ok())
                    .is_some_and(|(kind, _)| crate::v5::runtime::emulator_name(kind) == emulator)),
                "runtime emulator is unavailable for worker targets"
            );
        }
    }
    if config.execution_protocol == 6 {
        super::qualified::validate_profiles(config)?;
    }
    validate_branch(&config.trusted.branch)?;
    validate_literal(&config.trusted.environment, "trusted environment")?;
    ensure!(
        secret_reference(&config.trusted.signing_secret),
        "invalid signing secret reference"
    );
    ensure!(
        !config
            .trusted
            .signing_secret
            .eq_ignore_ascii_case("GITHUB_TOKEN"),
        "built-in GITHUB_TOKEN is reserved for delivery and cannot be a signing reference"
    );
    validate_literal(&config.delivery.environment, "delivery environment")?;
    let repository: Vec<_> = config.delivery.repository.split('/').collect();
    ensure!(
        repository.len() == 2 && repository.iter().all(|part| safe_segment(part)),
        "delivery repository must be owner/repository"
    );
    crate::config::relative(&config.delivery.policy).context("invalid delivery policy path")?;
    ensure!(
        safe_member(&config.delivery.policy),
        "delivery policy path must use safe ASCII segments"
    );
    if let Some(secret) = &config.delivery.token_secret {
        ensure!(
            secret_reference(secret),
            "invalid delivery token secret reference"
        );
        ensure!(
            !secret.eq_ignore_ascii_case(&config.trusted.signing_secret),
            "delivery and signing roles must use distinct secret references"
        );
    }
    for install in config.installs.values() {
        if let Some(secret) = &install.auth_secret {
            ensure!(
                !secret.eq_ignore_ascii_case(&config.trusted.signing_secret)
                    && config
                        .delivery
                        .token_secret
                        .as_ref()
                        .is_none_or(|delivery| !delivery.eq_ignore_ascii_case(secret)),
                "download, signing and delivery roles must use distinct secret references"
            );
        }
    }
    Ok(())
}

pub fn validate_install(install: &Install) -> Result<()> {
    validate_url(&install.url)?;
    ensure!(
        cohort::plan::is_digest(&install.sha256),
        "invalid engine install SHA-256"
    );
    match install.format.as_str() {
        "binary" => ensure!(
            install.member.as_deref().is_none_or(str::is_empty),
            "raw engine install must not select an archive member"
        ),
        "tar.gz" | "zip" => ensure!(
            install.member.as_deref().is_some_and(safe_member),
            "archive engine install must select a safe explicit member"
        ),
        _ => bail!("unsupported engine install format"),
    }
    if let Some(secret) = &install.auth_secret {
        ensure!(
            secret_reference(secret),
            "invalid download secret reference"
        );
        ensure!(
            !secret.eq_ignore_ascii_case("GITHUB_TOKEN"),
            "built-in GITHUB_TOKEN is reserved for delivery and cannot authenticate downloads"
        );
    }
    Ok(())
}

fn validate_url(url: &str) -> Result<()> {
    ensure!(
        !url.contains("${"),
        "engine install URL must be literal and cannot contain expressions"
    );
    ensure!(
        url.len() <= 8192
            && url.bytes().all(|b| b.is_ascii_graphic())
            && !url.contains('#')
            && !url.contains(['\\', '\'', '"']),
        "engine install URL must be HTTPS without userinfo, quotes, controls or a fragment"
    );
    let uri: ureq::http::Uri = url
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid engine install URL"))?;
    ensure!(
        uri.scheme_str() == Some("https")
            && uri.authority().is_some_and(
                |authority| !authority.as_str().contains('@') && !authority.host().is_empty()
            ),
        "engine install URL must be HTTPS without userinfo or a fragment"
    );
    Ok(())
}

fn validate_runner(runner: &Runner, protocol: u32) -> Result<()> {
    validate_runner_host(&runner.host, protocol)?;
    ensure!(
        protocol == 5 || (runner.emulators.is_empty() && runner.rootfs.is_empty()),
        "runtime dependency maps require execution-protocol 5"
    );
    for (name, path) in &runner.emulators {
        ensure!(
            matches!(name.as_str(), "qemu-arm" | "qemu-i386"),
            "unknown runtime emulator"
        );
        runtime_path(path)?;
    }
    for (target, path) in &runner.rootfs {
        crate::catalog::resolve(target)?;
        runtime_path(path)?;
    }
    rust_host(runner)?;
    ensure!(
        !runner.runs_on.is_empty() && runner.runs_on.len() <= 16,
        "runner labels must be nonempty and bounded"
    );
    let mut labels = BTreeSet::new();
    for label in &runner.runs_on {
        ensure!(
            !label.is_empty()
                && label.len() <= 100
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-/ ".contains(&b))
                && label.trim() == label
                && labels.insert(label),
            "runner labels must be unique literal strings without expressions or shell controls"
        );
    }
    for version in [&runner.rust_version, &runner.go_version]
        .into_iter()
        .flatten()
    {
        ensure!(fixed_version(version), "toolchain versions must be fixed");
    }
    if let Some(pin) = &runner.nfpm {
        ensure!(
            pin.version == crate::delivery::model::NFPM_VERSION
                && cohort::plan::is_digest(&pin.sha256),
            "nFPM requires exact version 2.49.0 and an executable SHA-256"
        );
    }
    Ok(())
}

fn validate_runner_host(host: &str, protocol: u32) -> Result<()> {
    if protocol == 5 && matches!(host, "linux-arm" | "linux-x86") {
        return Ok(());
    }
    validate_host(host)
}

fn runtime_path(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 4096
            && !value.contains("${")
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_./ :\\-".contains(&b))
            && value.trim() == value
            && !value
                .split(['/', '\\'])
                .any(|part| matches!(part, "." | "..")),
        "runtime dependency path must be a safe literal constant path"
    );
    Ok(())
}

pub fn validate_host(host: &str) -> Result<()> {
    ensure!(
        matches!(
            host,
            "linux-x86_64"
                | "linux-aarch64"
                | "macos-x86_64"
                | "macos-aarch64"
                | "windows-x86_64"
                | "windows-aarch64"
        ),
        "unsupported runner host key"
    );
    Ok(())
}

fn validate_literal(value: &str, kind: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 100
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-/ ".contains(&b))
            && value.trim() == value,
        "{kind} must be a bounded literal name"
    );
    Ok(())
}

fn validate_branch(branch: &str) -> Result<()> {
    ensure!(
        !branch.is_empty()
            && branch.len() <= 255
            && branch
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_./-".contains(&b))
            && !branch.starts_with('-')
            && !branch.ends_with('.')
            && !branch.contains("..")
            && branch
                .split('/')
                .all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock")),
        "trusted branch must be a literal Git branch name"
    );
    Ok(())
}

pub fn secret_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic() || byte == b'_' || (index > 0 && byte.is_ascii_digit())
        })
}

pub fn rust_host(runner: &Runner) -> Result<String> {
    validate_runner_host(&runner.host, 5)?;
    let (os, arch) = runner.host.split_once('-').context("invalid runner host")?;
    let suffix = match os {
        "linux" => "unknown-linux-gnu",
        "macos" => "apple-darwin",
        "windows" => "pc-windows-msvc",
        _ => unreachable!(),
    };
    let default = match (os, arch) {
        ("linux", "arm") => "armv7-unknown-linux-gnueabihf".into(),
        ("linux", "x86") => "i686-unknown-linux-gnu".into(),
        _ => format!("{arch}-{suffix}"),
    };
    let selected = runner.rust_host.as_deref().unwrap_or(&default);
    ensure!(
        selected == default
            || (os == "linux" && selected == format!("{arch}-unknown-linux-musl"))
            || (runner.host == "linux-arm"
                && matches!(
                    selected,
                    "arm-unknown-linux-gnueabi"
                        | "arm-unknown-linux-gnueabihf"
                        | "armv7-unknown-linux-gnueabi"
                        | "armv7-unknown-linux-gnueabihf"
                )),
        "rust-host must be a supported native triple matching runner host"
    );
    Ok(selected.into())
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic()
                || byte == b'_'
                || (index > 0 && (byte.is_ascii_digit() || byte == b'-'))
        })
}

fn safe_segment(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

pub fn safe_member(value: &str) -> bool {
    !value.is_empty() && value.len() <= 240 && value.split('/').all(safe_segment)
}

fn valid_target_key(value: &str) -> bool {
    for os in ["linux", "macos", "windows"] {
        for arch in ["x86_64", "aarch64"] {
            let host = format!("{os}-{arch}");
            if value == host
                || (os == "linux"
                    && ["gnu", "musl"]
                        .iter()
                        .any(|abi| value == format!("{host}-{abi}")))
                || (os == "windows" && value == format!("{host}-msvc"))
            {
                return true;
            }
        }
    }
    false
}

fn fixed_version(value: &str) -> bool {
    if value.len() > 100
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b))
    {
        return false;
    }
    let base = value.split(['-', '+']).next().unwrap_or("");
    let components: Vec<_> = base.split('.').collect();
    components.len() == 3
        && components
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        && !value.ends_with(['-', '+'])
        && !value.to_ascii_lowercase().contains("latest")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn runtime_maps_are_literal_catalog_bound_and_protocol_five_only() {
        let mut config = example();
        config.execution_protocol = 5;
        let worker = config.workers.get_mut("native").unwrap();
        worker.targets = vec!["linux-armv7-gnueabi".into()];
        worker
            .runner
            .emulators
            .insert("qemu-arm".into(), "/opt/controlled tools/qemu-arm".into());
        worker
            .runner
            .rootfs
            .insert("linux-armv7-gnueabi".into(), "/opt/rootfs/armv7".into());
        validate(&config).unwrap();
        let json = serde_json::to_string(&config).unwrap();
        assert_eq!(serde_json::from_str::<Config>(&json).unwrap(), config);
        for protocol in [3, 4] {
            let mut old = config.clone();
            old.execution_protocol = protocol;
            assert!(
                validate(&old)
                    .unwrap_err()
                    .to_string()
                    .contains("runtime dependency maps")
            );
        }
        for path in [
            "${{ secrets.TOOL }}",
            "$(touch marker)",
            "a;touch marker",
            "a'quoted",
            "../tool",
            "a\npath",
        ] {
            let mut bad = config.clone();
            bad.workers
                .get_mut("native")
                .unwrap()
                .runner
                .emulators
                .insert("qemu-arm".into(), path.into());
            assert!(validate(&bad).is_err(), "{path}");
        }
        let mut unknown = config.clone();
        unknown
            .workers
            .get_mut("native")
            .unwrap()
            .runner
            .emulators
            .insert("qemu-unknown".into(), "/opt/tool".into());
        assert!(validate(&unknown).is_err());
        let mut unavailable = config.clone();
        unavailable
            .workers
            .get_mut("native")
            .unwrap()
            .runner
            .rootfs
            .insert("linux-i686-gnu".into(), "/opt/rootfs/i686".into());
        assert!(validate(&unavailable).is_err());
        let mut absent_emulation = config.clone();
        absent_emulation.workers.get_mut("native").unwrap().targets = vec!["macos-aarch64".into()];
        absent_emulation
            .workers
            .get_mut("native")
            .unwrap()
            .runner
            .rootfs
            .clear();
        assert!(validate(&absent_emulation).is_err());
        let mut old_host = example();
        old_host.coordinator.host = "linux-arm".into();
        assert!(validate(&old_host).is_err());
        let toml = toml::to_string(&config).unwrap();
        let duplicated_toml =
            toml.replace("qemu-arm = ", "qemu-arm = '/opt/duplicate'\nqemu-arm = ");
        assert!(toml::from_str::<Config>(&duplicated_toml).is_err());
    }

    pub(crate) fn example() -> Config {
        let runner = Runner {
            runs_on: vec!["ubuntu-24.04".into()],
            host: "linux-x86_64".into(),
            rust_version: Some("1.96.0".into()),
            rust_host: None,
            go_version: Some("1.27.3".into()),
            nfpm: None,
            emulators: BTreeMap::new(),
            rootfs: BTreeMap::new(),
        };
        Config {
            schema: SCHEMA,
            execution_protocol: 3,
            environments: BTreeMap::new(),
            engine: Engine {
                version: env!("CARGO_PKG_VERSION").into(),
                source_id: cohort::model::ENGINE_SOURCE_ID.into(),
                contract: CONTRACT,
            },
            installs: BTreeMap::from([(
                "linux-x86_64".into(),
                Install {
                    url: "https://downloads.example.invalid/tool?signature=private-query".into(),
                    sha256: "a".repeat(64),
                    format: "tar.gz".into(),
                    member: Some("bin/relship".into()),
                    auth_secret: Some("ENGINE_DOWNLOAD_TOKEN".into()),
                },
            )]),
            coordinator: runner.clone(),
            workers: BTreeMap::from([(
                "native".into(),
                Worker {
                    runner,
                    targets: vec!["linux-x86_64-gnu".into()],
                },
            )]),
            trusted: Trusted {
                branch: "main".into(),
                environment: "release-rebuild".into(),
                signing_secret: "REBUILD_SIGNING_KEY".into(),
            },
            delivery: Delivery {
                repository: "example/releases".into(),
                environment: "release-delivery".into(),
                token_secret: Some("DRAFT_TOKEN".into()),
                policy: "release/trust.toml".into(),
                create_tag_if_missing: false,
            },
        }
    }

    #[test]
    fn configuration_rejects_unknown_fields_and_redacts_parse_errors() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("release-ci.toml");
        let text = toml::to_string(&example()).unwrap();
        fs::write(&path, &text).unwrap();
        assert!(load(&path).is_ok());
        fs::write(
            &path,
            text.replace("[engine]", "[engine]\nsetup = \"private-query\""),
        )
        .unwrap();
        let error = format!("{:#}", load(&path).unwrap_err());
        assert!(error.contains("unknown field"));
        assert!(!error.contains("private-query"));
        assert!(!error.contains("https://"));
    }

    #[test]
    fn install_urls_allow_queries_but_reject_credentials_and_non_https() {
        assert!(validate(&example()).is_ok());
        for url in [
            "http://example.invalid/relship",
            "https://user:secret@example.invalid/tool",
            "https://example.invalid/tool#fragment",
            "https:///tool",
            "https://example.invalid/\nsecret",
        ] {
            let mut config = example();
            config.installs.values_mut().next().unwrap().url = url.into();
            let error = format!("{:#}", validate(&config).unwrap_err());
            assert!(!error.contains("secret"));
            assert!(!error.contains(url));
        }
    }

    #[test]
    fn install_urls_are_literal_data_without_workflow_expressions_or_quotes() {
        for url in [
            "https://example.invalid/${{github.token}}",
            "https://example.invalid/tool?token=${{secrets.TOKEN}}",
            "https://example.invalid/tool?token=${TOKEN}",
            "https://example.invalid/tool?token=\"value\"",
            "https://example.invalid/tool?token='value'",
            "https://example.invalid/tool?token=\\value",
            "https://example.invalid/tool?token=\tvalue",
        ] {
            let error = validate_url(url).unwrap_err();
            if url.contains("${") {
                assert!(error.to_string().contains("cannot contain expressions"));
            }
        }
        assert!(
            validate_url(
                "https://example.invalid/tool?token=abc%2Fdef&query=$(literal);value=one+two"
            )
            .is_ok()
        );
    }

    #[test]
    fn archive_member_must_be_explicit_and_unambiguous() {
        for member in [
            "",
            ".",
            "..",
            "../relship",
            "bin/../relship",
            "/bin/relship",
            "bin//relship",
            "bin/relship*",
            "bin\\relship",
            "bin/a b",
            "bin/a\n",
        ] {
            let mut config = example();
            config.installs.values_mut().next().unwrap().member = Some(member.into());
            assert!(validate(&config).is_err(), "accepted member {member:?}");
        }
        let mut config = example();
        let install = config.installs.values_mut().next().unwrap();
        install.format = "binary".into();
        assert!(validate(&config).is_err());
        config.installs.values_mut().next().unwrap().member = None;
        assert!(validate(&config).is_ok());
    }

    #[test]
    fn role_secret_references_are_case_insensitively_distinct() {
        let mut config = example();
        config.delivery.token_secret = Some(config.trusted.signing_secret.to_ascii_lowercase());
        assert!(validate(&config).is_err());
        let mut config = example();
        config.installs.values_mut().next().unwrap().auth_secret =
            config.delivery.token_secret.clone();
        assert!(validate(&config).is_err());
        let mut config = example();
        config.installs.values_mut().next().unwrap().auth_secret =
            Some("${{ secrets.TOKEN }}".into());
        assert!(validate(&config).is_err());
    }

    #[test]
    fn default_delivery_token_cannot_be_reused_for_download_or_signing() {
        let mut config = example();
        config.delivery.token_secret = None;
        assert!(validate(&config).is_ok());
        config.installs.values_mut().next().unwrap().auth_secret = Some("GITHUB_TOKEN".into());
        assert!(
            validate(&config)
                .unwrap_err()
                .to_string()
                .contains("cannot authenticate downloads")
        );
        config.installs.values_mut().next().unwrap().auth_secret = None;
        config.trusted.signing_secret = "github_token".into();
        assert!(
            validate(&config)
                .unwrap_err()
                .to_string()
                .contains("cannot be a signing reference")
        );
    }

    #[test]
    fn literal_runner_names_and_exact_versions_are_required() {
        for version in ["latest", "stable", "1.96", "1.*.0", "^1.96.0", "1.96.0\n"] {
            let mut config = example();
            config.coordinator.rust_version = Some(version.into());
            assert!(validate(&config).is_err());
        }
        for label in [
            "${{ inputs.runner }}",
            "ubuntu; echo secret",
            "ubuntu\n",
            "",
        ] {
            let mut config = example();
            config.coordinator.runs_on = vec![label.into()];
            assert!(validate(&config).is_err());
        }
        let mut config = example();
        config.workers.get_mut("native").unwrap().runner.rust_host =
            Some("aarch64-unknown-linux-musl".into());
        assert!(validate(&config).is_err());
    }

    #[test]
    fn structural_load_can_report_another_engine_without_executing_it() {
        let mut config = example();
        config.engine.source_id = "b".repeat(64);
        assert!(validate(&config).is_ok());
        assert!(assert_current_engine(&config).is_err());
        assert_ne!(id(&config).unwrap(), id(&example()).unwrap());
    }

    #[test]
    fn optional_packager_pin_preserves_legacy_wire_and_requires_exact_identity() {
        let mut config = example();
        let legacy = serde_json::to_value(&config).unwrap();
        assert!(legacy["coordinator"].get("nfpm").is_none());
        assert!(legacy["workers"]["native"]["runner"].get("nfpm").is_none());
        let original_id = id(&config).unwrap();
        let mut explicit_null = legacy.clone();
        explicit_null["coordinator"]["nfpm"] = serde_json::Value::Null;
        assert_eq!(
            id(&serde_json::from_value(explicit_null).unwrap()).unwrap(),
            original_id
        );
        config.workers.get_mut("native").unwrap().runner.nfpm = Some(ToolPin {
            version: "2.49.0".into(),
            sha256: "a".repeat(64),
        });
        assert!(validate(&config).is_ok());
        assert_ne!(id(&config).unwrap(), original_id);
        config
            .workers
            .get_mut("native")
            .unwrap()
            .runner
            .nfpm
            .as_mut()
            .unwrap()
            .version = "2.48.0".into();
        assert!(validate(&config).is_err());
        config
            .workers
            .get_mut("native")
            .unwrap()
            .runner
            .nfpm
            .as_mut()
            .unwrap()
            .version = "2.49.0".into();
        config
            .workers
            .get_mut("native")
            .unwrap()
            .runner
            .nfpm
            .as_mut()
            .unwrap()
            .sha256 = "not-a-digest".into();
        assert!(validate(&config).is_err());
    }

    #[test]
    fn execution_protocol_defaults_to_legacy_and_is_part_of_trusted_profile_identity() {
        let mut config = example();
        let legacy = serde_json::to_value(&config).unwrap();
        assert!(legacy.get("execution-protocol").is_none());
        let original = id(&config).unwrap();
        let decoded: Config = serde_json::from_value(legacy.clone()).unwrap();
        assert_eq!(decoded.execution_protocol, 3);
        assert_eq!(id(&decoded).unwrap(), original);
        let mut explicit = legacy;
        explicit["execution-protocol"] = 3.into();
        assert_eq!(
            id(&serde_json::from_value(explicit).unwrap()).unwrap(),
            original
        );
        config.execution_protocol = 4;
        assert!(validate(&config).is_ok());
        assert_ne!(id(&config).unwrap(), original);
        for invalid in [0, 1, 2, 6] {
            config.execution_protocol = invalid;
            assert!(validate(&config).is_err());
        }
    }
}
