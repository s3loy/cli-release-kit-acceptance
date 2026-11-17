//! Signed CentOS 7 Perl supplement, staged without installing into the image.
use super::{Architecture, ToolInput};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const PINS: &str = include_str!("perl-pins.json");
const PREFIX: &str = "/work/perl-dependencies";

/// Source-bound package, key, and repository metadata pins.
pub fn pins_json() -> &'static str {
    PINS
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value[name]
        .as_str()
        .with_context(|| format!("missing Perl supplement pin field {name}"))
}

fn profile(arch: Architecture) -> Result<Value> {
    let pins: Value = serde_json::from_str(PINS)?;
    ensure!(pins["schema"] == 1, "unsupported Perl supplement schema");
    let pin = pins["profiles"][arch.name()].clone();
    ensure!(
        field(&pin, "architecture")? == arch.name(),
        "Perl supplement architecture differs"
    );
    let packages = pin["packages"]
        .as_array()
        .context("missing Perl RPM pins")?;
    ensure!(
        packages.len() == 19,
        "Perl supplement requires the frozen 19-package closure"
    );
    let keys = pin["keys"]
        .as_array()
        .context("missing Perl signing key pins")?;
    let key_ids: BTreeSet<_> = keys
        .iter()
        .map(|key| field(key, "key_id"))
        .collect::<Result<_>>()?;
    let forbidden = [
        "perl",
        "perl-libs",
        "glibc",
        "glibc-common",
        "glibc-devel",
        "gcc",
        "gcc-c++",
        "binutils",
        "rpm",
        "cpio",
    ];
    let mut names = BTreeSet::new();
    for package in packages {
        let name = field(package, "name")?;
        ensure!(
            !forbidden.contains(&name) && names.insert(name),
            "Perl supplement replaces a base tool or duplicates a package"
        );
        let package_arch = field(package, "arch")?;
        ensure!(
            package_arch == "noarch" || package_arch == arch.name(),
            "Perl RPM has the wrong architecture"
        );
        ensure!(
            key_ids.contains(field(package, "key_id")?),
            "Perl RPM has no pinned signing key"
        );
    }
    for module in ["IPC::Cmd", "Time::Piece", "Time::Seconds"] {
        ensure!(
            pin["probe_modules"]
                .as_array()
                .context("missing Perl module probes")?
                .iter()
                .any(|value| value == module),
            "Perl supplement omits required module {module}"
        );
    }
    Ok(pin)
}

fn raw(item: &Value, version: String) -> Result<ToolInput> {
    let input = ToolInput::Raw {
        name: field(item, "input_name")?.into(),
        version,
        url: field(item, "url")?.into(),
        sha256: field(item, "sha256")?.into(),
        filename: field(item, "filename")?.into(),
    };
    super::validate_tool_input(&input)?;
    Ok(input)
}

/// All RPMs, signing keys, and repository metadata are independent raw inputs.
pub fn inputs(arch: Architecture) -> Result<Vec<ToolInput>> {
    let pin = profile(arch)?;
    let mut inputs = Vec::new();
    for package in pin["packages"]
        .as_array()
        .context("missing Perl RPM pins")?
    {
        inputs.push(raw(package, field(package, "nvra")?.into())?);
    }
    for key in pin["keys"]
        .as_array()
        .context("missing Perl signing keys")?
    {
        inputs.push(raw(key, field(key, "primary_fingerprint")?.into())?);
    }
    for metadata in pin["metadata"]
        .as_array()
        .context("missing Perl repository metadata")?
    {
        for kind in ["repomd", "primary"] {
            inputs.push(raw(
                &serde_json::json!({
                    "input_name": metadata[format!("{kind}_input_name")],
                    "url": metadata[format!("{kind}_url")],
                    "sha256": metadata[format!("{kind}_sha256")],
                    "filename": metadata[format!("{kind}_filename")],
                }),
                "CentOS-7.9.2009".into(),
            )?);
        }
    }
    let names: BTreeSet<_> = inputs
        .iter()
        .filter_map(|input| match input {
            ToolInput::Raw { name, .. } => Some(name),
            _ => None,
        })
        .collect();
    ensure!(names.len() == inputs.len(), "duplicate Perl input names");
    Ok(inputs)
}

/// This environment only adds Perl module lookup paths in the owned prefix.
pub fn environment() -> BTreeMap<String, String> {
    [(
        "PERL5LIB".into(),
        [
            "usr/share/perl5/vendor_perl",
            "usr/share/perl5",
            "usr/lib64/perl5/vendor_perl",
            "usr/lib64/perl5",
        ]
        .map(|relative| format!("{PREFIX}/{relative}"))
        .join(":"),
    )]
    .into()
}

/// A single offline command. Acquired raw trees mount at `/inputs/{name}`;
/// only `/work/perl-bootstrap` and `/work/perl-dependencies` are written.
pub fn bootstrap_commands(arch: Architecture) -> Result<Vec<Vec<String>>> {
    inputs(arch)?;
    Ok(vec![vec![
        "python3".into(),
        "-c".into(),
        bootstrap_script().into(),
        serde_json::to_string(&profile(arch)?)?,
    ]])
}

/// Embedded in the executable so bootstrap behavior is part of source binding.
pub fn bootstrap_script() -> &'static str {
    r#"from pathlib import Path
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time

pin = json.loads(sys.argv[1])
assert platform.machine() == pin['architecture'], 'Perl supplement architecture differs from native runner'
work = Path('/work/perl-bootstrap')
prefix = Path('/work/perl-dependencies')
assert not work.exists() and not prefix.exists(), 'use a fresh owned work directory for Perl bootstrap'
work.mkdir()
logs = work / 'logs'
logs.mkdir()
env = os.environ.copy()
env.update({'LC_ALL': 'C', 'TZ': 'UTC', 'PERL5LIB': ':'.join(str(prefix / relative) for relative in pin['perl5lib'])})
commands = []
deadline = time.monotonic() + 1200

def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()

def dump(name, value):
    (work / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

def run(name, argv, cwd=None, stdin_path=None, stdout_path=None):
    budget = min(300, deadline - time.monotonic())
    assert budget > 0, 'Perl bootstrap time budget exhausted'
    output = stdout_path or logs / (name + '.stdout')
    error = logs / (name + '.stderr')
    started = time.monotonic()
    timed_out = False
    with output.open('wb') as stdout, error.open('wb') as stderr, (stdin_path or Path('/dev/null')).open('rb') as stdin:
        proc = subprocess.Popen([str(arg) for arg in argv], cwd=cwd, env=env, stdin=stdin, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            code = proc.wait(timeout=budget)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                code = proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                code = proc.wait()
    commands.append({'name': name, 'argv': [str(arg) for arg in argv], 'cwd': str(cwd) if cwd else None, 'exit_code': code, 'timed_out': timed_out, 'seconds': round(time.monotonic() - started, 3), 'stdout': str(output.relative_to(work)), 'stderr': str(error.relative_to(work))})
    dump('commands.json', commands)
    print(name + ' exit=' + str(code), flush=True)
    if code != 0 or timed_out:
        sys.stderr.write(error.read_text(errors='replace')[-16384:])
        raise RuntimeError(name + ' failed; first stdout/stderr retained in ' + str(logs))
    if stdout_path is None:
        assert output.stat().st_size <= 16 * 1024 * 1024, 'Perl bootstrap text output exceeds bound'
        return output.read_text(errors='replace')
    return ''

def raw(item):
    path = Path('/inputs') / item['input_name'] / item['filename']
    assert path.is_file() and not path.is_symlink(), 'raw Perl input must be a regular file'
    assert sha(path) == item['sha256'], 'raw Perl input differs from pin: ' + item['filename']
    if 'size' in item:
        assert path.stat().st_size == item['size'], 'raw Perl input size differs from pin'
    return path

packages = pin['packages']
forbidden = {'perl', 'perl-libs', 'glibc', 'glibc-common', 'glibc-devel', 'gcc', 'gcc-c++', 'binutils', 'rpm', 'cpio'}
assert len(packages) == 19 and len({item['name'] for item in packages}) == 19
assert not any(item['name'] in forbidden for item in packages), 'do not replace image tools or base libraries'
assert all(item['arch'] in ('noarch', pin['architecture']) for item in packages), 'RPM architecture differs'
files = [raw(item) for item in packages]
keys = [raw(item) for item in pin['keys']]
for metadata in pin['metadata']:
    for kind in ('repomd', 'primary'):
        raw({key: metadata[kind + '_' + key] for key in ('input_name', 'filename', 'sha256')})
tools = {name: Path(shutil.which(name) or '') for name in ('rpm', 'rpm2cpio', 'cpio', 'perl')}
assert all(path.is_file() for path in tools.values()), 'pinned image lacks required RPM/CPIO/Perl tools'
tool_hashes = {name: {'resolved_path': str(path.resolve()), 'sha256': sha(path.resolve())} for name, path in tools.items()}
run('rpm-version', [tools['rpm'], '--version'])
run('cpio-version', [tools['cpio'], '--version'])
for name in ('rpm2cpio', 'cpio'):
    provider = run(name + '-provider', [tools['rpm'], '--query', '--file', tools[name]])
    assert provider.strip() == pin['image_tools'][name + '_provider'], 'image tool provider differs from frozen baseline'
installed = run('image-package-names', [tools['rpm'], '--query', '--all', '--qf', '%{NAME}\n'])
assert not {item['name'] for item in packages}.intersection(installed.splitlines()), 'supplement would replace an installed package'
key_db = work / 'rpm-signature-db'
key_db.mkdir()
run('rpm-key-db-init', [tools['rpm'], '--dbpath', key_db, '--initdb'])
for index, key in enumerate(keys):
    run('rpm-key-import-' + str(index), [tools['rpm'], '--dbpath', key_db, '--import', key])
for index, (path, package) in enumerate(zip(files, packages)):
    observed = run('rpm-package-signature-' + str(index), [tools['rpm'], '--dbpath', key_db, '--checksig', '--verbose', path])
    signatures = [line for line in observed.splitlines() if 'Signature' in line]
    assert signatures and all(re.search(r'Signature.*key ID ' + package['key_id'] + r':\s+OK\s*$', line, re.IGNORECASE) for line in signatures), 'RPM signature does not match its pinned key: ' + path.name
identities = run('rpm-package-identities', [tools['rpm'], '--dbpath', key_db, '--query', '--package', '--qf', '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n'] + files)
assert sorted(identities.splitlines()) == sorted(item['nvra'] for item in packages), 'RPM identity differs from pin'
run('rpm-package-requires', [tools['rpm'], '--dbpath', key_db, '--query', '--package', '--requires'] + files)
run('rpm-package-provides', [tools['rpm'], '--dbpath', key_db, '--query', '--package', '--provides'] + files)
real_db = Path('/var/lib/rpm')
def database_inventory():
    return [{'path': path.name, 'sha256': sha(path), 'size': path.stat().st_size} for path in sorted(real_db.iterdir()) if path.is_file() and not path.name.startswith(('__db.', 'log.')) and path.name != '.rpm.lock']
before = database_inventory()
dependency_db = work / 'rpm-dependency-db'
shutil.copytree(real_db, dependency_db, ignore=shutil.ignore_patterns('__db.*', '.rpm.lock', 'log.*'))
for index, key in enumerate(keys):
    run('rpm-dependency-key-import-' + str(index), [tools['rpm'], '--dbpath', dependency_db, '--import', key])
run('rpm-image-provides', [tools['rpm'], '--dbpath', dependency_db, '--query', '--all', '--provides'])
sizes = run('rpm-package-installed-sizes', [tools['rpm'], '--dbpath', key_db, '--query', '--package', '--qf', '%{SIZE}\n'] + files)
size_rows = [int(value) for value in sizes.splitlines()]
assert len(size_rows) == len(packages) and all(value > 0 for value in size_rows)
file_names = run('rpm-package-file-names', [tools['rpm'], '--dbpath', key_db, '--query', '--package', '--list'] + files)
space = os.statvfs(work)
space_check = {'available_bytes': space.f_bavail * space.f_frsize, 'required_bytes': 2 * sum(size_rows) + 4 * 1024 * 1024, 'available_inodes': space.f_favail, 'required_inodes': 2 * len(file_names.splitlines()) + len(packages) + 32, 'inode_accounting': space.f_files != 0}
dump('space.json', space_check)
assert space_check['available_bytes'] >= space_check['required_bytes'], 'insufficient owned output bytes'
assert not space_check['inode_accounting'] or space_check['available_inodes'] >= space_check['required_inodes'], 'insufficient owned output inodes'
# Only this dry-run ignores hypothetical installation space on the read-only root.
run('rpm-requires-test', [tools['rpm'], '--noplugins', '--dbpath', dependency_db, '--install', '--test', '--ignoresize', '--noscripts', '--notriggers'] + files)
assert database_inventory() == before, 'real image RPM database changed'
prefix.mkdir()
payloads = []
for index, path in enumerate(files):
    payload = work / ('perl-rpm-' + str(index) + '.cpio')
    run('rpm-to-cpio-' + str(index), [tools['rpm2cpio'], path], stdout_path=payload)
    listing = run('cpio-list-' + str(index), [tools['cpio'], '--list', '--quiet'], stdin_path=payload)
    for name in listing.splitlines():
        member = Path(name)
        assert not member.is_absolute() and '..' not in member.parts and member.parts and member.parts[0] in ('usr', '.'), 'unsafe CPIO member: ' + name
    run('cpio-extract-' + str(index), [tools['cpio'], '--extract', '--make-directories', '--no-absolute-filenames', '--no-preserve-owner', '--preserve-modification-time', '--quiet'], cwd=prefix, stdin_path=payload)
    payloads.append({'package': path.name, 'cpio_sha256': sha(payload)})
for path in prefix.rglob('*'):
    if path.is_symlink():
        assert path.resolve().is_relative_to(prefix.resolve()), 'dependency symlink escapes owned prefix'
perl_code = '''use strict; use warnings;
die "unexpected Perl interpreter" unless $^V eq v5.16.3;
for my $module (@ARGV) {
    eval "require $module; 1" or die $@;
    (my $file = $module) =~ s{::}{/}g;
    $file .= '.pm';
    my $version = eval { $module->VERSION } // '';
    print join("\\t", 'MODULE', $module, $version, $INC{$file}), "\\n";
}
my $gcc = IPC::Cmd::can_run('gcc') or die "IPC::Cmd cannot locate gcc";
print "COMPILER\\t$gcc\\n";
'''
probe = run('perl-dependency-probe', [tools['perl'], '-e', perl_code] + pin['probe_modules'])
loaded = []
for line in probe.splitlines():
    values = line.split('\t')
    if values[0] == 'MODULE':
        assert len(values) == 4 and Path(values[3]).resolve().is_relative_to(prefix.resolve()), 'Perl module loaded outside the owned prefix: ' + line
        loaded.append({'module': values[1], 'version': values[2], 'path': values[3], 'sha256': sha(Path(values[3]))})
assert sorted(item['module'] for item in loaded) == sorted(pin['probe_modules']), 'required Perl module probe missing'
assert all(sha(path.resolve()) == tool_hashes[name]['sha256'] for name, path in tools.items()), 'image tool changed'
assert database_inventory() == before, 'real image RPM database changed'
inventory = [{'path': path.relative_to(prefix).as_posix(), 'sha256': sha(path), 'size': path.stat().st_size, 'mode': oct(path.stat().st_mode & 0o777)} for path in sorted(prefix.rglob('*')) if path.is_file()]
dump('evidence.json', {'scope': 'signed Perl build-tool RPM payloads staged in an owned prefix; no image package installation', 'architecture': pin['architecture'], 'packages': packages, 'keys': pin['keys'], 'metadata': pin['metadata'], 'signature_check_passed': True, 'copied_database_requires_test_passed': True, 'image_database_unchanged': True, 'owned_output_space_check': space_check, 'image_database_snapshot': before, 'image_tools_unchanged': tool_hashes, 'perl_version': '5.16.3', 'perl5lib': env['PERL5LIB'], 'loaded_modules': loaded, 'payloads': payloads, 'prefix_inventory': inventory})
"#
}
