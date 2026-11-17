"""Capture explicit Rust components without accepting SDK drift for builds."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import sys

ROOT = Path.cwd()
HOST = os.environ['NATIVE_HOST']
OUT = Path(os.environ['RUNNER_TEMP']) / 'relship-sdk-stability'
OUT.mkdir(exist_ok=False)
sys.dont_write_bytecode = True
loader = importlib.util.spec_from_file_location('capture_helper', ROOT / 'ci/native-curation/curate.py')
helper = importlib.util.module_from_spec(loader)
loader.loader.exec_module(helper)
helper.OUTPUT = OUT
spec = json.loads((ROOT / 'ci/sdk-stability/inputs.json').read_text())['hosts'][HOST]
artifact = Path(os.environ['RUNNER_TEMP']) / 'relship-sdk-inspector'

try:
    host_os = {'Darwin': 'macos', 'Windows': 'windows'}[platform.system()]
    host_arch = {'amd64': 'x86_64', 'x86_64': 'x86_64', 'arm64': 'aarch64', 'aarch64': 'aarch64'}[platform.machine().lower()]
    assert HOST == host_os + '-' + host_arch
    engine = artifact / spec['engine_filename']
    assert helper.sha(engine) == spec['engine_sha256']
    assert helper.sha(artifact / 'sdk-candidate.json') == spec['sdk_json_sha256']
    engine.chmod(0o755)
    info = json.loads(helper.run('inspector-identity', [engine, 'build-info', '--json', '--expect-source-id', spec['engine_source_id']]))
    assert info['target'] == spec['rust_host']
    expected = json.loads((artifact / 'sdk-candidate.json').read_text())
    toolchain = '1.96.0-' + spec['rust_host']
    rustup = shutil.which('rustup')
    assert rustup
    helper.run('provision-explicit-components', [rustup, 'toolchain', 'install', toolchain, '--profile', 'minimal', '--component', 'rustfmt,clippy', '--no-self-update'], timeout=300)
    components = helper.run('installed-components', [rustup, 'component', 'list', '--toolchain', toolchain, '--installed'])
    assert 'rustfmt-' in components and 'clippy-' in components
    environment = os.environ.copy()
    environment.update(expected['environment'])
    command = [engine, 'ci', 'inspect-sdk', '--id', expected['sdk_id'], '--version', expected['sdk_version']]
    for root in expected['roots']:
        command.extend(['--root', root])
    for tool in expected['tool_sha256']:
        command.extend(['--tool', tool])
    actual = json.loads(helper.run('inspect-explicit-sdk', command, env=environment, timeout=600))
    helper.save('sdk-candidate.json', actual)
    changed = [root for root in set(expected['roots']) | set(actual['roots']) if expected['roots'].get(root) != actual['roots'].get(root)]
    helper.save('capture.json', {'host': HOST, 'platform': platform.platform(), 'runner_image_version': os.environ.get('ImageVersion'), 'run_id': os.environ['GITHUB_RUN_ID'], 'source_commit': os.environ['GITHUB_SHA'], 'inspector_sha256': spec['engine_sha256'], 'inspector_source_id': spec['engine_source_id'], 'components': components.splitlines(), 'changed_roots': sorted(changed), 'tool_bytes_unchanged': actual['tool_sha256'] == expected['tool_sha256'], 'sdk_environment_unchanged': actual['environment'] == expected['environment'], 'candidate_only': True, 'consumer_qualification': False, 'publication_ready': False})
    assert actual['tool_sha256'] == expected['tool_sha256']
    assert actual['environment'] == expected['environment']
except Exception as error:
    helper.save('failure.json', {'host': HOST, 'type': type(error).__name__, 'message': str(error), 'publication_ready': False})
    raise
