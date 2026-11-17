"""Run native candidate package checks with an independently pinned test engine."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import tomllib

ROOT = Path.cwd()
HOST = os.environ["NATIVE_HOST"]
OUT = Path(os.environ["RUNNER_TEMP"]) / "relship-native-consumer"
OUT.mkdir(exist_ok=False)
LOGS = OUT / "logs"
LOGS.mkdir()


def run(name, command, *, environment=None, timeout=1800):
    print(f"native consumer: {name}", flush=True)
    started = time.monotonic()
    with (LOGS / (name + ".stdout")).open("wb") as stdout, (LOGS / (name + ".stderr")).open("wb") as stderr:
        try:
            result = subprocess.run([str(v) for v in command], env=environment, stdout=stdout, stderr=stderr, timeout=timeout)
        except subprocess.TimeoutExpired:
            (LOGS / (name + ".timeout.json")).write_text(json.dumps({"timeout_seconds": timeout}) + "\n")
            raise
    (LOGS / (name + ".command.json")).write_text(json.dumps({"argv": [str(v) for v in command], "exit_code": result.returncode, "elapsed_seconds": round(time.monotonic() - started, 3)}, indent=2) + "\n")
    if result.returncode:
        detail = (LOGS / (name + ".stderr")).read_text(errors="replace")[-12000:]
        raise RuntimeError(f"{name} failed ({result.returncode}): {detail}")
    return (LOGS / (name + ".stdout")).read_text()


try:
    expected = json.loads((ROOT / "ci/native-consumer/bootstrap.json").read_text())
    spec = expected["hosts"][HOST]
    host_os = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}[platform.system()]
    host_arch = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}[platform.machine().lower()]
    assert HOST == host_os + "-" + host_arch
    sys.dont_write_bytecode = True
    loader = importlib.util.spec_from_file_location("frozen_bootstrap", ROOT / "ci/native-curation/curate.py")
    frozen = importlib.util.module_from_spec(loader)
    loader.loader.exec_module(frozen)
    frozen.OUTPUT = OUT / "bootstrap-records"
    frozen.OUTPUT.mkdir()
    assert frozen.frozen_inputs()["engine_source_id"] == expected["engine_source_id"]
    rustup = shutil.which("rustup")
    assert rustup
    toolchain = "1.96.0-" + spec["rust_host"]
    run("provision-exact-rust", [rustup, "toolchain", "install", toolchain, "--profile", "minimal", "--no-self-update"], timeout=300)
    settings = tomllib.loads((ROOT / "release-ci.toml").read_text())
    environment = os.environ.copy()
    if HOST in settings["environments"]:
        environment.update(settings["environments"][HOST]["environment"]["sdk"]["environment"])
    environment["CARGO_TARGET_DIR"] = str(OUT / "bootstrap-target")
    run("build-engine", [rustup, "run", toolchain, "cargo", "build", "--manifest-path", frozen.SOURCE / "Cargo.toml", "--locked", "--release", "--bin", "relship"], environment=environment, timeout=1200)
    engine = OUT / "bootstrap-target/release" / spec["engine_filename"]
    info = json.loads(run("engine-identity", [engine, "build-info", "--json", "--expect-source-id", expected["engine_source_id"]]))
    assert info["target"] == spec["rust_host"]
    (OUT / "engine-artifact.json").write_text(json.dumps({"sha256": hashlib.sha256(engine.read_bytes()).hexdigest(), "build_info": info, "bootstrap": "reviewed-frozen-source"}, indent=2) + "\n")
    source = run("source", ["git", "rev-parse", "HEAD"]).strip()
    assert source == os.environ["GITHUB_SHA"]
    plan = OUT / "plan.json"
    run("plan", [engine, "plan", "--output", plan])
    graph = json.loads(plan.read_text())
    assert graph["schema"] == 6 and graph["engine_source_id"] == expected["engine_source_id"]
    job = OUT / "job"
    run("qualified-candidate", [engine, "ci", "qualified-run", "--config", "release-ci.toml", "--plan", plan, "--profile", HOST, "--expected-source", source, "--role", "candidate", "--output", job], timeout=2100)
    receipt = json.loads((job / "receipt.json").read_text())
    assert receipt["complete"] and not receipt["publication_ready"] and not receipt["failures"]
    source_files = subprocess.check_output(["git", "status", "--porcelain"], text=True)
    assert not source_files, source_files
    # Exported records must survive loss of the original build/source invocations.
    shutil.move(job / "invocations", OUT / "unavailable-invocations")
    environment = {"PATH": ""}
    if os.name == "nt":
        environment["SystemRoot"] = os.environ["SystemRoot"]
    run("offline-verify", [engine, "--project", OUT / "no-source", "verify", "--output", job / "result"], environment=environment)
    summary = {"host": HOST, "source_commit": source, "engine_source_id": expected["engine_source_id"], "selected_builds": receipt["selected"], "packages": receipt["packages"], "validation_count": len(receipt["validations"]), "complete": True, "publication_ready": False, "scope": "Native qualified candidate builds, final package runtime/install checks and offline verification; controlled URL installation and protected sealing are separate."}
    (OUT / "acceptance.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"host": HOST, "packages": len(receipt["packages"]), "validations": len(receipt["validations"]), "complete": True}), flush=True)
except Exception as error:
    (OUT / "failure.json").write_text(json.dumps({"host": HOST, "type": type(error).__name__, "message": str(error), "complete": False}, indent=2) + "\n")
    raise
