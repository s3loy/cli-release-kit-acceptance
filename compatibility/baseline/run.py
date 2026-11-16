#!/usr/bin/env python3
"""Run only the frozen native x86_64 baseline experiment."""
import argparse
import ast
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import traceback

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
OUT = Path(os.environ.get("BASELINE_OUT", "/tmp/relship-baseline")).resolve()
PINS = {p["name"]: p for p in json.loads((HERE / "image-pins.json").read_text())}
PYTHON = "/opt/python/cp312-cp312/bin/python3.12"
OWNED = set()
COMMANDS = []
OWNER = os.environ.setdefault("BASELINE_OWNER", "baseline-" + str(os.getpid()))
DEADLINE = None


def sha(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def dump(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def command(name, argv, timeout=300, env=None, required=True):
    if DEADLINE is not None:
        timeout = min(timeout, DEADLINE - time.monotonic())
        if timeout <= 0:
            raise TimeoutError("Shared experiment time budget exhausted before " + name)
    logs = OUT / "controller-logs"
    logs.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    with (logs / (name + ".stdout")).open("wb") as stdout, (logs / (name + ".stderr")).open("wb") as stderr:
        process = subprocess.Popen([str(a) for a in argv], env=env, stdout=stdout,
                                   stderr=stderr, start_new_session=True)
        expired = False
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            expired = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            code = process.wait()
    record = {"name": name, "argv": [str(a) for a in argv], "exit": code,
              "timed_out": expired, "elapsed": round(time.monotonic() - start, 3),
              "stdout_sha256": sha(logs / (name + ".stdout")),
              "stderr_sha256": sha(logs / (name + ".stderr"))}
    COMMANDS.append(record)
    dump(OUT / "commands.json", COMMANDS)
    if code or expired:
        print("Command " + name + " exited " + str(code)
              + (" after timeout" if expired else "") + "; original logs retained", flush=True)
        tail = (logs / (name + ".stderr")).read_text(errors="replace").splitlines()[-20:]
        if tail:
            print("\n".join(tail), file=sys.stderr, flush=True)
    if required and (code or expired):
        raise RuntimeError(name + " failed; inspect controller-logs")
    return code, (logs / (name + ".stdout")).read_text(errors="replace")


def cleanup():
    # Descendant drivers use the same label, including after a host-side timeout.
    errors = []
    try:
        listed = subprocess.run(["docker", "ps", "-aq", "--filter", "label=relship.baseline.owner=" + OWNER],
                                capture_output=True, text=True, timeout=15, check=False)
        if listed.returncode:
            errors.append({"operation": "list-owned-containers", "exit": listed.returncode,
                           "stderr": listed.stderr})
        else:
            OWNED.update(line for line in listed.stdout.splitlines() if re.fullmatch(r"[0-9a-f]+", line))
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append({"operation": "list-owned-containers", "error": str(exc)})
    if OWNED:
        try:
            removed = subprocess.run(["docker", "rm", "-f", *sorted(OWNED)],
                                     capture_output=True, text=True, timeout=45, check=False)
            # Auto-removed containers can remain in OWNED; other errors remain failures.
            unexpected = [line for line in removed.stderr.splitlines()
                          if "No such container:" not in line]
            if removed.returncode and (unexpected or not removed.stderr.strip()):
                errors.append({"operation": "remove-owned-containers", "exit": removed.returncode,
                               "stderr": "\n".join(unexpected)})
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append({"operation": "remove-owned-containers", "error": str(exc)})
    OWNED.clear()
    return errors


def native():
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("Native Linux x86_64 is required; local emulation is excluded")
    _, arch = command("docker-architecture", ["docker", "info", "--format", "{{.Architecture}}"])
    if arch.strip() not in ("x86_64", "amd64"):
        raise RuntimeError("Docker daemon is not native x86_64")
    dump(OUT / "native-host.json", {"system": platform.system(), "machine": platform.machine(),
         "kernel": platform.release(), "docker_architecture": arch.strip(),
         "python_version": sys.version, "python_sha256": sha(Path(sys.executable).resolve()),
         "host_uid": os.getuid(), "host_gid": os.getgid(),
         "container_user": str(os.getuid()) + ":" + str(os.getgid()),
         "runner_image": {k: os.environ.get(k) for k in ("ImageOS", "ImageVersion", "RUNNER_ARCH")},
         "containers_share_kernel": True, "minimum_cpu_kernel_qualified": False})


def image(name):
    return PINS[name]["reference"]


def pull(names):
    for name in names:
        ref = image(name)
        command("pull-" + name, ["docker", "pull", "--platform", "linux/amd64", ref], timeout=600)
        _, info = command("image-" + name, ["docker", "image", "inspect", ref])
        obj = json.loads(info)[0]
        if obj["Architecture"] != "amd64" or obj["Os"] != "linux" or obj["Id"] != PINS[name]["config_digest"]:
            raise RuntimeError("Pulled image identity mismatch: " + name)
    dump(OUT / "image-pins.json", [PINS[n] for n in names])


def docker(name, ref, argv, mounts=(), env=None, network="none", detach=False):
    owned = "baseline-" + name + "-" + str(os.getpid())
    OWNED.add(owned)
    cmd = ["docker", "run", "--name", owned, "--platform", "linux/amd64",
           "--user", str(os.getuid()) + ":" + str(os.getgid()), "--env", "HOME=/tmp",
           "--label", "relship.baseline.owner=" + OWNER,
           "--network", network, "--read-only", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges", "--cpus", "2", "--memory", "2g",
           "--pids-limit", "512", "--tmpfs", "/tmp:rw,nosuid,size=512m"]
    cmd += ["--detach"] if detach else ["--rm"]
    for host, guest, readonly in mounts:
        cmd += ["--mount", "type=bind,src=" + str(host) + ",dst=" + str(guest) + (",readonly" if readonly else "")]
    for key, value in (env or {}).items():
        cmd += ["--env", key + "=" + str(value)]
    cmd += [ref] + [str(a) for a in argv]
    return owned, cmd


def runtime_identity(label, ref):
    _, cmd = docker("identity-" + label, ref,
        ["/bin/sh", "-ec", "uname -a; getconf GNU_LIBC_VERSION; cat /etc/os-release"])
    _, text = command("runtime-" + label, cmd)
    expected = {"runtime217": "glibc 2.17", "runtime231": "glibc 2.31",
                "runtime239": "glibc 2.39"}[label]
    if expected not in text.splitlines():
        raise RuntimeError("Runtime libc differs from selected pin: " + label)


def build(name, harness, inputs, out, entry, extra=()):
    out.mkdir(parents=True, exist_ok=True)
    _, cmd = docker(name, image("build217"), entry,
        [(harness, "/case", True), (inputs, "/inputs", True), (out, "/out", False)] + list(extra),
        {"INPUTS_ROOT": "/inputs", "CASE_OUT": "/out", "CASE_PYTHON": PYTHON,
         "BASELINE_IMAGE": image("build217"), "JOBS": "2", "PYTHONDONTWRITEBYTECODE": "1"})
    return command("build-" + name, cmd, timeout=2400, required=False)[0]


def prepare_download(pin, root):
    root.mkdir(parents=True, exist_ok=True)
    path = root / pin["filename"]
    if not path.exists():
        partial = path.with_name(path.name + ".part")
        command("download-" + pin["filename"],
            ["curl", "--fail", "--location", "--silent", "--show-error", "--connect-timeout", "20",
             "--max-time", "600", "--output", partial, pin["url"]], timeout=610)
        if sha(partial) != pin["sha256"]:
            raise RuntimeError("Download SHA256 mismatch: " + pin["filename"])
        partial.rename(path)
    if sha(path) != pin["sha256"]:
        raise RuntimeError("Existing input SHA256 mismatch: " + pin["filename"])
    return path


def base_environment():
    # A pinned image is checked on the native runner before any consumer command.
    _, cmd = docker("build-inventory", image("build217"),
        ["/bin/bash", "-ec", "test \"$(uname -m)\" = x86_64; "
         "getconf GNU_LIBC_VERSION; "
         "test \"$(getconf GNU_LIBC_VERSION)\" = 'glibc 2.17'; "
         + PYTHON + " --version; gcc --version; ld --version; readelf --version; "
         "make --version; git --version; rpm -qa | sort"])
    command("build-environment", cmd)
    for label in ("runtime217", "runtime231", "runtime239"):
        runtime_identity(label, image(label))


def go_case():
    harness = HERE / "g-pure/harness"
    inputs, out = OUT / "go-inputs", OUT / "go-case"
    pins = json.loads((harness / "input-pins.json").read_text())
    for pin in (pins["source"], pins["sdk"]):
        prepare_download(pin, inputs)
    if build("go", harness, inputs, out, ["/bin/bash", "/case/build-in-container.sh"]):
        return False
    env = os.environ.copy()
    env.update(CASE_OUT=str(out), INPUTS_ROOT=str(inputs), BASELINE_IMAGE=image("build217"))
    for stage in ("collect-build", "package"):
        command("go-" + stage, [sys.executable, harness / "native-case.py", stage], env=env)
    passed = True
    for key, label in (("runtime217", "glibc-2.17"), ("runtime231", "glibc-2.31"),
                       ("runtime239", "glibc-2.39")):
        code, _ = command("go-" + key,
             [sys.executable, harness / "native-case.py", "runtime", "--label", label, "--image", image(key)],
             env=env, timeout=330, required=False)
        passed = passed and code == 0
    return passed


def c_case():
    case = HERE / "c-native"
    inputs, out = OUT / "c-inputs", OUT / "c-case"
    command("c-inputs", [sys.executable, case / "scripts/fetch_inputs.py", inputs], timeout=1800)
    if build("c", case, inputs, out, ["/bin/bash", "/case/scripts/build.sh"]):
        return False
    package = json.loads((out / "evidence/package.json").read_text())
    binary = out / package["extracted_executable"]
    if sha(binary) != package["executable_sha256"]:
        raise RuntimeError("Final curl bytes differ from package record")
    tls = OUT / "c-tls-fixture"
    command("c-tls-fixture", [sys.executable, case / "scripts/generate_fixture.py", tls])
    results = []
    for label in ("runtime217", "runtime231", "runtime239"):
        resultdir = out / "runtime" / label
        resultdir.mkdir(parents=True, exist_ok=True)
        name, cmd = docker("curl-" + label, image(label),
            ["/bin/sh", "-c", "while :; do sleep 3600; done"],
            [(binary.parent, binary.parent, True), (tls, tls, True),
             (resultdir, resultdir, False)], network="host", detach=True)
        command("curl-start-" + label, cmd)
        try:
            env = os.environ.copy()
            env["CURL_EXEC_PREFIX_JSON"] = json.dumps(["docker", "exec", name])
            code, _ = command("curl-check-" + label,
                [sys.executable, case / "scripts/accept_curl.py", binary, resultdir, tls],
                env=env, timeout=330, required=False)
            results.append({"runtime": label, "passed": code == 0,
                            "binary_sha256": sha(binary), "image": image(label)})
        finally:
            command("curl-stop-" + label, ["docker", "rm", "-f", name], required=False)
            OWNED.discard(name)
    dump(out / "runtime-matrix.json", results)
    return all(r["passed"] for r in results)


def rust_case(role):
    harness = HERE / "ripgrep/harness"
    inputs = OUT / "ripgrep-inputs"
    command("ripgrep-inputs", [sys.executable, harness / "prepare-inputs.py",
                              "--inputs-root", inputs], timeout=1800)
    old = HERE / "r-old/harness"
    old_inputs, old_out = OUT / "engine-inputs", OUT / "engine-case"
    if role == "rust-engine":
        if not old.exists():
            raise RuntimeError("R-old harness has not been integrated")
        env = os.environ.copy()
        env.update(SOURCE_ROOT=str(REPO), RUST_SDK_ROOT=str(inputs / "rust-sdk"),
                   INPUTS_ROOT=str(old_inputs))
        code, _ = command("engine-inputs", [sys.executable, old / "prepare-inputs.py"],
                          env=env, timeout=900, required=False)
        if code == 0:
            code = build("engine", old, old_inputs, old_out,
                         [PYTHON, "/case/container-build.py"])
            if code == 0:
                # R-old's interface and fixture checks are validated by check mode.
                runtime_code, _ = command("engine-runtime-driver", [sys.executable, HERE / "engine_runtime.py",
                         "--output", old_out, "--inputs", old_inputs], timeout=1800, required=False)
                return runtime_code == 0
        return False
    outcomes = []
    for variant in (role.removeprefix("rust-"),):
        out = OUT / ("ripgrep-" + variant)
        code = build("ripgrep-" + variant, harness, inputs, out,
                     ["/bin/bash", "/case/container-build.sh", variant],
                     extra=[(harness, "/harness", True)])
        outcomes.append(code == 0)
        if code:
            continue
        for label in ("runtime217", "runtime231", "runtime239"):
            resultdir = out / "runtime" / label
            prefix = ["docker", "run", "--rm", "--platform", "linux/amd64",
                      "--user", str(os.getuid()) + ":" + str(os.getgid()), "--env", "HOME=/tmp",
                      "--label", "relship.baseline.owner=" + OWNER,
                      "--network", "none", "--read-only", "--cap-drop", "ALL",
                      "--security-opt", "no-new-privileges", "--cpus", "2", "--memory", "2g",
                      "--pids-limit", "256", "--tmpfs", "/tmp:rw,nosuid,size=256m",
                      "--mount", "type=bind,src={fixture},dst=/fixtures,readonly",
                      "--mount", "type=bind,src=" + str(out / "extracted") + ",dst=/payload,readonly",
                      "--workdir", "/fixtures", image(label)]
            argv = [sys.executable, harness / "check-runtime.py", "--binary", "/payload/bin/rg",
                    "--host-binary", out / "extracted/bin/rg", "--out-dir", resultdir,
                    "--exec-prefix-json", json.dumps(prefix)]
            if variant == "pcre2":
                argv += ["--pcre2"]
            code, _ = command("ripgrep-" + variant + "-" + label, argv,
                              timeout=300, required=False)
            outcomes.append(code == 0)
    return all(outcomes)


def high_input():
    pins = json.loads((HERE / "high-control.json").read_text())
    archive = HERE / pins["fixture_path"]
    if sha(archive) != pins["fixture_sha256"]:
        raise RuntimeError("Retained high-control fixture SHA256 mismatch")
    root = OUT / "high-input"
    root.mkdir(parents=True, exist_ok=True)
    with gzip.open(archive, "rb") as stream:
        data = stream.read(pins["uncompressed_bytes"] + 1)
    if len(data) != pins["uncompressed_bytes"] or hashlib.sha256(data).hexdigest() != pins["binary_sha256"]:
        raise RuntimeError("Retained high-control binary SHA256/size mismatch")
    binary = root / "relship"
    binary.write_bytes(data)
    binary.chmod(0o755)
    dump(OUT / "high-input.json", {"artifact_id": pins["artifact_id"],
         "original_artifact_sha256": pins["artifact_sha256"],
         "fixture_sha256": sha(archive), "binary_sha256": sha(binary),
         "source_run_url": pins["source_run_url"], "download_required": False})
    return binary


def controls():
    binary = high_input()
    command("rejection-controls", [sys.executable, HERE / "negative_controls.py",
            "--high-binary", binary, "--output", OUT / "controls"], timeout=1800)
    return True


def check():
    results = []
    for item in json.loads((HERE / "engine-source-files.json").read_text()):
        path = REPO / item["path"]
        if sha(path) != item["sha256"]:
            raise RuntimeError("Frozen engine source mismatch: " + item["path"])
    for pin in PINS.values():
        if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", pin["reference"]) or pin["platform"] != "linux/amd64":
            raise RuntimeError("Invalid platform image pin")
    high = json.loads((HERE / "high-control.json").read_text())
    if sha(HERE / high["fixture_path"]) != high["fixture_sha256"]:
        raise RuntimeError("Retained high-control fixture mismatch")
    old = json.loads((HERE / "r-old/harness/input-pins.json").read_text())
    fixture = HERE / "r-old/fixtures/reader-fixture.tar.gz"
    if sha(fixture) != old["reader_fixture"]["archive_sha256"]:
        raise RuntimeError("Retained reader fixture mismatch")
    for path in HERE.rglob("*.py"):
        ast.parse(path.read_text(), filename=str(path))
        results.append(path.relative_to(HERE).as_posix())
    for path in HERE.rglob("*.sh"):
        subprocess.run(["bash", "-n", str(path)], check=True)
    print(json.dumps({"status": "static preparation checked; no Linux build or runtime execution",
                      "python_files": len(results), "engine_source_files": 73, "image_pins": len(PINS)}))


def report_file(path):
    return (path.is_file() and not path.is_symlink()
            and path.stat().st_size <= 20 * 1024 * 1024
            and path.suffix in (".json", ".log", ".stdout", ".stderr", ".txt",
                                ".versions", ".dynamic", ".headers"))


def collect(role):
    destination = OUT / "reports"
    destination.mkdir(exist_ok=True)
    excluded = {"inputs", "downloads", "source", "rust-sdk", "sdk", "target", "cargo-home",
                "work", "payload", "extracted", "stage", "gnupg", "c-tls-fixture", "high-input", "reports"}
    # Keep preparation evidence without descending into source/SDK/cache directories.
    for inputs in OUT.glob("*-inputs"):
        if not inputs.is_dir():
            continue
        selected = [inputs / name for name in ("input-pins.json", "prepared-inputs.json",
                    "acquisition.json", "signature-results.json")]
        for logdir in ("preparation-logs", "acquisition-logs"):
            if (inputs / logdir).is_dir() and not (inputs / logdir).is_symlink():
                selected.extend((inputs / logdir).rglob("*"))
        for path in selected:
            if report_file(path):
                target = destination / "input-evidence" / path.relative_to(OUT)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
    for base, dirs, files in os.walk(OUT):
        dirs[:] = [d for d in dirs if d not in excluded and not d.endswith("-inputs")]
        for name in files:
            path = Path(base) / name
            if not report_file(path):
                continue
            target = destination / path.relative_to(OUT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    dump(destination / "retention.json", {"role": role, "retention_days": 3,
         "contents": "Reports and logs only. No executable, package archive, SDK, Cargo cache or TLS private key.",
         "native_execution_required": True, "release_publication": False})


def main():
    global DEADLINE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=["check", "go", "c", "rust-engine", "rust-default", "rust-pcre2", "controls"])
    args = parser.parse_args()
    if args.role == "check":
        check()
        return
    OUT.mkdir(parents=True, exist_ok=True)
    budget_minutes = 40 if args.role == "controls" else 80
    DEADLINE = time.monotonic() + budget_minutes * 60
    passed = False
    error = None
    try:
        check()
        native()
        pull(["build217", "runtime217", "runtime231", "runtime239"])
        base_environment()
        if args.role.startswith("rust-"):
            passed = rust_case(args.role)
        else:
            passed = {"go": go_case, "c": c_case, "controls": controls}[args.role]()
        if not passed:
            failed = [{"name": row["name"], "exit": row["exit"], "timed_out": row["timed_out"],
                       "stderr": "controller-logs/" + row["name"] + ".stderr"}
                      for row in COMMANDS if row["exit"] or row["timed_out"]]
            error = {"message": "Required experiment role failed; inspect retained case reports",
                     "failed_commands": failed}
    except Exception as exc:
        error = {"message": str(exc), "traceback": traceback.format_exc()}
    finally:
        try:
            cleanup_errors = cleanup()
        except Exception as exc:
            cleanup_errors = [{"operation": "cleanup", "error": str(exc)}]
        passed = passed and not cleanup_errors and error is None
        result = {"role": args.role, "passed": passed,
             "error": error, "cleanup_errors": cleanup_errors, "shared_budget_minutes": budget_minutes,
             "experiment": "manual native x86_64 feasibility",
             "baseline": "glibc 2.17", "automatic_baseline_raise": False,
             "product_integration": False, "release_publication": False}
        dump(OUT / "job-result.json", result)
        try:
            collect(args.role)
        except Exception as exc:
            passed = False
            result["passed"] = False
            result["report_collection_error"] = {"type": type(exc).__name__, "message": str(exc),
                                                  "traceback": traceback.format_exc()}
            dump(OUT / "job-result.json", result)
            # Keep the failure record even when an individual report could not be copied.
            dump(OUT / "reports/job-result.json", result)
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
