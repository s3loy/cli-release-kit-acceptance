#!/usr/bin/env python3
"""Run the isolated G-pure case on a native Linux x86_64 Docker host."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import tarfile
import time


HERE = Path(__file__).resolve().parent
PINS = json.loads((HERE / "input-pins.json").read_text())
OUT = Path(os.environ["CASE_OUT"]).resolve()
INPUTS = Path(os.environ["INPUTS_ROOT"]).resolve()
LOGS = OUT / "host-logs"
LOGS.mkdir(parents=True, exist_ok=True)
REPORT = OUT / "results.json"
RESULTS = json.loads(REPORT.read_text()) if REPORT.exists() else {
    "case": "G-pure", "harness": "manual-control", "status": "prepared-only",
    "source_commit": PINS["source"]["upstream_commit"],
    "limits": {"input_seconds": 600, "build_seconds": 2400,
               "functional_process_seconds": 300, "cpus": 2, "memory": "2g"},
    "limitations": ["This case is not relship integration or release evidence.",
                    "Userspace containers share the host kernel.",
                    "No minimum CPU or kernel qualification is claimed.",
                    "GoAWK has no external module dependencies."]}
SEQ = 0
DEADLINE = None


def save():
    REPORT.write_text(json.dumps(RESULTS, indent=2) + "\n")


def sha(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def run(label, argv, timeout=300, data=None, allow_failure=False, owned_container=None):
    started = time.monotonic()
    if DEADLINE is not None:
        timeout = min(timeout, DEADLINE - started)
        if timeout <= 0:
            raise RuntimeError("The entire functional check exceeded its 300-second limit")
    record = {"argv": argv, "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "timeout_seconds": timeout}
    process = subprocess.Popen(argv, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(data.encode() if data is not None else None, timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        if owned_container:
            subprocess.run(["docker", "rm", "-f", owned_container], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=30, check=False)
        record["timed_out"] = True
    record.update(exit_code=process.returncode, elapsed_seconds=round(time.monotonic() - started, 3),
                  stdout_sha256=hashlib.sha256(stdout).hexdigest(), stderr_sha256=hashlib.sha256(stderr).hexdigest())
    (LOGS / (label + ".stdout")).write_bytes(stdout)
    (LOGS / (label + ".stderr")).write_bytes(stderr)
    (LOGS / (label + ".json")).write_text(json.dumps(record, indent=2) + "\n")
    if record.get("timed_out") or (process.returncode and not allow_failure):
        raise RuntimeError(label + " failed; see " + str(LOGS / (label + ".json")))
    return process.returncode, stdout.decode(errors="replace"), stderr.decode(errors="replace")


def pinned_image(value):
    if not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", value):
        raise ValueError("An immutable OCI manifest reference is required: " + value)
    return value


def native_host():
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "amd64"):
        raise RuntimeError("This experiment requires a native Linux x86_64 host; emulation is not accepted")
    _, architecture, _ = run("docker-architecture", ["docker", "info", "--format", "{{.Architecture}}"])
    if architecture.strip() not in ("x86_64", "amd64"):
        raise RuntimeError("The Docker daemon must run natively on x86_64")
    run("host-identity", ["uname", "-a"])
    run("docker-version", ["docker", "version"])
    run("docker-info", ["docker", "info"])
    RESULTS["execution"] = {"mode": "native", "host_system": platform.system(),
                            "host_machine": platform.machine(), "host_kernel": platform.release(),
                            "docker_architecture": architecture.strip(), "shared_kernel": True}


def container(label, image, command, mounts=(), env=(), data=None, timeout=300, allow_failure=False):
    global SEQ
    SEQ += 1
    name = "baseline-g-pure-{}-{}".format(os.getpid(), SEQ)
    argv = ["docker", "run", "--rm", "--name", name, "--platform", "linux/amd64",
            "--user", str(os.getuid()) + ":" + str(os.getgid()), "--env", "HOME=/tmp",
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--cpus", "2", "--memory", "2g",
            "--pids-limit", "256", "--tmpfs", "/tmp:rw,nosuid,size=512m"]
    if os.environ.get("BASELINE_OWNER"):
        argv += ["--label", "relship.baseline.owner=" + os.environ["BASELINE_OWNER"]]
    for host, guest, mode in mounts:
        argv += ["--mount", "type=bind,src={},dst={},{}".format(host, guest, "readonly" if mode == "ro" else "rw")]
    for key, value in env:
        argv += ["--env", key + "=" + value]
    if data is not None:
        argv += ["--interactive"]
    argv += [pinned_image(image)] + command
    return run(label, argv, timeout, data, allow_failure, name)


def collect_build():
    native_host()
    image = pinned_image(os.environ["BASELINE_IMAGE"])
    run("build-image-inspect", ["docker", "image", "inspect", image])
    observed = json.loads((OUT / "build-result.json").read_text())
    if observed["status"] != "built" or observed["binary_sha256"] != sha(OUT / "payload/goawk"):
        raise RuntimeError("Container build report does not match the payload")
    for pin in (PINS["source"], PINS["sdk"]):
        if sha(INPUTS / pin["filename"]) != pin["sha256"]:
            raise RuntimeError("Input checksum mismatch: " + pin["filename"])
    for entry in PINS["source_allowlist"]:
        if sha(OUT / "source" / entry["path"]) != entry["sha256"]:
            raise RuntimeError("Source replay mismatch: " + entry["path"])
    actual_paths = sorted(str(path.relative_to(OUT / "source")) for path in (OUT / "source").rglob("*") if path.is_file())
    if actual_paths != sorted(entry["path"] for entry in PINS["source_allowlist"]):
        raise RuntimeError("The source directory contains unexpected files")
    if sha(HERE / "check.py") != PINS["original_check_sha256"]:
        raise RuntimeError("The retained source-owned functional check changed")
    observed["image"] = image
    observed["network_policy"] = "The launcher must supply --network none; retain its actual argv as evidence"
    observed["sdk_binary_sha256"] = sha(OUT / "sdk/go/bin/go")
    observed["recipe_sha256"] = sha(HERE / "build-in-container.sh")
    observed["source_overlay"] = False
    RESULTS["inputs"] = {"pins": PINS, "source_replay_verified": True, "sdk_archive_hash_verified": True,
                          "external_module_fetches": 0,
                          "dependency_preparation": "The pinned go.mod contains no require directives; all build inputs are source and the fixed SDK."}
    RESULTS["build"] = observed
    RESULTS.setdefault("counts", {})["builds"] = 1
    RESULTS["status"] = "built"
    save()


def package():
    native_host()
    archive = OUT / "goawk-v1.30.1-linux-x86_64.tar.gz"
    if archive.exists() or (OUT / "extracted").exists():
        raise RuntimeError("Packaging preserves existing evidence; use a fresh CASE_OUT")
    run("tar-version", ["tar", "--version"])
    run("gzip-version", ["gzip", "--version"])
    members = ["goawk", "LICENSE.txt", "README.md"]
    run("archive-create", ["tar", "--sort=name", "--mtime=@0", "--owner=0", "--group=0",
        "--numeric-owner", "--format=ustar", "-czf", str(archive), "-C", str(OUT / "payload")] + members)
    extracted = OUT / "extracted"
    extracted.mkdir()
    observed = []
    with tarfile.open(archive, "r:gz") as stream:
        all_members = stream.getmembers()
        if sorted(member.name for member in all_members) != sorted(members):
            raise RuntimeError("Unexpected archive members")
        for member in all_members:
            expected_mode = 0o755 if member.name == "goawk" else 0o644
            if not member.isfile() or member.mode != expected_mode or member.uid != 0 or member.gid != 0:
                raise RuntimeError("Unexpected member metadata: " + member.name)
            contents = stream.extractfile(member).read()
            if hashlib.sha256(contents).hexdigest() != sha(OUT / "payload" / member.name):
                raise RuntimeError("Archive payload mismatch: " + member.name)
            target = extracted / member.name
            target.write_bytes(contents)
            target.chmod(member.mode)
            observed.append({"path": member.name, "sha256": sha(target), "mode": oct(member.mode), "size": member.size})
    RESULTS["package"] = {"filename": archive.name, "sha256": sha(archive), "members": observed,
                          "creation_tool": "GNU tar + gzip", "independent_extraction_tool": "Python tarfile",
                          "extracted_binary_matches_payload": sha(extracted / "goawk") == sha(OUT / "payload/goawk")}
    RESULTS["status"] = "packaged"
    RESULTS.setdefault("counts", {})["package_writes"] = 1
    save()


def runtime(label, image):
    global DEADLINE
    DEADLINE = time.monotonic() + 300
    native_host()
    image = pinned_image(image)
    run("runtime-" + label + "-image-inspect", ["docker", "image", "inspect", image])
    mount = [(OUT / "extracted", "/payload", "ro")]
    identity = container("runtime-" + label + "-identity", image,
                         ["/bin/sh", "-ec", "uname -a; getconf GNU_LIBC_VERSION; cat /etc/os-release"], mount)
    expected_libc = {"glibc-2.17": "glibc 2.17", "glibc-2.31": "glibc 2.31", "glibc-2.39": "glibc 2.39"}[label]
    if expected_libc not in identity[1].splitlines():
        raise RuntimeError("Unexpected runtime libc identity: " + label)
    launch = container("runtime-" + label + "-bare-launch", image, ["/payload/goawk", "-version"], mount)
    if launch[1] != "v1.30.1\n":
        raise RuntimeError("Unexpected GoAWK version output: " + label)
    checks = [
        ("arithmetic", "BEGIN { print 6 * 7 }", "", lambda r: r[0] == 0 and r[1] == "42\n"),
        ("stream-sum", "{ sum += $1 } END { print sum }", "2\n3\n", lambda r: r[0] == 0 and r[1] == "5\n"),
        ("uppercase", 'BEGIN { print toupper("Hello") }', "", lambda r: r[0] == 0 and r[1] == "HELLO\n"),
        ("syntax-error", "BEGIN {", "", lambda r: r[0] != 0 and bool(r[2])),
    ]
    observations = []
    for name, program, data, assertion in checks:
        result = container("runtime-" + label + "-" + name, image, ["/payload/goawk", program],
                           mount, data=data, allow_failure=True)
        passed = assertion(result)
        observations.append({"assertion": name, "passed": passed, "exit_code": result[0],
                             "stdout": result[1], "stderr": result[2]})
        if not passed:
            RESULTS.setdefault("runtimes", {})[label] = {"image": image, "checks": observations, "passed": False}
            save()
            raise RuntimeError("Functional assertion failed: " + label + "/" + name)
    RESULTS.setdefault("runtimes", {})[label] = {"image": image, "libc": expected_libc,
        "bare_launch_exit_code": launch[0], "checks": observations, "passed": True,
        "functional_assertions": 4, "installed_test_tools": False,
        "check_transport": "Host Python invokes the extracted program in an unmodified clean container"}
    RESULTS.setdefault("counts", {})["functional_assertions"] = sum(
        len(value["checks"]) for value in RESULTS["runtimes"].values())
    RESULTS["counts"]["bare_launches"] = len(RESULTS["runtimes"])
    required = {"glibc-2.17", "glibc-2.31", "glibc-2.39"}
    RESULTS["status"] = "passed-three-userspaces" if required.issubset(RESULTS["runtimes"]) and all(
        RESULTS["runtimes"][key]["passed"] for key in required) else "runtime-checked"
    save()


parser = argparse.ArgumentParser()
sub = parser.add_subparsers(dest="stage", required=True)
for name in ("collect-build", "package"):
    sub.add_parser(name)
runtime_parser = sub.add_parser("runtime")
runtime_parser.add_argument("--label", required=True, choices=("glibc-2.17", "glibc-2.31", "glibc-2.39"))
runtime_parser.add_argument("--image", required=True)
args = parser.parse_args()
try:
    if args.stage == "runtime":
        runtime(args.label, args.image)
    else:
        globals()[args.stage.replace("-", "_")]()
except Exception as error:
    RESULTS["status"] = "failed"
    RESULTS["failed_stage"] = args.stage
    RESULTS["failure"] = str(error)
    save()
    raise
