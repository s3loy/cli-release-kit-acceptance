#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import traceback
import zipfile


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def engine_source_id(root):
    files = [Path("Cargo.toml"), Path("Cargo.lock"), Path("build.rs")]
    files.extend(path.relative_to(root) for path in (root / "src").rglob("*") if path.is_file())
    state = hashlib.sha256(b"cli-release-kit-engine-source/v1\0")
    for path in sorted(files):
        name = path.as_posix().encode()
        data = (root / path).read_bytes()
        state.update(struct.pack(">Q", len(name)) + name + struct.pack(">Q", len(data)) + data)
    return state.hexdigest()


def command(out, name, argv, cwd, *, timeout=1200, check=True, env=None):
    try:
        result = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        write_json(out / "logs" / (name + ".json"), {"argv": argv, "timeout": timeout, "timed_out": True})
        raise RuntimeError(f"{name} exceeded {timeout} seconds") from error
    record = {"argv": argv, "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    write_json(out / "logs" / (name + ".json"), record)
    if check and result.returncode:
        raise RuntimeError(f"{name} exited {result.returncode}; inspect logs/{name}.json")
    return record


def inspect_elf(root, out, label, binary):
    header = command(out, label + "-elf-header", ["readelf", "--file-header", str(binary)], root)["stdout"]
    program = command(out, label + "-elf-program", ["readelf", "--program-headers", str(binary)], root)["stdout"]
    dynamic = command(out, label + "-elf-dynamic", ["readelf", "--dynamic", str(binary)], root)["stdout"]
    versions = command(out, label + "-elf-versions", ["readelf", "--version-info", str(binary)], root)["stdout"]
    assert "Advanced Micro Devices X86-64" in header
    glibc = sorted(set(re.findall(r"\bGLIBC_[0-9]+(?:\.[0-9]+)+", versions)),
                   key=lambda value: tuple(map(int, value.removeprefix("GLIBC_").split("."))))
    return {
        "sha256": digest(binary), "size": binary.stat().st_size,
        "interpreter": re.findall(r"Requesting program interpreter: ([^\]]+)", program),
        "needed": re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dynamic),
        "glibc_version_tags": sorted(set(re.findall(r"\bGLIBC_[A-Za-z0-9_.]+", versions))),
        "glibc_versions": glibc, "max_glibc_version": glibc[-1] if glibc else None,
    }


def main(root, out, runner):
    assert runner in {"ubuntu-22.04", "ubuntu-24.04"}
    assert out != root and not out.is_relative_to(root)
    assert not out.exists(), "Use a fresh output directory"
    out.mkdir(parents=True)
    expected = json.loads((root / "compatibility/source-snapshot.json").read_text())
    assert engine_source_id(root) == expected["engine_source_id"]
    assert all(digest(root / name) == value for name, value in expected["files"].items())
    clean = command(out, "source-clean-before", ["git", "status", "--porcelain=v1", "--untracked-files=all"], root)
    assert clean["stdout"] == "", "The reviewed fixture must be committed before the real experiment"
    source_commit = command(out, "source-commit", ["git", "rev-parse", "HEAD"], root)["stdout"].strip()
    source_tree = command(out, "source-tree", ["git", "rev-parse", "HEAD^{tree}"], root)["stdout"].strip()
    environment = {}
    for label, argv in [
        ("rustc", ["rustc", "-vV"]), ("cargo", ["cargo", "--version"]),
        ("compiler", ["cc", "--version"]), ("libc", ["ldd", "--version"]),
        ("kernel", ["uname", "-a"]), ("docker", ["docker", "version", "--format", "{{json .}}"]),
    ]:
        environment[label] = command(out, "environment-" + label, argv, root)["stdout"]
    assert "release: 1.96.0\n" in environment["rustc"]
    assert "host: x86_64-unknown-linux-gnu\n" in environment["rustc"]
    cargo_target = out / "cargo"
    command(out, "bootstrap-build", ["cargo", "build", "--locked", "--release", "--bin", "relship",
                                   "--target", "x86_64-unknown-linux-gnu", "--target-dir", str(cargo_target)], root)
    bootstrap = out / "bin/relship-bootstrap"
    bootstrap.parent.mkdir()
    shutil.copy2(cargo_target / "x86_64-unknown-linux-gnu/release/relship", bootstrap)
    info = command(out, "bootstrap-build-info", [str(bootstrap), "build-info"], root)["stdout"]
    assert "source: " + expected["engine_source_id"] in info
    plan_file, assignment_file, worker = out / "plan.json", out / "assignment.json", out / "worker"
    command(out, "self-package-plan", [str(bootstrap), "plan", "--output", str(plan_file)], root)
    plan = json.loads(plan_file.read_text())
    assert plan["schema"] == 5 and plan["config"]["schema"] == 4
    assert plan["source"]["commit"] == source_commit and plan["source"]["tree"] == source_tree
    assert plan["engine_source_id"] == expected["engine_source_id"]
    assert len(plan["builds"]) == 1 and len(plan["packages"]) == 2
    assert {package["format"] for package in plan["packages"]} == {"tar.gz", "zip"}
    command(out, "self-package-assign", [str(bootstrap), "assign", "--plan", str(plan_file), "--output", str(assignment_file)], root)
    assert json.loads(assignment_file.read_text())["skip_runtime"] is False
    command(out, "self-package-worker", [str(bootstrap), "worker", "--plan", str(plan_file), "--assignment", str(assignment_file), "--output", str(worker)], root)
    command(out, "self-package-verify", [str(bootstrap), "verify", "--output", str(worker)], root)
    payload_file = worker / "payloads/0/payload.json"
    payload = json.loads(payload_file.read_text())
    assert payload["status"] == "complete" and payload["engine_source_id"] == expected["engine_source_id"]
    version_tasks = [task for task in payload["tasks"] if "version" in task["id"]]
    assert version_tasks and all(task["state"] == "succeeded" for task in version_tasks)
    payload_binary = out / "bin/relship-payload"
    shutil.copy2(worker / "payloads/0/files/relship", payload_binary)
    assert digest(payload_binary) == payload["files"]["relship"]["sha256"]
    binary_paths = {"bootstrap": bootstrap, "payload": payload_binary}
    packages = []
    for index, package in enumerate(plan["packages"]):
        record_file = worker / f"packages/{index}/package.json"
        record = json.loads(record_file.read_text())
        archive = worker / f"packages/{index}" / package["filename"]
        assert digest(archive) == record["sha256"]
        if package["format"] == "tar.gz":
            with tarfile.open(archive) as opened:
                assert {member.name for member in opened} == {"relship", "LICENSE"}
                member = opened.getmember("relship")
                assert member.isfile() and member.mode & 0o111
                data = opened.extractfile("relship").read()
                license_bytes = opened.extractfile("LICENSE").read()
        else:
            with zipfile.ZipFile(archive) as opened:
                assert set(opened.namelist()) == {"relship", "LICENSE"}
                assert (opened.getinfo("relship").external_attr >> 16) & 0o111
                data = opened.read("relship")
                license_bytes = opened.read("LICENSE")
        assert license_bytes == (root / "LICENSE").read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest(payload_binary)
        label = package["format"].replace(".", "-")
        extracted = out / "extracted" / label / "relship"
        extracted.parent.mkdir(parents=True)
        extracted.write_bytes(data)
        extracted.chmod(0o755)
        binary_paths[label] = extracted
        package_copy = out / "packages" / package["filename"]
        package_copy.parent.mkdir(exist_ok=True)
        shutil.copy2(archive, package_copy)
        shutil.copy2(record_file, out / "packages" / (label + "-record.json"))
        packages.append({"format": package["format"], "filename": package["filename"],
                         "sha256": digest(archive), "binary_sha256": digest(extracted)})
    elf = {label: inspect_elf(root, out, label, path) for label, path in binary_paths.items()}
    smoke_args = [("version", ["--version"]), ("build-info", ["build-info"]),
                  ("targets", ["targets", "--builder", "rust"])]
    for label, binary in binary_paths.items():
        for suffix, arguments in smoke_args:
            result = command(out, "native-" + label + "-" + suffix, [str(binary), *arguments], root)
            assert_smoke(suffix, result, expected["engine_source_id"])
    observations = []
    images = json.loads((root / "compatibility/image-pins.json").read_text())
    for image in images:
        label = image["name"].replace(":", "-")
        command(out, "pull-" + label, ["docker", "pull", "--platform", "linux/amd64", image["reference"]], root, timeout=180)
        image_info = command(out, "image-" + label, ["docker", "image", "inspect", image["reference"]], root)["stdout"]
        observation = {"image": image, "image_inspect": json.loads(image_info), "binaries": {}}
        base = ["docker", "run", "--rm", "--platform", "linux/amd64", "--network", "none", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "64", "--memory", "256m",
                "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "--mount", f"type=bind,source={out},target=/evidence,readonly",
                image["reference"]]
        observation["libc"] = command(out, label + "-libc", base + ["getconf", "GNU_LIBC_VERSION"], root, timeout=30)["stdout"].strip()
        for binary_label, binary in binary_paths.items():
            tasks = []
            for suffix, arguments in smoke_args:
                result = command(out, label + "-" + binary_label + "-" + suffix,
                                 base + ["/evidence/" + binary.relative_to(out).as_posix(), *arguments], root, timeout=30, check=False)
                if result["exit_code"] == 0:
                    assert_smoke(suffix, result, expected["engine_source_id"])
                tasks.append({"name": suffix, "exit_code": result["exit_code"], "stderr": result["stderr"]})
            observation["binaries"][binary_label] = {"passed": all(task["exit_code"] == 0 for task in tasks), "tasks": tasks}
        observations.append(observation)
    write_json(out / "report/userspace-observations.json", observations)
    for image in observations:
        if image["image"]["name"] in {runner.replace("ubuntu-", "ubuntu:"), "ubuntu:24.04"}:
            assert all(binary["passed"] for binary in image["binaries"].values()), "Matching or newer userspace smoke failed"
    clean = command(out, "source-clean-after", ["git", "status", "--porcelain=v1", "--untracked-files=all"], root)
    assert clean["stdout"] == ""
    for source_file in [plan_file, assignment_file, payload_file, worker / "receipt.json"]:
        if source_file.exists():
            shutil.copy2(source_file, out / "report" / source_file.name)
    report = {"schema": 1, "status": "passed", "runner": runner, "engine_source_id": expected["engine_source_id"],
              "source_commit": source_commit, "source_tree": source_tree, "environment": environment,
              "runner_image": {key: os.environ.get(key) for key in ["ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH"]},
              "elf": elf, "packages": packages, "userspace_observations": observations,
              "scope": "Source-built Linux x86_64 engine, real self-packages, CLI smoke in pinned Linux userspaces",
              "limitations": ["No HTTPS installer/bootstrap coverage", "No C/C++ builder support",
                              "No six-platform runtime qualification", "No public release or package publication",
                              "Containers share the runner kernel", "Rust 1.96.0 fixed; no older-Rust experiment"]}
    write_json(out / "report/result.json", report)
    print(json.dumps({"runner": runner, "status": "passed", "engine_source_id": report["engine_source_id"],
                      "max_glibc_version": elf["payload"]["max_glibc_version"]}))


def assert_smoke(suffix, result, source_id):
    if suffix == "version":
        assert result["stdout"] == "relship 0.1.0\n"
    elif suffix == "build-info":
        assert "source: " + source_id in result["stdout"]
        assert "x86_64-unknown-linux-gnu" in result["stdout"]
    else:
        assert "linux-x86_64-gnu [rust] x86_64-unknown-linux-gnu" in result["stdout"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--runner", required=True)
    args = parser.parse_args()
    try:
        main(Path(__file__).resolve().parents[1], args.output.resolve(), args.runner)
    except Exception:
        write_json(args.output.resolve() / "report/failure.json", {"status": "failed", "traceback": traceback.format_exc()})
        raise
