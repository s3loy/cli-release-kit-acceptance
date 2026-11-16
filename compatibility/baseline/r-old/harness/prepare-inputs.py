#!/usr/bin/env python3
"""Prepare frozen relship source and dependencies on a native Linux amd64 CI host."""

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import tomllib

from support import digest, execute, inventory, now, verify, write_json

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=os.environ.get("SOURCE_ROOT"))
    parser.add_argument("--rust-sdk-root", type=Path, default=os.environ.get("RUST_SDK_ROOT"))
    parser.add_argument("--inputs-root", type=Path, default=os.environ.get("INPUTS_ROOT"))
    args = parser.parse_args()
    if not all([args.source_root, args.rust_sdk_root, args.inputs_root]):
        parser.error("Set SOURCE_ROOT, RUST_SDK_ROOT and INPUTS_ROOT, or pass explicit options")
    if sys.platform != "linux" or platform.machine() != "x86_64":
        parser.error("Dependency preparation requires a native Linux x86_64 CI host")
    pins = json.loads((HERE / "input-pins.json").read_text())
    root = args.inputs_root.resolve()
    root.mkdir(parents=True, exist_ok=False)
    source_root = args.source_root.resolve()
    sdk_root = args.rust_sdk_root.resolve()
    verify(source_root, pins["engine_source_files"], exact=False)
    verify(sdk_root, pins["sdk_files"])
    source = root / "source"
    source.mkdir()
    for row in pins["engine_source_files"]:
        path = source / row["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_root / row["path"], path)
        path.chmod(0o644)
    verify(source, pins["engine_source_files"])
    sdk = root / "rust-sdk"
    shutil.copytree(sdk_root, sdk)
    sdk_files = inventory(sdk)
    if not (sdk / "bin/cargo").is_file() or not (sdk / "bin/rustc").is_file():
        raise RuntimeError("RUST_SDK_ROOT must contain the reviewed Rust SDK")
    env = os.environ.copy()
    for name in [key for key in env if key.startswith("CARGO_") or key.startswith("RUST")]:
        env.pop(name)
    cargo_home = root / "cargo-home"
    cargo_home.mkdir()
    env.update(PATH=str(sdk / "bin") + os.pathsep + env["PATH"],
               CARGO_HOME=str(cargo_home), RUSTC=str(sdk / "bin/rustc"),
               CARGO_NET_RETRY="0", PYTHONDONTWRITEBYTECODE="1")
    observations = []
    logs = root / "preparation-logs"
    logs.mkdir()
    for name, argv, timeout in [
        ("rustc-version", [str(sdk / "bin/rustc"), "--version", "--verbose"], 120),
        ("cargo-version", [str(sdk / "bin/cargo"), "--version", "--verbose"], 120),
        ("cargo-fetch", [str(sdk / "bin/cargo"), "fetch", "--locked", "--target", pins["target"],
                         "--manifest-path", str(source / "Cargo.toml")], 600),
    ]:
        result = execute(argv, cwd=source, env=env, timeout=timeout)
        write_json(logs / (name + ".json"), result)
        observations.append({"name": name, "argv": argv, "exit_code": result["exit_code"]})
        if result["exit_code"] or result["timed_out"]:
            raise RuntimeError("Preparation command failed: " + name)
        if name in {"rustc-version", "cargo-version"} and "1.96.0" not in result["stdout"]:
            raise RuntimeError("Unexpected Rust SDK version: " + name)
    verify(source, pins["engine_source_files"])
    lock = tomllib.loads((source / "Cargo.lock").read_text())
    crates = []
    for package in lock["package"]:
        if not package.get("source", "").startswith("registry+"):
            continue
        filename = package["name"] + "-" + package["version"] + ".crate"
        matches = list((cargo_home / "registry/cache").glob("*/" + filename))
        if not matches:
            continue  # Cargo excludes dependencies that cannot apply to this explicit target.
        if len(matches) != 1 or digest(matches[0]) != package["checksum"]:
            raise RuntimeError("Locked Cargo crate checksum differs: " + filename)
        crates.append({"name": package["name"], "version": package["version"],
                       "source": package["source"], "sha256": package["checksum"],
                       "path": matches[0].relative_to(root).as_posix()})
    if not any(row["name"] == "ring" for row in crates):
        raise RuntimeError("The frozen ring native dependency was not prefetched")
    shutil.copyfile(HERE / "input-pins.json", root / "input-pins.json")
    write_json(root / "prepared-inputs.json", {
        "schema": 1, "prepared_at_utc": now(), "host_platform": platform.platform(),
        "host_machine": platform.machine(), "commands": observations,
        "source_files": inventory(source), "sdk_files": sdk_files,
        "cargo_home_files": inventory(cargo_home), "registry_crates": crates,
        "input_pins_sha256": digest(root / "input-pins.json"),
        "status": "prepared; compilation has not run",
    })


if __name__ == "__main__":
    main()
