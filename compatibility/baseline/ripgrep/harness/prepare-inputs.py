#!/usr/bin/env python3
"""Prepare pinned ripgrep inputs on a native Linux amd64 CI host."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib


HERE = Path(__file__).resolve().parent


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def inventory(root):
    return [
        {"path": p.relative_to(root).as_posix(), "sha256": digest(p),
         "mode": oct(p.stat().st_mode & 0o777), "bytes": p.stat().st_size}
        for p in sorted(root.rglob("*")) if p.is_file()
    ]


def download(url, path, expected):
    if path.exists():
        if digest(path) != expected:
            raise RuntimeError("Existing input has wrong SHA256: " + str(path))
        return
    partial = path.with_name(path.name + ".part")
    subprocess.run([
        "curl", "--fail", "--location", "--silent", "--show-error",
        "--max-time", "600", "--dump-header", str(path) + ".headers",
        "--output", str(partial), url,
    ], check=True, timeout=610)
    if digest(partial) != expected:
        raise RuntimeError("Downloaded input has wrong SHA256: " + url)
    partial.rename(path)


def extract(archive, destination):
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise RuntimeError("Unsafe archive member: " + member.name)
            if not (member.isfile() or member.isdir() or member.issym()):
                raise RuntimeError("Unsupported archive member: " + member.name)
            if member.issym():
                target = Path(member.linkname)
                if target.is_absolute() or ".." in target.parts:
                    raise RuntimeError("Unsafe symlink: " + member.name)
        tar.extractall(destination, filter="data")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs-root", type=Path, required=True)
    parser.add_argument("--rust-archives-root", type=Path,
                        help="Optional existing verified Rust archive cache")
    args = parser.parse_args()
    if sys.platform != "linux" or platform.machine() != "x86_64":
        parser.error("Input preparation requires a native Linux x86_64 host")
    root = args.inputs_root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    logs = root / "preparation-logs"
    logs.mkdir(exist_ok=True)
    pins = json.loads((HERE / "input-pins.json").read_text())
    (root / "input-pins.json").write_text(json.dumps(pins, indent=2) + "\n")
    archives = root / "downloads"
    archives.mkdir(exist_ok=True)
    rust_archives = (args.rust_archives_root or archives).resolve()
    rust_archives.mkdir(parents=True, exist_ok=True)
    manifest = rust_archives / "channel-rust-1.96.0.toml"
    download(pins["rust"]["manifest_url"], manifest,
             pins["rust"]["manifest_sha256"])
    official = tomllib.loads(manifest.read_text())
    for component in pins["rust"]["components"]:
        entry = official["pkg"][component["component"]]["target"][pins["target"]]
        if entry["xz_url"] != component["url"] or entry["xz_hash"] != component["sha256"]:
            raise RuntimeError("Rust component disagrees with the official manifest")
    sdk = root / "rust-sdk"
    if sdk.exists():
        parser.error("Use a fresh inputs root; rust-sdk already exists")
    sdk.mkdir()
    for component in pins["rust"]["components"]:
        archive = rust_archives / component["local_archive"]
        download(component["url"], archive, component["sha256"])
        with tempfile.TemporaryDirectory(prefix="rust-component-", dir=root) as temp:
            extract(archive, Path(temp))
            top = Path(temp) / archive.name.removesuffix(".tar.xz")
            for name in (top / "components").read_text().splitlines():
                for child in (top / name).iterdir():
                    if child.name == "manifest.in":
                        continue
                    if child.is_dir():
                        shutil.copytree(child, sdk / child.name,
                                        dirs_exist_ok=True, symlinks=True)
                    else:
                        shutil.copy2(child, sdk / child.name)
    source_archive = archives / "ripgrep-upstream.tar.gz"
    download(pins["source"]["url"], source_archive, pins["source"]["sha256"])
    source = root / "source"
    with tempfile.TemporaryDirectory(prefix="ripgrep-source-", dir=root) as temp:
        extract(source_archive, Path(temp))
        shutil.move(str(Path(temp) / pins["source"]["archive_root"]), source)
    for path, key in [("Cargo.lock", "cargo_lock_sha256"),
                      ("Cargo.toml", "cargo_toml_sha256"),
                      (".cargo/config.toml", "cargo_config_sha256")]:
        if digest(source / path) != pins[key]:
            raise RuntimeError("Frozen source mismatch: " + path)
    source_before = inventory(source)
    cargo_home = root / "cargo-home"
    cargo_home.mkdir()
    env = os.environ.copy()
    env.update(PATH=str(sdk / "bin") + os.pathsep + env["PATH"],
               CARGO_HOME=str(cargo_home), RUSTC=str(sdk / "bin/rustc"),
               CARGO_NET_RETRY="0", PYTHONDONTWRITEBYTECODE="1")
    argv = [str(sdk / "bin/cargo"), "fetch", "--locked", "--target",
            pins["target"], "--manifest-path", str(source / "Cargo.toml")]
    with (logs / "cargo-fetch.stdout.log").open("wb") as out, \
            (logs / "cargo-fetch.stderr.log").open("wb") as err:
        proc = subprocess.run(argv, env=env, cwd=source, stdout=out, stderr=err, timeout=600)
    if proc.returncode:
        raise RuntimeError("Dependency prefetch failed; inspect preparation-logs")
    if inventory(source) != source_before:
        raise RuntimeError("Dependency fetch changed frozen source")
    crates = []
    for pkg in pins["registry_packages"]:
        name = pkg["name"] + "-" + pkg["version"] + ".crate"
        matches = list((cargo_home / "registry/cache").glob("*/" + name))
        if not matches:
            continue  # Cargo's explicit target excludes irrelevant platforms.
        path = matches[0]
        if digest(path) != pkg["checksum"]:
            raise RuntimeError("Cargo.lock checksum mismatch: " + name)
        crates.append({**pkg, "path": path.relative_to(root).as_posix(),
                       "actual_sha256": digest(path)})
    if not any(c["name"] == "pcre2-sys" for c in crates):
        raise RuntimeError("PCRE2 bundled C dependency was not prefetched")
    record = {"schema": 1, "host_platform": platform.platform(),
              "host_machine": platform.machine(), "prefetch_argv": argv,
              "source_files": source_before, "sdk_files": inventory(sdk),
              "cargo_registry_crates": crates,
              "cargo_home_files": inventory(cargo_home),
              "input_pins_sha256": digest(root / "input-pins.json"),
              "status": "prepared; product compilation has not run"}
    (root / "prepared-inputs.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"status": record["status"], "inputs_root": str(root),
                      "registry_crates": len(crates)}, indent=2))


if __name__ == "__main__":
    main()
