#!/usr/bin/env python3
"""Build one frozen ripgrep case inside the caller's pinned offline container."""

import argparse
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import traceback


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def inventory(root):
    return [{"path": p.relative_to(root).as_posix(), "sha256": digest(p),
             "mode": oct(p.stat().st_mode & 0o777), "bytes": p.stat().st_size}
            for p in sorted(root.rglob("*")) if p.is_file()]


def verify(root, files):
    for item in files:
        path = root / item["path"]
        if digest(path) != item["sha256"]:
            raise RuntimeError("Prepared input mismatch: " + str(path))


def retain_pcre2_license(crate, destination):
    upstream = crate / "upstream"
    licence = upstream / "LICENCE"
    if licence.exists():
        content = licence.read_bytes()
        sources = [{"path": "upstream/LICENCE", "sha256": digest(licence)}]
        chunks = []
        recipe = "Exact upstream/LICENCE bytes from the pinned prepared Cargo source"
    else:
        unique = {}
        covered = set()
        for source in sorted(upstream.rglob("*")):
            if not source.is_file() or source.suffix not in {".c", ".h"}:
                continue
            for match in re.finditer(rb"/\*.*?\*/", source.read_bytes(), re.DOTALL):
                block = match.group()
                lowered = block.lower()
                if b"copyright" not in lowered or not (
                        b"redistribution" in lowered or b"permission" in lowered):
                    continue
                relative = source.relative_to(crate).as_posix()
                covered.add(relative)
                entry = {"path": relative, "sha256": digest(source),
                         "byte_start": match.start(), "byte_end": match.end()}
                unique.setdefault(block, []).append(entry)
        required = {"upstream/src/pcre2_compile.c",
                    "upstream/deps/sljit/sljit_src/sljitLir.h"}
        if not required <= covered:
            raise RuntimeError("Pinned PCRE2 and SLJIT license notices were not both found")
        content = b"\n\n".join(unique) + b"\n"
        chunks = [{"sha256": hashlib.sha256(block).hexdigest(),
                   "bytes": len(block), "sources": paths}
                  for block, paths in unique.items()]
        sources = []
        recipe = ("The pinned crate omits upstream/LICENCE; retain every unique complete "
                  "copyright/redistribution or permission comment from bundled C/H files, "
                  "including PCRE2 and SLJIT, with each comment's bytes unchanged")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(content)
    destination.chmod(0o644)
    return {"payload_path": "LICENSES/PCRE2.txt", "sha256": digest(destination),
            "bytes": len(content), "recipe": recipe,
            "upstream_licence_file_present": licence.exists(),
            "sources": sources, "comment_chunks": chunks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", choices=["default", "pcre2"])
    args = parser.parse_args()
    inputs = Path(os.environ.get("INPUTS_ROOT", "/inputs")).resolve()
    out = Path(os.environ.get("CASE_OUT", "/out")).resolve()
    out.mkdir(parents=True, exist_ok=True)
    logs = out / "logs"
    logs.mkdir(exist_ok=True)
    report = {"schema": 1, "case": args.case, "execution": "manual feasibility",
              "started_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "stage": "input-validation", "status": "running"}
    env = os.environ.copy()

    def save():
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")

    def run(name, argv, required=True, timeout=120):
        entry = {"name": name, "argv": argv, "status": "running"}
        report.setdefault("commands", []).append(entry)
        save()
        with (logs / (name + ".stdout.log")).open("wb") as stdout, \
                (logs / (name + ".stderr.log")).open("wb") as stderr:
            proc = subprocess.run(argv, env=env, cwd=source, stdout=stdout, stderr=stderr,
                                  timeout=timeout)
        entry.update(exit_code=proc.returncode, status="finished")
        save()
        if required and proc.returncode:
            raise RuntimeError("Command failed: " + name)
        return (logs / (name + ".stdout.log")).read_text(errors="replace")

    try:
        save()
        pins = json.loads((inputs / "input-pins.json").read_text())
        prepared = json.loads((inputs / "prepared-inputs.json").read_text())
        if digest(inputs / "input-pins.json") != prepared["input_pins_sha256"]:
            raise RuntimeError("Prepared pin record mismatch")
        source = inputs / "source"
        sdk = inputs / "rust-sdk"
        overrides = [key for key in env if key.startswith("CARGO_PROFILE_")
                     or key.startswith("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_")
                     or key in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                                "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP"}]
        if overrides:
            raise RuntimeError("Undeclared Cargo/profile overrides: " + ", ".join(overrides))
        verify(source, prepared["source_files"])
        verify(sdk, prepared["sdk_files"])
        verify(inputs / "cargo-home", prepared["cargo_home_files"])
        for path, key in [("Cargo.lock", "cargo_lock_sha256"),
                          ("Cargo.toml", "cargo_toml_sha256"),
                          (".cargo/config.toml", "cargo_config_sha256")]:
            if digest(source / path) != pins[key]:
                raise RuntimeError("Frozen application source mismatch: " + path)
        source_before = inventory(source)
        shutil.copytree(inputs / "cargo-home", out / "cargo-home", symlinks=True)
        compiler = shutil.which("cc") or shutil.which("gcc")
        if not compiler:
            raise RuntimeError("No C compiler exists in the pinned build image")
        env.update(PATH=str(sdk / "bin") + os.pathsep + env["PATH"],
                   CARGO_HOME=str(out / "cargo-home"),
                   CARGO_TARGET_DIR=str(out / "target"),
                   CARGO_BUILD_JOBS="2", CARGO_NET_OFFLINE="true",
                   RUSTC=str(sdk / "bin/rustc"), CC=compiler,
                   CC_ENABLE_DEBUG_OUTPUT="1", PYTHONDONTWRITEBYTECODE="1")
        if args.case == "pcre2":
            env["PCRE2_SYS_STATIC"] = "1"
        elif "PCRE2_SYS_STATIC" in env:
            raise RuntimeError("Default case must not inherit PCRE2_SYS_STATIC")
        report.update(
            input_pins=pins, input_pins_sha256=digest(inputs / "input-pins.json"),
            prepared_inputs_sha256=digest(inputs / "prepared-inputs.json"),
            environment={k: env[k] for k in sorted(env) if k in {
                "PATH", "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS",
                "CARGO_NET_OFFLINE", "RUSTC", "CC", "CC_ENABLE_DEBUG_OUTPUT",
                "PCRE2_SYS_STATIC", "PYTHONDONTWRITEBYTECODE", "BASELINE_IMAGE",
                "INPUTS_ROOT", "CASE_OUT", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
                "LD_LIBRARY_PATH", "LIBRARY_PATH", "PKG_CONFIG_PATH"}},
            profile={"name": "release", "upstream_debug": 1,
                     "default_features": True, "features": ["pcre2"] if args.case == "pcre2" else [],
                     "cargo_configuration_changed": False},
            stage="tool-bootstrap")
        save()
        run("uname", ["uname", "-a"])
        glibc_identity = run("glibc", ["getconf", "GNU_LIBC_VERSION"]).strip()
        if glibc_identity != "glibc 2.17":
            raise RuntimeError("Build userspace is not the candidate glibc 2.17: " + glibc_identity)
        run("os-release", ["cat", "/etc/os-release"])
        run("cc-version", [compiler, "--version"])
        run("cc-target", [compiler, "-dumpmachine"])
        compiler_linker = run("cc-linker", [compiler, "-print-prog-name=ld"]).strip()
        compiler_linker = shutil.which(compiler_linker) or compiler_linker
        run("cc-linker-version", [compiler_linker, "--version"])
        run("ld-version", ["ld", "--version"])
        run("readelf-version", ["readelf", "--version"])
        run("tar-version", ["tar", "--version"])
        run("package-inventory", ["rpm", "-qa"], required=False)
        run("memory", ["cat", "/proc/meminfo"])
        run("cpu", ["cat", "/proc/cpuinfo"])
        for tool in [sdk / "bin/rustc", sdk / "bin/cargo", *sorted((sdk / "lib").glob("*.so*"))]:
            run("sdk-" + tool.name + "-elf-versions",
                ["readelf", "-W", "--version-info", str(tool)], required=False)
        run("rustc-version", [str(sdk / "bin/rustc"), "--version", "--verbose"])
        run("cargo-version", [str(sdk / "bin/cargo"), "--version", "--verbose"])
        report["stage"] = "build"
        argv = [str(sdk / "bin/cargo"), "build", "--locked", "--offline",
                "--release", "--target", pins["target"], "--package", "ripgrep",
                "--bin", "rg", "-j", "2", "--manifest-path", str(source / "Cargo.toml"), "-vv"]
        if args.case == "pcre2":
            argv += ["--features", "pcre2"]
        run("cargo-build", argv, timeout=2400)
        if inventory(source) != source_before:
            raise RuntimeError("Build changed frozen source")
        binary = out / "target" / pins["target"] / "release/rg"
        report["stage"] = "elf-inspection"
        run("file", ["file", str(binary)])
        run("elf-header", ["readelf", "-W", "-h", str(binary)])
        run("elf-program-headers", ["readelf", "-W", "-l", str(binary)])
        dynamic = run("elf-dynamic", ["readelf", "-W", "-d", str(binary)])
        versions = run("elf-versions", ["readelf", "-W", "--version-info", str(binary)])
        run("elf-dyn-symbols", ["readelf", "-W", "--dyn-syms", str(binary)])
        run("ldd-build-environment", ["ldd", str(binary)], required=False)
        glibc = sorted(set(re.findall(r"GLIBC_(\d+(?:\.\d+)+)", versions)),
                       key=lambda value: tuple(map(int, value.split("."))))
        glibc_labels = sorted(set(re.findall(r"\bGLIBC_[A-Za-z0-9_.]+", versions)))
        report["elf"] = {"required_glibc_versions": glibc,
                         "required_glibc_labels": glibc_labels,
                         "maximum_glibc": glibc[-1] if glibc else None,
                         "needed": re.findall(r"Shared library: \[(.*?)\]", dynamic),
                         "candidate_glibc": "2.17"}
        if args.case == "pcre2":
            builds = out / "target" / pins["target"] / "release/build"
            archives = list(builds.glob("pcre2-sys-*/out/libpcre2.a"))
            objects = list(builds.glob("pcre2-sys-*/out/*pcre2*.o"))
            outputs = [p.read_text(errors="replace") for p in builds.glob("pcre2-sys-*/output")]
            if not archives or not objects or not any(
                    "rustc-link-lib=static=pcre2" in text or "rustc-link-lib=static=libpcre2" in text
                    for text in outputs):
                raise RuntimeError("Bundled PCRE2 C archive/object/link evidence is incomplete")
            if any("pcre2" in item for item in report["elf"]["needed"]):
                raise RuntimeError("Unexpected dynamic PCRE2 dependency")
            report["pcre2_native"] = {
                "PCRE2_SYS_STATIC": "1", "C_compiler": compiler,
                "archives": [{"path": str(p.relative_to(out)), "sha256": digest(p)} for p in archives],
                "objects": [{"path": str(p.relative_to(out)), "sha256": digest(p)} for p in objects],
                "build_script_output": outputs,
                "source_route": "Pinned pcre2-sys build.rs bypasses pkg-config when PCRE2_SYS_STATIC=1; cc compiles bundled upstream/src C sources",
            }
        report["stage"] = "packaging"
        stage = out / "payload"
        (stage / "bin").mkdir(parents=True)
        shutil.copyfile(binary, stage / "bin/rg")
        (stage / "bin/rg").chmod(0o755)
        for name in ["COPYING", "LICENSE-MIT", "UNLICENSE", "README.md", "GUIDE.md", "FAQ.md", "CHANGELOG.md"]:
            shutil.copyfile(source / name, stage / name)
            (stage / name).chmod(0o644)
        if args.case == "pcre2":
            pcre2_pin = next(p for p in pins["registry_packages"] if p["name"] == "pcre2-sys")
            crate_name = "pcre2-sys-" + pcre2_pin["version"]
            crates = list((inputs / "cargo-home/registry/src").glob("*/" + crate_name))
            if len(crates) != 1:
                raise RuntimeError("Expected exactly one pinned prepared PCRE2 Cargo source")
            report["pcre2_native"]["license"] = retain_pcre2_license(
                crates[0], stage / "LICENSES/PCRE2.txt")
            report["pcre2_native"]["license"]["crate_pin"] = pcre2_pin
        manifest = inventory(stage)
        package = out / ("ripgrep-15.2.0-linux-x86_64-" + args.case + ".tar.gz")
        with package.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as tar:
                for path in sorted(stage.rglob("*")):
                    info = tar.gettarinfo(str(path), arcname=path.relative_to(stage).as_posix())
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = 0
                    if path.is_file():
                        with path.open("rb") as stream:
                            tar.addfile(info, stream)
                    else:
                        tar.addfile(info)
        extracted = out / "extracted"
        extracted.mkdir()
        run("independent-extraction", ["tar", "-xzf", str(package), "--no-same-owner", "-C", str(extracted)])
        if inventory(extracted) != manifest:
            raise RuntimeError("Independent extraction differs in files, hashes, sizes or modes")
        directories = [{"path": p.relative_to(stage).as_posix(), "mode": oct(p.stat().st_mode & 0o777)}
                       for p in sorted(stage.rglob("*")) if p.is_dir()]
        extracted_directories = [{"path": p.relative_to(extracted).as_posix(), "mode": oct(p.stat().st_mode & 0o777)}
                                 for p in sorted(extracted.rglob("*")) if p.is_dir()]
        if directories != extracted_directories or any(p.is_symlink() for p in extracted.rglob("*")):
            raise RuntimeError("Independent extraction has unexpected directories, modes or symlinks")
        run("independent-member-list", ["tar", "-tzvf", str(package)])
        report.update(payload_files=manifest, extracted_files=inventory(extracted),
                      payload_directories=directories, extracted_directories=extracted_directories,
                      built_binary_sha256=digest(binary),
                      package={"path": package.name, "sha256": digest(package),
                               "bytes": package.stat().st_size},
                      source_preserved=True, stage="abi-gate")
        if any(tuple(map(int, version.split("."))) > (2, 17) for version in glibc):
            raise RuntimeError("Artifact imports glibc newer than 2.17; baseline is unchanged")
        if any(not re.fullmatch(r"GLIBC_\d+(?:\.\d+)+", label) for label in glibc_labels):
            raise RuntimeError("Artifact has an unclassified GLIBC ABI requirement; review retained ELF data")
        report.update(status="built-and-packaged; runtime matrix pending", stage="complete")
        save()
    except Exception as error:
        report.update(status="failed", failure=str(error), traceback=traceback.format_exc())
        save()
        raise
    finally:
        report["finished_at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        save()


if __name__ == "__main__":
    main()
