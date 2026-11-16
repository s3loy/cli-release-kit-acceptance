#!/usr/bin/env python3
"""Build and package frozen relship in the caller's pinned offline glibc 2.17 container."""

import json
import os
from pathlib import Path
import re
import shutil
import traceback

from support import archive, digest, execute, inventory, now, verify, write_json


def main():
    inputs = Path(os.environ.get("INPUTS_ROOT", "/inputs")).resolve()
    out = Path(os.environ.get("CASE_OUT", "/out")).resolve()
    out.mkdir(parents=True, exist_ok=True)
    logs = out / "logs"
    logs.mkdir(exist_ok=True)
    report = {"schema": 1, "case": "R-old", "execution": "manual feasibility; native amd64 CI",
              "started_at_utc": now(), "status": "running", "stage": "input-validation"}
    env = os.environ.copy()
    source = inputs / "source"

    def save():
        write_json(out / "result.json", report)

    def run(name, argv, required=True, timeout=120):
        result = execute(argv, cwd=source, env=env, timeout=timeout)
        (logs / (name + ".stdout.log")).write_text(result.pop("stdout"))
        (logs / (name + ".stderr.log")).write_text(result.pop("stderr"))
        report.setdefault("commands", []).append({"name": name, **result})
        save()
        if required and (result["exit_code"] or result["timed_out"]):
            raise RuntimeError("Command failed: " + name)
        return (logs / (name + ".stdout.log")).read_text()

    try:
        pins = json.loads((inputs / "input-pins.json").read_text())
        prepared = json.loads((inputs / "prepared-inputs.json").read_text())
        if digest(inputs / "input-pins.json") != prepared["input_pins_sha256"]:
            raise RuntimeError("Prepared input pin record changed")
        sdk = inputs / "rust-sdk"
        verify(source, pins["engine_source_files"])
        verify(source, prepared["source_files"])
        verify(sdk, pins["sdk_files"])
        verify(sdk, prepared["sdk_files"])
        verify(inputs / "cargo-home", prepared["cargo_home_files"])
        image_environment = pins["build_image_environment"]
        for key, value in image_environment.items():
            if env.get(key) != value:
                raise RuntimeError("Pinned image environment mismatch: " + key)
        overrides = [key for key in env if key not in image_environment and (key.startswith("CARGO_PROFILE_")
                     or key.startswith("CARGO_TARGET_") or key in {
                         "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                         "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP", "CFLAGS",
                         "CXXFLAGS", "CPPFLAGS", "LDFLAGS", "LD_LIBRARY_PATH",
                         "LIBRARY_PATH", "PKG_CONFIG_PATH"})]
        if overrides:
            raise RuntimeError("Undeclared build overrides: " + ", ".join(sorted(overrides)))
        if env.get("BASELINE_IMAGE") != pins["build_image"]:
            raise RuntimeError("Caller must declare the reviewed BASELINE_IMAGE digest")
        shutil.copytree(inputs / "cargo-home", out / "cargo-home")
        compiler = shutil.which("cc") or shutil.which("gcc")
        if not compiler:
            raise RuntimeError("No C compiler in the pinned image for ring/zstd native code")
        env.update(PATH=str(sdk / "bin") + os.pathsep + env["PATH"],
                   CARGO_HOME=str(out / "cargo-home"), CARGO_TARGET_DIR=str(out / "target"),
                   CARGO_BUILD_JOBS="2", CARGO_NET_OFFLINE="true", CARGO_NET_RETRY="0",
                   RUSTC=str(sdk / "bin/rustc"), CC=compiler, CC_ENABLE_DEBUG_OUTPUT="1",
                   PYTHONDONTWRITEBYTECODE="1")
        report.update(input_pins_sha256=digest(inputs / "input-pins.json"),
                      prepared_inputs_sha256=digest(inputs / "prepared-inputs.json"),
                      engine_source_id=pins["engine_source_id"],
                      input_record=pins,
                      pinned_image_environment=image_environment,
                      environment={key: env[key] for key in sorted(env) if key in {
                          "PATH", "CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_BUILD_JOBS",
                          "CARGO_NET_OFFLINE", "CARGO_NET_RETRY", "RUSTC", "CC",
                          "CC_ENABLE_DEBUG_OUTPUT", "BASELINE_IMAGE", "CASE_OUT", "INPUTS_ROOT"}},
                      profile={"name": "release", "default_features": True,
                               "modified_product_configuration": False,
                               "native_dependencies": "Cargo.lock ring and zstd-sys compiled in this image"},
                      stage="tool-bootstrap")
        save()
        run("uname", ["uname", "-a"])
        if run("glibc", ["getconf", "GNU_LIBC_VERSION"]).strip() != "glibc 2.17":
            raise RuntimeError("Build userspace does not report glibc 2.17")
        for name, argv in [
            ("os-release", ["cat", "/etc/os-release"]),
            ("memory", ["cat", "/proc/meminfo"]), ("cpu", ["cat", "/proc/cpuinfo"]),
            ("cc-version", [compiler, "--version"]), ("cc-target", [compiler, "-dumpmachine"]),
            ("ld-version", ["ld", "--version"]), ("readelf-version", ["readelf", "--version"]),
            ("tar-version", ["tar", "--version"]), ("package-inventory", ["rpm", "-qa"]),
        ]:
            run(name, argv)
        linker = run("cc-linker", [compiler, "-print-prog-name=ld"]).strip()
        linker = shutil.which(linker) or linker
        run("cc-linker-version", [linker, "--version"])
        for tool in [sdk / "bin/rustc", sdk / "bin/cargo", *sorted((sdk / "lib").glob("*.so*"))]:
            run("sdk-" + tool.name + "-elf-versions",
                ["readelf", "-W", "--version-info", str(tool)], required=False)
        run("rustc-version", [str(sdk / "bin/rustc"), "--version", "--verbose"])
        run("cargo-version", [str(sdk / "bin/cargo"), "--version", "--verbose"])
        report["stage"] = "build"
        run("cargo-build", [str(sdk / "bin/cargo"), "build", "--locked", "--offline", "--release",
                            "--target", pins["target"], "--package", "relship", "--bin", "relship",
                            "-j", "2", "--manifest-path", str(source / "Cargo.toml"), "-vv"],
            timeout=2400)
        verify(source, prepared["source_files"])
        binary = out / "target" / pins["target"] / "release/relship"
        report["stage"] = "elf-inspection"
        for name, argv in [
            ("file", ["file", str(binary)]), ("elf-header", ["readelf", "-W", "-h", str(binary)]),
            ("elf-program-headers", ["readelf", "-W", "-l", str(binary)]),
            ("elf-dyn-symbols", ["readelf", "-W", "--dyn-syms", str(binary)]),
        ]:
            run(name, argv)
        dynamic = run("elf-dynamic", ["readelf", "-W", "-d", str(binary)])
        versions = run("elf-versions", ["readelf", "-W", "--version-info", str(binary)])
        run("ldd-build-environment", ["ldd", str(binary)], required=False)
        requirements = sorted(set(re.findall(r"GLIBC_(\d+(?:\.\d+)+)", versions)),
                              key=lambda value: tuple(map(int, value.split("."))))
        report["elf"] = {"required_glibc_versions": requirements,
                         "maximum_glibc": requirements[-1] if requirements else None,
                         "needed": re.findall(r"Shared library: \[(.*?)\]", dynamic),
                         "candidate_glibc": "2.17"}
        native_outputs = []
        for path in sorted((out / "target" / pins["target"] / "release/build").glob("*/output")):
            if path.parent.name.startswith(("ring-", "zstd-sys-")):
                target = logs / ("native-" + path.parent.name + ".log")
                shutil.copyfile(path, target)
                native_outputs.append({"name": path.parent.name, "sha256": digest(target),
                                       "log": target.relative_to(out).as_posix()})
        report["native_build_scripts"] = native_outputs
        report["stage"] = "packaging"
        payload = out / "payload"
        (payload / "bin").mkdir(parents=True)
        shutil.copyfile(binary, payload / "bin/relship")
        (payload / "bin/relship").chmod(0o755)
        shutil.copyfile(source / "LICENSE", payload / "LICENSE")
        (payload / "LICENSE").chmod(0o644)
        package = out / "relship-0.1.0-linux-x86_64-r-old.tar.gz"
        manifest = archive(payload, package)
        extracted = out / "extracted"
        extracted.mkdir()
        run("independent-extraction", ["tar", "-xzf", str(package), "--no-same-owner", "-C", str(extracted)])
        verify(extracted, manifest)
        report.update(payload_files=manifest, extracted_files=inventory(extracted), source_preserved=True,
                      package={"path": package.name, "sha256": digest(package), "bytes": package.stat().st_size},
                      stage="abi-gate")
        if any(tuple(map(int, version.split("."))) > (2, 17) for version in requirements):
            raise RuntimeError("Artifact imports glibc above 2.17; preserve the candidate baseline")
        info = json.loads(run("build-info", [str(extracted / "bin/relship"), "build-info", "--json",
                                             "--expect-source-id", pins["engine_source_id"],
                                             "--expect-version", "0.1.0", "--expect-contract", "1"]))
        report.update(build_info=info, status="built and packaged; runtime matrix pending", stage="complete")
    except Exception as error:
        report.update(status="failed", failure=str(error), traceback=traceback.format_exc())
        raise
    finally:
        report["finished_at_utc"] = now()
        save()


if __name__ == "__main__":
    main()
