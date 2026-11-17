#!/usr/bin/env python3
"""Capture candidate SDK identities and bootstrap unreleased test engines only."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "engine-src"
HOST = os.environ.get("CURATION_HOST", "")
OUTPUT = Path("curation-output") / HOST
RUST_HOST = os.environ.get("CURATION_RUST_HOST", "")


def save(name, value):
    (OUTPUT / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(name, command, *, cwd=None, env=None, timeout=120, persist=True):
    argv = [str(s) for s in command]
    try:
        result = subprocess.run(argv, cwd=cwd, env=env,
                                capture_output=True, text=True, errors="replace", timeout=timeout)
        stdout, stderr, status, timed_out = result.stdout, result.stderr, result.returncode, False
    except subprocess.TimeoutExpired as error:
        def text(value):
            return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value or ""
        stdout, stderr, status, timed_out = text(error.stdout), text(error.stderr), None, True
    if persist:
        (OUTPUT / (name + ".stdout.log")).write_text(stdout, encoding="utf-8")
        (OUTPUT / (name + ".stderr.log")).write_text(stderr, encoding="utf-8")
    save(name + ".command.json", {"argv": argv, "exit_code": status,
                                  "timed_out": timed_out, "timeout_seconds": timeout,
                                  "output_retained": persist})
    if timed_out or status:
        detail = (stderr or stdout)[-8000:] if persist else "environment output omitted"
        failure = f"timed out after {timeout}s" if timed_out else f"failed with {status}"
        raise RuntimeError(f"{name} {failure}; {detail}")
    return stdout.strip()


def frozen_inputs():
    manifest = json.loads((HERE / "engine-source-files.json").read_text())
    actual = {p.relative_to(SOURCE).as_posix(): sha(p) for p in SOURCE.rglob("*") if p.is_file()}
    if actual != manifest["files"]:
        raise ValueError("frozen engine input SHA-256 manifest mismatch")
    digest = hashlib.sha256(b"cli-release-kit-engine-source/v1\0")
    for name in sorted(actual, key=lambda name: PurePosixPath(name).parts):
        if name in ("rust-toolchain.toml", "LICENSE"):
            continue
        path = SOURCE / name
        encoded, body = name.encode(), path.read_bytes()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
    if digest.hexdigest() != manifest["engine_source_id"]:
        raise ValueError("frozen engine source identity mismatch")
    save("engine-source-files.json", manifest)
    return manifest


def macos_candidate():
    developer = Path(run("xcode-select", ["xcode-select", "-p"])).resolve()
    sdk = Path(run("xcrun-sdk-path", ["xcrun", "--sdk", "macosx", "--show-sdk-path"])).resolve()
    version = run("xcrun-sdk-version", ["xcrun", "--sdk", "macosx", "--show-sdk-version"])
    tools = [Path(run("xcrun-" + tool, ["xcrun", "--sdk", "macosx", "--find", tool])).resolve()
             for tool in ("clang", "ar", "ld")]
    tools.append(Path("/usr/bin/make").resolve())
    resource = Path(run("clang-resource-dir", [tools[0], "-print-resource-dir"])).resolve(strict=True)
    if not (resource / "include").is_dir() or not (resource / "lib").is_dir():
        raise ValueError(f"selected Apple clang include/runtime closure is missing: {resource}")
    # Hash the C closure, avoiding unrelated Swift/LLDB aliases in the whole usr/lib tree.
    library_dirs = {p.parent.parent / "lib" for p in tools[:3]}
    library_dirs.add(developer / "usr/lib")
    library_files = []
    for name in ("libtapi.dylib", "libcodedirectory.dylib", "libLTO.dylib", "libswiftDemangle.dylib"):
        matches = sorted({(root / name).resolve(strict=True) for root in library_dirs if (root / name).is_file()})
        if len(matches) != 1:
            raise ValueError(f"Apple C closure needs one {name}; matches={list(map(str, matches))}; searched={sorted(str(p) for p in library_dirs)}")
        library_files.append(matches[0])
    env = os.environ.copy()
    env.update({"DEVELOPER_DIR": str(developer), "SDKROOT": str(sdk),
                "CC": str(tools[0]), "AR": str(tools[1]), "LD": str(tools[2])})
    roots = [sdk, resource, *library_files]
    implicit_include = tools[0].parent.parent / "include"
    if implicit_include.is_dir():
        roots.append(implicit_include.resolve(strict=True))
    return {"id": "apple-c-sdk-candidate", "version": version,
            "roots": [str(p) for p in roots], "tools": [str(p) for p in tools],
            "selected_toolchain_include": {"path": str(implicit_include), "included": implicit_include.is_dir()},
            "generator_candidate": "Unix Makefiles"}, env


def append_rust_candidate(candidate, bootstrap_tools):
    paths = [Path(bootstrap_tools[name]["path"]).resolve(strict=True) for name in ("cargo", "rustc")]
    if any(path.parent.name.lower() != "bin" for path in paths):
        raise ValueError("Rust tools must be native executables in a reviewed prefix/bin directory")
    prefixes = {path.parent.parent for path in paths}
    if len(prefixes) != 1:
        raise ValueError("native cargo and rustc have different pinned toolchain prefixes")
    prefix = prefixes.pop()
    target_libraries = prefix / "lib/rustlib" / RUST_HOST / "lib"
    if not target_libraries.is_dir():
        raise ValueError(f"native Rust target library closure is missing: {target_libraries}")
    candidate["roots"] = list(dict.fromkeys([*candidate["roots"], str(prefix)]))
    candidate["tools"] = list(dict.fromkeys([*candidate["tools"], *(str(path) for path in paths)]))
    candidate["tool_sha256"] = {path: sha(path) for path in candidate["tools"]}
    candidate["language_toolchains"] = {
        "rust": {"version": "1.96.0", "native_host": RUST_HOST, "prefix": str(prefix),
                 "target_libraries": str(target_libraries), "status": "captured-for-review"},
        "go": {"required_version": "1.27.4", "status": "pending", "ambient_tools_pinned": False}}


def pe_machine(path):
    with Path(path).open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise ValueError(f"candidate is not PE: {path}")
        stream.seek(0x3C)
        offset = struct.unpack("<I", stream.read(4))[0]
        stream.seek(offset)
        if stream.read(4) != b"PE\0\0":
            raise ValueError(f"candidate has invalid PE signature: {path}")
        return hex(struct.unpack("<H", stream.read(2))[0])


def windows_candidate():
    vswhere = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio/Installer/vswhere.exe"
    installations = json.loads(run("vswhere", [vswhere, "-all", "-products", "*", "-format", "json", "-utf8"]))
    discovery = []
    for item in installations:
        root = Path(item["installationPath"])
        discovery.append({"installation": str(root), "version": item["installationVersion"],
                          "toolset_roots": sorted(str(p) for p in (root / "VC/Tools/MSVC").glob("*")),
                          "redist_roots": sorted(str(p) for p in (root / "VC/Redist/MSVC").glob("*"))})
    kits = Path(os.environ["ProgramFiles(x86)"]) / "Windows Kits/10"
    save("windows-discovery.json", {"review_status": "candidate-discovery-only", "visual_studio": discovery,
                                    "windows_sdk_lib_roots": sorted(str(p) for p in (kits / "Lib").glob("*"))})
    selected = run("vswhere-selected", [vswhere, "-latest", "-products", "*", "-property", "installationPath"])
    if not selected or "\n" in selected:
        raise ValueError("no single Visual Studio candidate installation")
    vs = Path(selected)
    arch = "arm64" if HOST.endswith("aarch64") else "amd64"
    # Keep cmd.exe's /c argument free of nested quotes: Python's Windows argv
    # quoting targets the C runtime and is not cmd.exe batch quoting.
    script = OUTPUT / "capture-vs-env.cmd"
    script.write_text(
        f'@echo off\ncall "{vs / "Common7/Tools/VsDevCmd.bat"}" '
        f'-no_logo -arch={arch} -host_arch={arch} '
        '>vsdevcmd.stdout.log 2>vsdevcmd.stderr.log\n'
        'if errorlevel 1 exit /b %errorlevel%\nset\n', encoding="utf-8")
    # Keep the complete SET output in memory only. It can contain CI credentials.
    raw = run("vsdevcmd", ["cmd.exe", "/d", "/s", "/c", script.name],
              cwd=OUTPUT, persist=False)
    env = os.environ.copy()
    for line in raw.splitlines():
        if "=" in line and not line.startswith("="):
            key, value = line.split("=", 1)
            env[key] = value
    normalized = {k.upper(): v for k, v in env.items()}
    required = ["VCTOOLSINSTALLDIR", "WINDOWSSDKDIR", "WINDOWSSDKVERSION", "INCLUDE", "LIB", "LIBPATH"]
    if any(not normalized.get(k) for k in required):
        raise ValueError("developer command shell did not identify a complete candidate SDK")
    toolset = Path(normalized["VCTOOLSINSTALLDIR"])
    sdkroot = Path(normalized["WINDOWSSDKDIR"])
    sdkversion = normalized["WINDOWSSDKVERSION"].rstrip("\\/")
    target_arch = "arm64" if HOST.endswith("aarch64") else "x64"
    tools = [Path(shutil.which(n, path=normalized["PATH"]) or "")
             for n in ("cl.exe", "link.exe", "lib.exe", "nmake.exe", "rc.exe", "mt.exe")]
    if any(not p.is_file() for p in tools):
        raise ValueError("candidate Windows compiler/backend/SDK tools are missing")
    expected_machine = "0xaa64" if target_arch == "arm64" else "0x8664"
    if any(pe_machine(p) != expected_machine for p in tools[:4]):
        raise ValueError("MSVC candidate compiler tools do not run natively on this host")
    roots = [toolset, sdkroot / "Include" / sdkversion, sdkroot / "Lib" / sdkversion,
             sdkroot / "bin" / sdkversion]
    redist = sorted((vs / "VC/Redist/MSVC").glob("*"))
    license_candidates = []
    patterns = ["[Ll]icense*", "*[Ee][Uu][Ll][Aa]*", "VC/Redist/MSVC/**/[Ll]icense*", "VC/Redist/MSVC/**/[Rr]edist*.txt",
                "Licenses/**/*", "Common7/IDE/*[Ll]icense*", "Common7/IDE/*[Ee][Uu][Ll][Aa]*"]
    for pattern in patterns:
        for path in vs.glob(pattern):
            if path.is_file():
                license_candidates.append({"source": str(path.resolve()), "sha256": sha(path)})
    dll_candidates = []
    for root in redist:
        for path in (root / target_arch).glob("**/*.dll"):
            debug = any("debug" in part.lower() for part in path.relative_to(root).parts)
            if not debug and not path.name.lower().endswith("d.dll") and path.name.lower().startswith(("vcruntime", "msvcp", "concrt")):
                dll_candidates.append({"source": str(path.resolve()), "sha256": sha(path), "pe_machine": pe_machine(path)})
    save("windows-runtime-candidates.json", {
        "review_status": "unreviewed", "license_approval": False, "runtime_policy_generated": False,
        "selection_method": "installed-VsDevCmd-defaults-recorded-for-review",
        "target_arch": target_arch, "msvc_toolset_root": str(toolset), "windows_sdk_root": str(sdkroot),
        "windows_sdk_version": sdkversion, "redist_roots": [str(p) for p in redist],
        "license_globs": patterns, "license_candidates": license_candidates, "dll_candidates": dll_candidates,
        "next_review": "Select exact release CRT DLLs and redistributable license inputs, verify rights, then inspect explicit runtime policy."})
    env.update({"CC": str(tools[0]), "AR": str(tools[2]), "LD": str(tools[1])})
    return {"id": "msvc-c-sdk-candidate", "version": toolset.name + "+sdk-" + sdkversion,
            "roots": [str(p.resolve()) for p in roots], "tools": [str(p.resolve()) for p in tools],
            "generator_candidate": "NMake Makefiles"}, env


def main():
    OUTPUT.mkdir(parents=True, exist_ok=False)
    observed_os = {"Linux": "linux", "Darwin": "macos", "Windows": "windows"}.get(platform.system())
    observed_arch = {"x86_64": "x86_64", "amd64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64"}.get(platform.machine().lower())
    if HOST != f"{observed_os}-{observed_arch}":
        raise ValueError("runner process host OS/architecture differs from proposed native matrix")
    save("host.json", {"host": HOST, "platform": platform.platform(), "machine": platform.machine(),
                       "runner_label": os.environ.get("CURATION_RUNNER_LABEL"),
                       "runner_arch": os.environ.get("RUNNER_ARCH"), "image_os": os.environ.get("ImageOS"),
                       "image_version": os.environ.get("ImageVersion"), "github_sha": os.environ.get("GITHUB_SHA"),
                       "github_run_id": os.environ.get("GITHUB_RUN_ID"), "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT")})
    manifest = frozen_inputs()
    candidate, sdk_env = (None, os.environ.copy())
    if observed_os == "macos":
        candidate, sdk_env = macos_candidate()
    elif observed_os == "windows":
        candidate, sdk_env = windows_candidate()
    if candidate:
        candidate["tool_sha256"] = {path: sha(path) for path in candidate["tools"]}
        save("sdk-selection-candidate.json", candidate)
    toolchain = "1.96.0-" + RUST_HOST
    run("rustup-version", ["rustup", "--version"])
    run("rustup-install", ["rustup", "toolchain", "install", toolchain, "--profile", "minimal", "--no-self-update"], timeout=300)
    rustc = run("rustc-version", ["rustup", "run", toolchain, "rustc", "-vV"])
    if not rustc.startswith("rustc 1.96.0 ") or f"host: {RUST_HOST}" not in rustc.splitlines():
        raise ValueError("Rust compiler version or native host differs from requested toolchain")
    bootstrap_tools = {}
    for name in ("cargo", "rustc"):
        path = Path(run("rustup-which-" + name, ["rustup", "which", "--toolchain", toolchain, name])).resolve()
        bootstrap_tools[name] = {"path": str(path), "sha256": sha(path)}
    save("bootstrap-tool-identities.json", bootstrap_tools)
    if candidate:
        append_rust_candidate(candidate, bootstrap_tools)
        save("sdk-selection-candidate.json", candidate)
    cargo_env = sdk_env.copy()
    cargo_env["CARGO_TARGET_DIR"] = str((SOURCE.parent / "engine-target").resolve())
    run("engine-build", ["rustup", "run", toolchain, "cargo", "build", "--locked", "--release", "--bin", "relship"],
        cwd=SOURCE, env=cargo_env, timeout=1200)
    filename = "relship" + (".exe" if observed_os == "windows" else "")
    engine = Path(cargo_env["CARGO_TARGET_DIR"]) / "release" / filename
    info = json.loads(run("engine-build-info", [engine, "build-info", "--json", "--expect-source-id", manifest["engine_source_id"]]))
    if info["target"] != RUST_HOST:
        raise ValueError("test engine target differs from native host")
    shutil.copy2(engine, OUTPUT / filename)
    shutil.copy2(SOURCE / "LICENSE", OUTPUT / "LICENSE")
    save("engine-artifact.json", {"kind": "unreleased-test-engine", "host": HOST, "filename": filename,
                                  "sha256": sha(engine), "build_info": info, "consumer_install_url": None,
                                  "rust_toolchain": toolchain, "controlled_https_bootstrap_ready": False})
    if candidate:
        command = [engine, "ci", "inspect-sdk", "--id", candidate["id"], "--version", candidate["version"]]
        for root in candidate["roots"]:
            command.extend(["--root", root])
        for tool in candidate["tools"]:
            command.extend(["--tool", tool])
        sdk = json.loads(run("inspect-sdk", command, env=sdk_env, timeout=600))
        save("sdk-candidate.json", sdk)
    save("capture-result.json", {"status": "captured-for-review", "reviewed_sdk_pin": False,
                                 "sdk_capture_applicable": candidate is not None,
                                 "linux_builtin_baseline_changed": False, "consumer_ci_qualification": False,
                                 "windows_runtime_policy_accepted": False, "publication_ready": False})


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        if OUTPUT.is_dir():
            save("capture-failure.json", {"status": "failed", "error_type": type(error).__name__, "message": str(error),
                                          "consumer_ci_qualification": False, "publication_ready": False})
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
