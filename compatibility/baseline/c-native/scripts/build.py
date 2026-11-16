#!/usr/bin/env python3
"""Build the isolated curl/OpenSSL baseline case inside the pinned Linux image."""

from pathlib import Path
import gzip
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import traceback
from perl_dependencies import prepare as prepare_perl_dependencies


SCRIPT_DIR = Path(__file__).resolve().parent
PIN_FILE = SCRIPT_DIR.parent / "inputs.json"
PINS = json.loads(PIN_FILE.read_text())
OUT = Path(os.environ["CASE_OUT"]).resolve()
INPUTS = Path(os.environ["INPUTS_ROOT"]).resolve()
JOBS = int(os.environ.get("JOBS", "2"))
assert 1 <= JOBS <= 2, "the initial case permits at most two compiler jobs"
OUT.mkdir(parents=True, exist_ok=True)
LOGS = OUT / "logs"
LOGS.mkdir(exist_ok=True)
EVIDENCE = OUT / "evidence"
EVIDENCE.mkdir(exist_ok=True)
COMMANDS = []
START = time.monotonic()
DEADLINE = START + 40 * 60
ENV = os.environ.copy()
ENV.update({"LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "0"})
ENV["CFLAGS"] = "-O2 -march=x86-64 -mtune=generic"
ENV["PKG_CONFIG_LIBDIR"] = str(OUT / "empty-pkg-config")
STAGE = "input-preparation"


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run(name, argv, cwd=None, timeout=300, stdin_path=None, stdout_path=None):
    remaining = min(timeout, DEADLINE - time.monotonic())
    if remaining <= 0:
        raise TimeoutError("40-minute case build budget exhausted")
    started = time.monotonic()
    output_path = stdout_path or LOGS / (name + ".stdout")
    with output_path.open("wb") as stdout, (LOGS / (name + ".stderr")).open("wb") as stderr, \
            (stdin_path or Path(os.devnull)).open("rb") as stdin:
        process = subprocess.Popen([str(x) for x in argv], cwd=cwd, env=ENV,
                                   stdin=stdin, stdout=stdout, stderr=stderr, start_new_session=True)
        timed_out = False
        try:
            code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                code = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                code = process.wait()
    COMMANDS.append({"name": name, "stage": STAGE, "argv": [str(x) for x in argv],
                     "cwd": str(cwd) if cwd else None, "exit_code": code,
                     "timed_out": timed_out, "seconds": round(time.monotonic() - started, 3),
                     "stdin": str(stdin_path.relative_to(OUT)) if stdin_path else None,
                     "stdout": str(output_path.relative_to(OUT)), "stderr": "logs/" + name + ".stderr"})
    dump(EVIDENCE / "commands.json", COMMANDS)
    print(name, "exit=" + str(code), "seconds=" + str(COMMANDS[-1]["seconds"]), flush=True)
    if code != 0 or timed_out:
        raise RuntimeError(name + " failed; preserve its first stdout/stderr")
    return output_path.read_text(errors="replace") if stdout_path is None else ""


def extract(archive, destination):
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as package:
        package.extractall(destination, filter="data")


def inventory(root):
    return [{"path": path.relative_to(root).as_posix(), "sha256": sha(path),
             "size": path.stat().st_size, "mode": oct(path.stat().st_mode & 0o777)}
            for path in sorted(root.rglob("*")) if path.is_file()]


def main():
    global STAGE
    assert not (OUT / "work").exists(), "use a fresh CASE_OUT; do not overwrite prior build evidence"
    work = OUT / "work"
    sources = work / "sources"
    tools = work / "tools"
    selected = []
    for item in PINS["archives"]:
        archive = INPUTS / item["filename"]
        actual = sha(archive)
        assert actual == item["sha256"], (item["filename"], actual, item["sha256"])
        selected.append({**item, "actual_sha256": actual, "actual_size": archive.stat().st_size})
        extract(archive, tools if item["role"] == "cmake-tool" else sources)
    dump(EVIDENCE / "inputs.json", {"archives": selected, "baseline_image": os.environ.get("BASELINE_IMAGE"),
                                    "execution": os.environ.get("CASE_EXECUTION", "native-x86_64-ci"),
                                    "script_inventory": inventory(SCRIPT_DIR),
                                    "environment": {k: ENV[k] for k in ["PATH", "CFLAGS", "PKG_CONFIG_LIBDIR", "SOURCE_DATE_EPOCH", "LC_ALL", "TZ"]}})
    cmake = tools / "cmake-3.31.12-linux-x86_64/bin/cmake"
    curl_source = sources / "curl-8.23.0"
    openssl_source = sources / "openssl-3.5.9"
    dump(EVIDENCE / "source-replay.json", {"curl": inventory(curl_source), "openssl": inventory(openssl_source)})
    STAGE = "tool-bootstrap"
    run("uname", ["uname", "-a"])
    run("libc-version", ["getconf", "GNU_LIBC_VERSION"])
    run("c-compiler", [ENV.get("CC", "gcc"), "--version"])
    run("c-compiler-target", [ENV.get("CC", "gcc"), "-dumpmachine"])
    run("linker", ["ld", "--version"])
    run("make", ["make", "--version"])
    tar_version = run("tar-version", ["tar", "--version"])
    assert "GNU tar" in tar_version, tar_version
    run("perl", ["perl", "-V"])
    run("readelf", ["readelf", "--version"])
    run("python", [sys.executable, "--version"])
    run("rpm-inventory", ["rpm", "-qa", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n"])
    run("cmake-tool-elf", ["readelf", "-W", "-h", "-l", "-d", "-V", cmake])
    run("cmake-bootstrap", [cmake, "--version"])
    libc = (LOGS / "libc-version.stdout").read_text().strip()
    assert libc == "glibc 2.17", libc
    assert "x86_64" in (LOGS / "c-compiler-target.stdout").read_text()
    STAGE = "perl-dependency-preparation"
    prepare_perl_dependencies(PINS, INPUTS, OUT, ENV, run, dump, inventory, sha)
    STAGE = "native-dependency-build"
    openssl_build = work / "openssl-build"
    openssl_build.mkdir()
    openssl_install = work / "openssl-install"
    run("openssl-configure", ["perl", openssl_source / "Configure", "linux-x86_64",
                               "no-shared", "no-module", "no-tests", "--prefix=" + str(openssl_install), "--libdir=lib"],
        cwd=openssl_build)
    run("openssl-build", ["make", "-j" + str(JOBS), "build_sw"], cwd=openssl_build, timeout=2400)
    run("openssl-install", ["make", "install_sw"], cwd=openssl_build, timeout=300)
    run("openssl-identity", [openssl_install / "bin/openssl", "version", "-a"])
    dump(EVIDENCE / "openssl-inventory.json", inventory(openssl_install))
    assert not list((openssl_install / "lib").glob("*.so*")), "OpenSSL shared library appeared"
    STAGE = "cmake-configure"
    curl_build = work / "curl-build"
    query = curl_build / ".cmake/api/v1/query"
    query.mkdir(parents=True)
    (query / "codemodel-v2").touch()
    (query / "toolchains-v1").touch()
    run("curl-configure", [cmake, "-S", curl_source, "-B", curl_build, "-G", "Unix Makefiles",
                           "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_C_FLAGS_RELEASE=-O2 -DNDEBUG -march=x86-64 -mtune=generic",
                           "-DBUILD_SHARED_LIBS=OFF", "-DBUILD_STATIC_LIBS=ON", "-DBUILD_CURL_EXE=ON",
                           "-DBUILD_TESTING=OFF", "-DBUILD_EXAMPLES=OFF", "-DCURL_DISABLE_INSTALL=ON",
                           "-DCURL_USE_OPENSSL=ON", "-DOPENSSL_USE_STATIC_LIBS=TRUE",
                           "-DOPENSSL_ROOT_DIR=" + str(openssl_install),
                           "-DOPENSSL_INCLUDE_DIR=" + str(openssl_install / "include"),
                           "-DOPENSSL_SSL_LIBRARY=" + str(openssl_install / "lib/libssl.a"),
                           "-DOPENSSL_CRYPTO_LIBRARY=" + str(openssl_install / "lib/libcrypto.a"),
                           "-DCURL_USE_LIBPSL=OFF", "-DCURL_ZLIB=OFF", "-DCURL_BROTLI=OFF", "-DCURL_ZSTD=OFF",
                           "-DUSE_LIBIDN2=OFF", "-DCURL_USE_LIBSSH2=OFF", "-DCURL_USE_LIBSSH=OFF",
                           "-DUSE_NGHTTP2=OFF", "-DUSE_NGTCP2=OFF", "-DUSE_QUICHE=OFF", "-DCURL_USE_GSSAPI=OFF",
                           "-DCURL_DISABLE_LDAP=ON", "-DCURL_CA_FALLBACK=OFF", "-DCURL_CA_BUNDLE=none", "-DCURL_CA_PATH=none"], timeout=600)
    STAGE = "cmake-target-discovery"
    reply = curl_build / ".cmake/api/v1/reply"
    indices = sorted(reply.glob("index-*.json"))
    assert len(indices) == 1, "expected exactly one fresh File API index"
    index = json.loads(indices[0].read_text())
    codemodel_ref = index["reply"]["codemodel-v2"]
    assert codemodel_ref["kind"] == "codemodel" and codemodel_ref["version"]["major"] == 2
    codemodel = json.loads((reply / codemodel_ref["jsonFile"]).read_text())
    matches = []
    for config in codemodel["configurations"]:
        for ref in config["targets"]:
            target = json.loads((reply / ref["jsonFile"]).read_text())
            if target["name"] == "curl" and target["type"] == "EXECUTABLE":
                matches.append(target)
    assert len(matches) == 1, "curl executable target missing or ambiguous"
    target = matches[0]
    languages = sorted({group["language"] for group in target["compileGroups"]})
    assert languages == ["C"], languages
    assert len(target["artifacts"]) == 1, target["artifacts"]
    executable = (curl_build / target["artifacts"][0]["path"]).resolve()
    assert executable.is_relative_to(curl_build.resolve()), "File API executable escapes build directory"
    dump(EVIDENCE / "cmake-target.json", {"index": indices[0].name, "codemodel": codemodel_ref,
                                         "target": target, "resolved_executable": str(executable),
                                         "compile_languages": languages})
    shutil.copytree(reply, EVIDENCE / "cmake-file-api")
    STAGE = "curl-build"
    run("curl-build", [cmake, "--build", curl_build, "--target", "curl", "--parallel", str(JOBS)], timeout=2400)
    assert executable.is_file()
    STAGE = "elf-inspection"
    run("curl-file", ["file", executable])
    elf = run("curl-elf", ["readelf", "-W", "-h", "-l", "-d", "-V", executable])
    run("curl-dynamic-symbols", ["readelf", "-W", "--dyn-syms", executable])
    closure_output = run("curl-linked-closure", ["ldd", executable])
    assert "not found" not in closure_output, closure_output
    closure_paths = sorted({Path(match).resolve() for match in re.findall(r"(?:=>\s+|^\s+)(/\S+)", closure_output, re.MULTILINE)})
    closure = []
    for number, path in enumerate(closure_paths):
        observed = run("curl-library-" + str(number), ["readelf", "-W", "-h", "-d", "-V", path])
        library_versions = sorted(set(re.findall(r"\bGLIBC_([0-9]+(?:\.[0-9]+)+)\b", observed)),
                                  key=lambda value: tuple(map(int, value.split("."))))
        closure.append({"resolved_path": str(path), "sha256": sha(path), "size": path.stat().st_size,
                        "observed_glibc_versions": library_versions,
                        "note": "readelf observations include this system library's definitions and requirements"})
    dump(EVIDENCE / "runtime-library-inventory.json", closure)
    version = run("curl-version", [executable, "--version"])
    versions = sorted(set(re.findall(r"\bGLIBC_([0-9]+(?:\.[0-9]+)+)\b", elf)), key=lambda value: tuple(map(int, value.split("."))))
    needed = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", elf)
    maximum = max((tuple(map(int, value.split("."))) for value in versions), default=(0,))
    abi = {"glibc_requirements": versions, "maximum_glibc": versions[-1] if versions else None,
           "baseline": "2.17", "within_baseline": maximum <= (2, 17), "needed": needed,
           "sha256": sha(executable), "openssl_static": not any("ssl" in item or "crypto" in item for item in needed)}
    dump(EVIDENCE / "abi.json", abi)
    assert abi["within_baseline"], "actual curl ELF exceeds glibc 2.17; do not raise the baseline"
    assert abi["openssl_static"], needed
    assert "curl 8.23.0" in version and "OpenSSL/3.5.9" in version and "https" in version
    STAGE = "archive-packaging"
    package_name = "curl-8.23.0-linux-x86_64-glibc2.17-manual"
    stage = OUT / "stage" / package_name
    (stage / "bin").mkdir(parents=True)
    (stage / "LICENSES").mkdir()
    shutil.copy2(executable, stage / "bin/curl")
    shutil.copyfile(curl_source / "COPYING", stage / "COPYING")
    shutil.copyfile(openssl_source / "LICENSE.txt", stage / "LICENSES/OPENSSL.txt")
    (stage / "version.txt").write_text(version)
    dump(stage / "BUILD.json", {"scope": "isolated manual CMake baseline case; not a relship receipt",
                                "source_archives": selected, "abi": abi,
                                "baseline_image": os.environ.get("BASELINE_IMAGE"), "executable_sha256": sha(executable)})
    archive = OUT / (package_name + ".tar.gz")
    with archive.open("wb") as stream, gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode="w") as package:
        for path in [stage] + sorted(stage.rglob("*")):
            info = package.gettarinfo(str(path), arcname=str(path.relative_to(stage.parent)))
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            if info.isfile():
                with path.open("rb") as content:
                    package.addfile(info, content)
            else:
                package.addfile(info)
    extracted = OUT / "extracted"
    extracted.mkdir()
    run("archive-independent-extract", ["tar", "--extract", "--gzip", "--file", archive,
                                        "--directory", extracted, "--no-same-owner", "--same-permissions"])
    extracted_exe = extracted / package_name / "bin/curl"
    assert sha(extracted_exe) == sha(executable)
    assert inventory(stage) == inventory(extracted / package_name)
    dump(EVIDENCE / "package.json", {"archive": archive.name, "archive_sha256": sha(archive),
                                     "archive_size": archive.stat().st_size, "executable_sha256": sha(executable),
                                     "extracted_executable": str(extracted_exe.relative_to(OUT)),
                                     "archive_writer": "Python tarfile with gzip mtime=0",
                                     "independent_extractor": "build-image GNU tar; see tar-version and archive-independent-extract command records",
                                     "independent_extraction_matches_stage": True, "files": inventory(stage)})
    dump(OUT / "result.json", {"status": "built-and-packaged", "stage": STAGE,
                              "seconds": round(time.monotonic() - START, 3),
                              "runtime_acceptance": "pending clean runtime and host-driven 12-check matrix",
                              "product_integration": False})


try:
    main()
except BaseException as error:
    dump(OUT / "result.json", {"status": "failed", "stage": STAGE, "exception": str(error),
                              "seconds": round(time.monotonic() - START, 3), "product_integration": False})
    traceback.print_exc()
    raise
