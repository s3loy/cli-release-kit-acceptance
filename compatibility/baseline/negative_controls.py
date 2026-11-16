#!/usr/bin/env python3
"""Evaluate two real ELF rejection controls, without changing the selected ABI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import tempfile
import traceback

HERE = Path(__file__).resolve().parent


def version_tuple(value):
    return tuple(map(int, value.split(".")))


def imports(text):
    # Read actual version-need entries, not arbitrary strings or definitions.
    needs = text.split("Version needs section", 1)
    if len(needs) != 2:
        return []
    return sorted(set(re.findall(r"Name:\s+GLIBC_(\d+(?:\.\d+)+)", needs[1])),
                  key=version_tuple)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--high-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    os.environ["BASELINE_OUT"] = str(out)
    core = runpy.run_path(str(HERE / "run.py"))
    core["native"]()
    command, docker, image = core["command"], core["docker"], core["image"]
    sha, dump = core["sha"], core["dump"]
    result = {"baseline": "glibc 2.17", "passed": False,
              "scope": "Isolated inspection prototype and actual loaders; not a product verifier"}
    try:
        highdir = out / "high"
        highdir.mkdir()
        high = highdir / "relship"
        shutil.copyfile(args.high_binary, high)
        high.chmod(0o755)
        _, cmd = docker("high-inspection", image("build217"),
            ["readelf", "-W", "--version-info", "/subject/relship"],
            [(highdir, "/subject", True)])
        _, observed = command("high-version-needs", cmd)
        required = imports(observed)
        assert required and version_tuple(required[-1]) == (2, 39), required
        result["high_requirement"] = {"binary_sha256": sha(high),
            "numeric_glibc_needs": required, "prototype_rejects_217": True}
        for label in ("runtime217", "runtime231", "runtime239"):
            _, cmd = docker("high-" + label, image(label), ["/subject/relship", "--version"],
                            [(highdir, "/subject", True)])
            code, _ = command("high-launch-" + label, cmd, required=False)
            stderr = (out / "controller-logs" / ("high-launch-" + label + ".stderr")).read_text(errors="replace")
            expected = code == 0 if label == "runtime239" else code != 0 and "GLIBC_2.39" in stderr
            assert expected, (label, code, stderr)
            result.setdefault("high_runtimes", []).append(
                {"runtime": label, "exit": code, "expected_observation": True})
        new = out / "new-libc"
        new.mkdir()
        export = "baseline-new-libc-" + str(os.getpid())
        core["OWNED"].add(export)
        command("new-libc-container", ["docker", "create", "--platform", "linux/amd64",
                                     "--label", "relship.baseline.owner=" + core["OWNER"],
                                     "--name", export, image("runtime239"), "/bin/true"])
        command("new-libc-copy", ["docker", "cp",
                 export + ":/lib/x86_64-linux-gnu/libc.so.6", str(new / "libc.so.6")])
        command("new-libc-remove", ["docker", "rm", export])
        core["OWNED"].discard(export)
        dump(new / "identity.json", {"source_image": image("runtime239"),
                                     "sha256": sha(new / "libc.so.6")})
        sdk = out / "sdk"
        sdk.mkdir()
        prepared = runpy.run_path(str(HERE / "ripgrep/harness/prepare-inputs.py"))
        pins = json.loads((HERE / "ripgrep/harness/input-pins.json").read_text())
        downloads = out / "downloads"
        downloads.mkdir()
        for item in pins["rust"]["components"]:
            path = downloads / item["local_archive"]
            prepared["download"](item["url"], path, item["sha256"])
            with tempfile.TemporaryDirectory(dir=out) as temp:
                prepared["extract"](path, Path(temp))
                top = Path(temp) / path.name.removesuffix(".tar.xz")
                for component in (top / "components").read_text().splitlines():
                    for child in (top / component).iterdir():
                        if child.name == "manifest.in":
                            continue
                        if child.is_dir():
                            shutil.copytree(child, sdk / child.name,
                                            dirs_exist_ok=True, symlinks=True)
                        else:
                            shutil.copy2(child, sdk / child.name)
        fixture = out / "fixture"
        fixture.mkdir()
        (fixture / "high.c").write_text(
            "extern unsigned long strlcpy(char *, const char *, unsigned long);\n"
            "int high_copy(char *out) { return (int)strlcpy(out, \"hello\", 16); }\n")
        (fixture / "main.c").write_text(
            "extern int high_copy(char *);\n"
            "int main(void) { char out[16]; return high_copy(out) == 5 ? 0 : 1; }\n")
        _, cmd = docker("dependency-control", image("build217"),
            ["/bin/bash", "/harness/control-build.sh"],
            [(HERE, "/harness", True), (fixture, "/out", False),
             (sdk, "/sdk", True), (new, "/new", True)])
        command("dependency-build", cmd, timeout=300)
        main_needs = imports((fixture / "main.versions").read_text())
        library_needs = imports((fixture / "library.versions").read_text())
        assert main_needs and all(version_tuple(v) <= (2, 17) for v in main_needs)
        assert library_needs and any(version_tuple(v) > (2, 17) for v in library_needs)
        result["dependency_requirement"] = {
            "main_sha256": sha(fixture / "control"), "library_sha256": sha(fixture / "libhigh.so"),
            "main_needs": main_needs, "library_needs": library_needs,
            "main_only_gate_passes": True, "closure_gate_rejects": True,
            "new_libc_sha256": sha(new / "libc.so.6")}
        for label in ("runtime217", "runtime231", "runtime239"):
            _, cmd = docker("closure-" + label, image(label), ["/payload/control"],
                            [(fixture, "/payload", True)])
            code, _ = command("closure-launch-" + label, cmd, required=False)
            err = (out / "controller-logs" / ("closure-launch-" + label + ".stderr")).read_text(errors="replace")
            expected = code == 0 if label == "runtime239" else code != 0 and "GLIBC_" in err
            assert expected, (label, code, err)
            result.setdefault("dependency_runtimes", []).append({"runtime": label, "exit": code})
        missing = out / "missing-library"
        missing.mkdir()
        shutil.copyfile(fixture / "control", missing / "control")
        (missing / "control").chmod(0o755)
        _, cmd = docker("missing-soname", image("runtime239"), ["/payload/control"],
                        [(missing, "/payload", True)])
        code, _ = command("missing-soname", cmd, required=False)
        err = (out / "controller-logs/missing-soname.stderr").read_text(errors="replace")
        assert code != 0 and "libhigh.so" in err
        result["missing_soname_rejected"] = True
        result["passed"] = True
    except Exception as exc:
        result["error"] = {"type": type(exc).__name__, "message": str(exc),
                           "traceback": traceback.format_exc()}
        raise
    finally:
        cleanup_errors = core["cleanup"]()
        result["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            result["passed"] = False
        dump(out / "result.json", result)
    assert result["passed"]


if __name__ == "__main__":
    main()
