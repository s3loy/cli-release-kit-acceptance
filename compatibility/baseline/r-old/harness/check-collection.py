#!/usr/bin/env python3
"""Verify retained public collection data in the old build image with its declared Git."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil

from support import digest, execute, inventory, now, verify, write_json

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    pins = json.loads((HERE / "input-pins.json").read_text())
    fixture = args.fixture_root.resolve()
    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema": 1, "case": "R-old", "started_at_utc": now(), "status": "running",
              "scope": "collection reader in glibc 2.17 build image with preinstalled Git; not a clean runtime qualification",
              "payload_execution": False, "binary_sha256": digest(args.binary), "commands": []}
    env = os.environ.copy()
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
               GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", PYTHONDONTWRITEBYTECODE="1")
    for key in list(env):
        if key.startswith("GIT_") and key not in {
                "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT", "GIT_OPTIONAL_LOCKS"}:
            env.pop(key)

    def run(name, argv, required=True):
        result = execute(argv, env=env, timeout=290)
        write_json(out / (name + ".json"), result)
        report["commands"].append({"name": name, "argv": result["argv"], "exit_code": result["exit_code"],
                                   "timed_out": result["timed_out"]})
        write_json(out / "assertions.json", report)
        if required and (result["exit_code"] or result["timed_out"]):
            raise RuntimeError("Collection check failed: " + name)
        return result["stdout"]

    try:
        if env.get("BASELINE_IMAGE") != pins["build_image"]:
            raise RuntimeError("Declare the reviewed BASELINE_IMAGE digest for functional scope")
        verify(fixture, pins["reader_fixture"]["materialized_files"], exact=False)
        verify(fixture / "source", pins["reader_fixture"]["source_files"], exact=False)
        prepared = json.loads((fixture / "prepared-fixture.json").read_text())
        verify(fixture / "source/.git", prepared["source_git_files"])
        before = inventory(fixture)
        source = out / "verify-work/source"
        source.parent.mkdir()
        # Docker's executing UID owns this copy, so Git's ownership guard stays enabled.
        # The fixture mount remains read-only and never needs a safe.directory exception.
        shutil.copytree(fixture / "source", source)
        verify(source, pins["reader_fixture"]["source_files"], exact=False)
        verify(source / ".git", prepared["source_git_files"])
        report["source_copy"] = {"path": str(source), "owner_uid": source.stat().st_uid,
                                 "executing_uid": os.getuid(), "git_inputs_preserved": True}
        git = shutil.which("git")
        if not git:
            raise RuntimeError("Pinned build image has no Git; do not install into clean runtimes")
        report["git"] = {"path": git, "sha256": digest(git),
                         "version": run("git-version", [git, "--version"]).strip()}
        run("uname", ["uname", "-a"])
        if run("glibc", ["getconf", "GNU_LIBC_VERSION"]).strip() != "glibc 2.17":
            raise RuntimeError("Functional environment differs from glibc 2.17")
        run("package-inventory", ["rpm", "-qa"])
        libraries = {}
        for name, executable in [("relship", args.binary.resolve()), ("git", Path(git))]:
            linked = run(name + "-ldd", ["ldd", str(executable)], required=False)
            paths = re.findall(r"(?:=>\s+)?(/[^\s()]+)", linked)
            libraries[name] = [{"path": path, "sha256": digest(Path(path))}
                               for path in sorted(set(paths)) if Path(path).is_file()]
        report["functional_runtime_libraries"] = libraries
        run("build-info", [str(args.binary.resolve()), "build-info", "--json", "--expect-source-id",
                           pins["engine_source_id"], "--expect-version", "0.1.0", "--expect-contract", "1"])
        collection = fixture / "collection"
        snapshot = json.loads(run("status", [str(args.binary.resolve()), "--project", str(source),
                                               "status", "--output", str(fixture / "status-attempt"), "--json"]))
        if (snapshot["engine_source_id"] != pins["engine_source_id"]
                or snapshot["status"] != "complete"
                or snapshot["plan_id"] != json.loads((collection / "plan.json").read_text())["id"]):
            raise RuntimeError("Status did not read the retained same-engine complete attempt")
        run("verify", [str(args.binary.resolve()), "--project", str(source),
                       "verify", "--output", str(collection), "--policy", str(fixture / "trust-policy.toml")])
        if before != inventory(fixture):
            raise RuntimeError("Reader modified frozen public fixture inputs")
        verify(source, pins["reader_fixture"]["source_files"], exact=False)
        report.update(status="passed", passed=2, fixture_preserved=True)
    except Exception as error:
        report.update(status="failed", failure=str(error))
        raise
    finally:
        report["finished_at_utc"] = now()
        write_json(out / "assertions.json", report)


if __name__ == "__main__":
    main()
