#!/usr/bin/env python3
"""Reconstruct the public ripgrep reader fixture before CI disables network access."""

import argparse
import json
import os
from pathlib import Path
import shutil

from support import digest, execute, extract, inventory, now, verify, write_json

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    pins = json.loads((HERE / "input-pins.json").read_text())["reader_fixture"]
    if digest(args.archive) != pins["archive_sha256"]:
        raise RuntimeError("Public reader fixture archive digest changed")
    out = args.out_dir.resolve()
    extract(args.archive, out)
    verify(out, pins["archive_files"])
    for alias in pins["aliases"]:
        original = out / alias["source"]
        destination = out / alias["destination"]
        if digest(original) != alias["sha256"] or destination.exists():
            raise RuntimeError("Fixture package alias differs from the reviewed inventory")
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, destination)
        destination.chmod(0o644)
    verify(out, pins["materialized_files"])
    source = out / "source"
    source.mkdir()
    logs = out / "preparation-logs"
    logs.mkdir()
    env = os.environ.copy()
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
               GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    for key in list(env):
        if key.startswith("GIT_") and key not in {
                "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_TERMINAL_PROMPT", "GIT_OPTIONAL_LOCKS"}:
            env.pop(key)
    report = {"schema": 1, "archive_sha256": digest(args.archive), "started_at_utc": now(),
              "status": "running", "commands": []}
    try:
        for name, argv in [
            ("git-version", ["git", "--version"]),
            ("git-init", ["git", "init", "--quiet", str(source)]),
            ("git-fetch-upstream", ["git", "-C", str(source), "-c", "fetch.fsckObjects=true", "fetch",
                                    "--no-tags", "--depth=1", pins["upstream_url"], pins["upstream_commit"]]),
            ("git-bundle-verify", ["git", "-C", str(source), "bundle", "verify", str(out / "ripgrep-overlay.bundle")]),
            ("git-fetch-overlay", ["git", "-C", str(source), "-c", "fetch.fsckObjects=true", "fetch", "--no-tags",
                                   str(out / "ripgrep-overlay.bundle"), "HEAD"]),
            ("git-checkout", ["git", "-C", str(source), "checkout", "--detach", pins["source_commit"]]),
            ("git-status", ["git", "-C", str(source), "status", "--porcelain=v1", "--untracked-files=all"]),
            ("git-head", ["git", "-C", str(source), "rev-parse", "HEAD"]),
            ("git-tree", ["git", "-C", str(source), "rev-parse", "HEAD^{tree}"]),
        ]:
            result = execute(argv, env=env, timeout=600)
            write_json(logs / (name + ".json"), result)
            report["commands"].append({"name": name, "argv": result["argv"], "exit_code": result["exit_code"]})
            write_json(out / "prepared-fixture.json", report)
            if result["exit_code"] or result["timed_out"]:
                raise RuntimeError("Fixture preparation failed: " + name)
            expected = {"git-head": pins["source_commit"], "git-tree": pins["source_tree"], "git-status": ""}
            if name in expected and result["stdout"].strip() != expected[name]:
                raise RuntimeError("Reconstructed source identity differs: " + name)
        verify(source, pins["source_files"], exact=False)
        report.update(status="prepared; no consumer payload executed", source_commit=pins["source_commit"],
                      source_tree=pins["source_tree"], source_git_files=inventory(source / ".git"))
    except Exception as error:
        report.update(status="failed", failure=str(error))
        raise
    finally:
        report["finished_at_utc"] = now()
        write_json(out / "prepared-fixture.json", report)


if __name__ == "__main__":
    main()
