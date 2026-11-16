#!/usr/bin/env python3
"""Check bare relship launch in a clean userspace using a host-side command prefix."""

import argparse
import json
from pathlib import Path

from support import digest, execute, now, write_json

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--host-binary", type=Path)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--exec-prefix-json", default="[]")
    parser.add_argument("--environment-id", required=True)
    parser.add_argument("--expected-glibc", choices=["2.17", "2.31", "2.39"], required=True)
    args = parser.parse_args()
    prefix = json.loads(args.exec_prefix_json)
    if not isinstance(prefix, list) or not all(isinstance(value, str) for value in prefix):
        parser.error("Execution prefix must be a JSON string array")
    if prefix and not args.host_binary:
        parser.error("Prefix mode requires --host-binary for the inspected local bytes")
    pins = json.loads((HERE / "input-pins.json").read_text())
    binary = str(args.binary if prefix else args.binary.resolve())
    host_binary = args.host_binary or args.binary.resolve()
    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    report = {"schema": 1, "case": "R-old", "scope": "bare launch in clean runtime; no Git provisioned",
              "environment_id": args.environment_id, "expected_glibc": args.expected_glibc,
              "binary_sha256": digest(host_binary), "started_at_utc": now(),
              "status": "running", "commands": []}
    try:
        for name, argv in [
            ("uname", ["uname", "-a"]), ("glibc", ["getconf", "GNU_LIBC_VERSION"]),
            ("os-release", ["cat", "/etc/os-release"]),
            ("runtime-library-identity", ["sh", "-c",
                "for f in /lib64/ld-linux-x86-64.so.2 /lib64/libc.so.6 /lib/x86_64-linux-gnu/libc.so.6 "
                "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2; do "
                "if test -f \"$f\"; then sha256sum \"$f\"; fi; done"]),
            ("version", [binary, "--version"]),
            ("build-info", [binary, "build-info", "--json", "--expect-source-id", pins["engine_source_id"],
                            "--expect-version", "0.1.0", "--expect-contract", "1"]),
            ("targets", [binary, "targets", "--json"]),
        ]:
            result = execute(prefix + argv, timeout=60)
            write_json(out / (name + ".json"), result)
            report["commands"].append({"name": name, "argv": result["argv"],
                                       "exit_code": result["exit_code"], "timed_out": result["timed_out"]})
            write_json(out / "assertions.json", report)
            if result["exit_code"] or result["timed_out"]:
                raise RuntimeError("Bare runtime command failed: " + name)
            if name == "glibc" and result["stdout"].strip() != "glibc " + args.expected_glibc:
                raise RuntimeError("Runtime libc differs from selected profile")
            if name == "build-info":
                info = json.loads(result["stdout"])
                if info["target"] != pins["target"]:
                    raise RuntimeError("Built target differs from the pinned Linux target")
            if name == "targets" and not json.loads(result["stdout"]):
                raise RuntimeError("Empty targets catalog")
        report.update(status="passed", passed=3)
    except Exception as error:
        report.update(status="failed", failure=str(error))
        raise
    finally:
        report["finished_at_utc"] = now()
        write_json(out / "assertions.json", report)


if __name__ == "__main__":
    main()
