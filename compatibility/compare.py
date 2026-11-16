#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--input", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
reports = [json.loads(path.read_text()) for path in sorted(args.input.glob("*/report/result.json"))]
assert len(reports) == 2, "Both matrix reports are required"
by_runner = {report["runner"]: report for report in reports}
assert set(by_runner) == {"ubuntu-22.04", "ubuntu-24.04"}
assert all(report["status"] == "passed" for report in reports)
assert len({report["engine_source_id"] for report in reports}) == 1
assert len({report["source_commit"] for report in reports}) == 1
assert len({report["source_tree"] for report in reports}) == 1
rows = []
for runner, report in sorted(by_runner.items()):
    rows.append({"runner": runner, "payload_sha256": report["elf"]["payload"]["sha256"],
                 "max_glibc_version": report["elf"]["payload"]["max_glibc_version"],
                 "interpreter": report["elf"]["payload"]["interpreter"],
                 "needed": report["elf"]["payload"]["needed"],
                 "userspaces": {image["image"]["name"]: {
                     "libc": image["libc"], "passed": all(binary["passed"] for binary in image["binaries"].values()),
                     "binaries": image["binaries"]} for image in report["userspace_observations"]}})
for old, new in zip(by_runner["ubuntu-22.04"]["userspace_observations"], by_runner["ubuntu-24.04"]["userspace_observations"]):
    assert old["image"] == new["image"], "A/B must run the same pinned userspace images"
result = {"schema": 1, "status": "observed", "engine_source_id": reports[0]["engine_source_id"],
          "source_commit": reports[0]["source_commit"], "rust_toolchain": "1.96.0", "rows": rows,
          "interpretation": "Compare required GLIBC versions and actual CLI results; older-userspace failures are retained observations.",
          "limitations": reports[0]["limitations"]}
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
print(json.dumps({"status": result["status"], "rows": [{key: row[key] for key in ["runner", "max_glibc_version"]} for row in rows]}))
