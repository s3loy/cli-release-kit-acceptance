#!/usr/bin/env python3
"""Require one consistent result for every planned native baseline role."""
import argparse
import json
import os
from pathlib import Path
import sys


REQUIRED_ROLES = ("controls", "rust-engine", "rust-default", "rust-pcre2", "go", "c")
EXPECTED_FIELDS = {
    "experiment": "manual native x86_64 feasibility",
    "baseline": "glibc 2.17",
    "automatic_baseline_raise": False,
    "product_integration": False,
    "release_publication": False,
}


def summarize(reports):
    records = []
    input_errors = []
    for path in sorted(reports.rglob("job-result.json")):
        relative = path.relative_to(reports).as_posix()
        try:
            value = json.loads(path.read_text())
            if not isinstance(value, dict):
                raise ValueError("result must be a JSON object")
        except (OSError, UnicodeError, ValueError) as error:
            input_errors.append({"path": relative, "reason": "unreadable result: " + str(error)})
            records.append({"path": relative, "value": None})
            continue
        role = value.get("role")
        if role not in REQUIRED_ROLES:
            input_errors.append({"path": relative, "reason": "unknown or missing role: " + repr(role)})
        records.append({"path": relative, "value": value})

    rows = []
    for role in REQUIRED_ROLES:
        expected = "baseline-" + role + "/job-result.json"
        matching = [record for record in records if record["value"] is not None
                    and record["value"].get("role") == role]
        reasons = []
        if not matching:
            reasons.append("required result missing")
        elif len(matching) != 1:
            reasons.append("duplicate results for this role")
        if not any(record["path"] == expected for record in matching):
            reasons.append("required artifact result missing at " + expected)
        for record in matching:
            prefix = record["path"] + ": "
            value = record["value"]
            if record["path"] != expected:
                reasons.append(prefix + "unexpected artifact location")
            if value.get("passed") is not True:
                reasons.append(prefix + "job did not pass")
            if value.get("error") is not None:
                reasons.append(prefix + "controller reported an error")
            for name, expected_value in EXPECTED_FIELDS.items():
                actual = value.get(name)
                matches = actual is expected_value if isinstance(expected_value, bool) else actual == expected_value
                if not matches:
                    reasons.append(prefix + name + " must be " + json.dumps(expected_value))
        rows.append({"role": role, "passed": not reasons, "result_count": len(matching),
                     "result_files": [record["path"] for record in matching], "reasons": reasons,
                     "error": matching[0]["value"].get("error") if len(matching) == 1 else None})

    return {"passed": not input_errors and all(row["passed"] for row in rows),
            "required_jobs": rows, "required_roles": list(REQUIRED_ROLES),
            "result_file_count": len(records), "input_errors": input_errors,
            "scope": "Native x86_64 manual baseline feasibility, with shared-kernel userspaces",
            "release_publication": False, "c_product_integration": False}


def readable(result):
    def cell(text):
        return str(text).replace("|", "\\|").replace("\n", " ").replace("\r", " ")

    text = "Native x86_64 baseline: " + ("PASS" if result["passed"] else "FAIL") + "\n\n"
    text += "| Required role | Result | Files | Details |\n| --- | --- | --- | --- |\n"
    for row in result["required_jobs"]:
        details = "; ".join(row["reasons"]) if row["reasons"] else "Required result and fields match"
        text += "| {} | {} | {} | {} |\n".format(
            row["role"], "PASS" if row["passed"] else "FAIL", row["result_count"], cell(details))
    if result["input_errors"]:
        text += "\nAdditional input errors:\n\n"
        for error in result["input_errors"]:
            text += "- " + cell(error["path"]) + ": " + cell(error["reason"]) + "\n"
    text += ("\nThese results cover the recorded userspaces and checks. Product C integration "
             "and minimum CPU/kernel qualification remain separate.\n")
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", type=Path)
    args = parser.parse_args()
    result = summarize(args.reports)
    args.reports.mkdir(parents=True, exist_ok=True)
    (args.reports / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    text = readable(result)
    print(text, file=sys.stderr, end="")
    print(json.dumps(result, indent=2))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
            stream.write(text)
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
