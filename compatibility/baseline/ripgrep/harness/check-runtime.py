#!/usr/bin/env python3
"""Run the preserved ten assertions, plus two checks for the PCRE2 case."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import runpy

execute = runpy.run_path(str(Path(__file__).with_name("execute-check.py")))["execute"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--pcre2", action="store_true")
    parser.add_argument("--exec-prefix-json", default="[]",
                        help="JSON argv prefix; {fixture} and {fixture_runtime} are replaced")
    parser.add_argument("--host-binary", type=Path,
                        help="Host artifact bytes corresponding to --binary in prefix mode")
    args = parser.parse_args()
    prefix = json.loads(args.exec_prefix_json)
    if not isinstance(prefix, list) or not all(isinstance(part, str) for part in prefix):
        parser.error("--exec-prefix-json must contain a JSON array of strings")
    if prefix and args.host_binary is None:
        parser.error("--host-binary is required with an execution prefix")
    binary = args.binary if prefix else args.binary.resolve()
    host_binary = args.host_binary or binary
    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    original = Path(__file__).with_name("consumer-check.py")
    expected = "be777079d746ae70f9ea6b3c5a64331ce77554fdd271ad1c14e46b406cad5fd1"
    assert hashlib.sha256(original.read_bytes()).hexdigest() == expected
    env = os.environ.copy()
    env.update(KIT_BINARY=str(binary), KIT_ATTEMPT_DIR=str(out),
               KIT_EXEC_PREFIX_JSON=args.exec_prefix_json, PYTHONDONTWRITEBYTECODE="1")
    adapted = original.with_name("consumer-check-prefix.py")
    completed = subprocess.run([os.sys.executable, str(adapted)], env=env,
                               text=True, capture_output=True, timeout=240)
    (out / "original.stdout.log").write_text(completed.stdout)
    (out / "original.stderr.log").write_text(completed.stderr)
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["passed"] == 10
    extra = []
    if args.pcre2:
        with tempfile.TemporaryDirectory(prefix="pcre2-check-", dir=out) as directory:
            sample = Path(directory) / "sample.txt"
            sample.write_text("order=42\norder=7\n", encoding="utf-8")
            cases = [
                ("pcre2-version", ["--pcre2-version"], "PCRE2", None),
                ("pcre2-lookbehind", ["--pcre2", "-o", r"(?<=order=)42", "sample.txt"],
                 None, "42\n"),
            ]
            for name, argv, contains, exact in cases:
                execution_prefix = [part.replace("{fixture}", directory).replace(
                    "{fixture_runtime}", "/fixtures") for part in prefix]
                result = execute(execution_prefix, str(binary), argv, directory)
                item = {"name": name, "args": argv, "command": result.args, "exit_code": result.returncode,
                        "stdout": result.stdout, "stderr": result.stderr}
                extra.append(item)
                (out / "pcre2-assertions.json").write_text(json.dumps(extra, indent=2) + "\n")
                assert result.returncode == 0, item
                if contains:
                    assert contains in result.stdout, item
                if exact is not None:
                    assert result.stdout == exact, item
    report.update(binary_sha256=hashlib.sha256(host_binary.read_bytes()).hexdigest(),
                  original_check_sha256=expected, pcre2=args.pcre2,
                  adapted_check_sha256=hashlib.sha256(adapted.read_bytes()).hexdigest(),
                  exec_prefix=prefix,
                  passed=report["passed"] + len(extra),
                  results=report["results"] + extra)
    (out / "assertions.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"passed": report["passed"], "pcre2": args.pcre2}))


if __name__ == "__main__":
    main()
