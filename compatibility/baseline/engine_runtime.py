#!/usr/bin/env python3
"""Drive R-old launch and retained collection checks on the native CI host."""
import argparse
import json
import os
from pathlib import Path
import runpy
import sys
import traceback

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    os.environ["BASELINE_OUT"] = str(out / "runtime-controller")
    harness = HERE / "r-old/harness"
    binary = out / "extracted/bin/relship"
    stages = {name: "pending" for name in (
        "native-host", "runtime217", "runtime231", "runtime239",
        "reader-fixture", "collection-reader")}
    errors = []
    cleanup_errors = []
    first_error = None
    original_exception = None
    core = None
    stage = "native-host"

    def record_failure(name, error, cleanup=False, details=None):
        nonlocal first_error
        detail = {"stage": name, "type": type(error).__name__, "message": str(error)}
        if error.__traceback__ is not None:
            detail["traceback"] = "".join(traceback.format_exception(error))
        if details is not None:
            detail["details"] = details
        (cleanup_errors if cleanup else errors).append(detail)
        if first_error is None:
            first_error = detail
        if not cleanup:
            stages[name] = "failed"

    try:
        stages[stage] = "running"
        core = runpy.run_path(str(HERE / "run.py"))
        core["native"]()
        command, docker, image = core["command"], core["docker"], core["image"]
        stages[stage] = "passed"
        for key, libc in (("runtime217", "2.17"), ("runtime231", "2.31"),
                          ("runtime239", "2.39")):
            stage = key
            stages[stage] = "running"
            name, cmd = docker("engine-" + key, image(key),
                ["/bin/sh", "-c", "while :; do sleep 3600; done"],
                [(binary.parent, "/payload", True)], detach=True)
            try:
                command("start-" + key, cmd)
                code, _ = command("check-" + key,
                    [sys.executable, harness / "check-runtime.py",
                     "--binary", "/payload/relship", "--host-binary", binary,
                     "--out-dir", out / "runtime" / key,
                     "--exec-prefix-json", json.dumps(["docker", "exec", name]),
                     "--environment-id", image(key), "--expected-glibc", libc],
                    timeout=300, required=False)
                if code:
                    record_failure(stage, RuntimeError("check-" + key + " exited " + str(code)))
                else:
                    stages[stage] = "passed"
            except Exception as error:
                # Record the command failure before cleanup can raise another exception.
                record_failure(stage, error)
                raise
            finally:
                try:
                    code, _ = command("stop-" + key, ["docker", "rm", "-f", name], required=False)
                    if code:
                        record_failure("stop-" + key,
                                       RuntimeError("Container cleanup exited " + str(code)), cleanup=True)
                    else:
                        core["OWNED"].discard(name)
                except Exception as error:
                    record_failure("stop-" + key, error, cleanup=True)
        stage = "reader-fixture"
        stages[stage] = "running"
        fixture = args.inputs.resolve() / "reader-fixture"
        command("prepare-reader-fixture",
            [sys.executable, harness / "prepare-fixture.py",
             "--archive", HERE / "r-old/fixtures/reader-fixture.tar.gz",
             "--out-dir", fixture], timeout=600)
        stages[stage] = "passed"
        stage = "collection-reader"
        stages[stage] = "running"
        verify_out = out / "collection"
        verify_out.mkdir()
        _, cmd = docker("engine-collection", image("build217"),
            [core["PYTHON"], "/case/check-collection.py",
             "--binary", "/payload/relship", "--fixture-root", "/fixture",
             "--out-dir", "/out/check"],
            [(harness, "/case", True), (binary.parent, "/payload", True),
             (fixture, "/fixture", True), (verify_out, "/out", False)],
            {"BASELINE_IMAGE": image("build217"), "PYTHONDONTWRITEBYTECODE": "1"})
        code, _ = command("collection-reader", cmd, timeout=300, required=False)
        if code:
            record_failure(stage, RuntimeError("collection-reader exited " + str(code)))
        else:
            stages[stage] = "passed"
    except Exception as error:
        if stages[stage] != "failed":
            record_failure(stage, error)
        original_exception = error
    finally:
        if core is not None:
            try:
                for failure in core["cleanup"]():
                    record_failure("cleanup", RuntimeError("Controller cleanup failed: "
                                   + failure.get("operation", "unknown operation")),
                                   cleanup=True, details=failure)
            except Exception as error:
                record_failure("cleanup", error, cleanup=True)
        passed = all(state == "passed" for state in stages.values()) and first_error is None
        summary = {"passed": passed, "status": "passed" if passed else "failed",
                   "stages": stages, "error": first_error, "errors": errors,
                   "cleanup_errors": cleanup_errors,
                   "unfinished_stages": [name for name, state in stages.items()
                                         if state in ("pending", "running")],
                   "payload_executed_in_reader_fixture": False,
                   "clean_runtime_scope": "three bare CLI launch checks",
                   "reader_scope": "glibc 2.17 build image with declared Git"}
        try:
            out.mkdir(parents=True, exist_ok=True)
            (out / "runtime-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        except Exception as error:
            if original_exception is None:
                raise
            print("Could not save runtime summary: " + str(error), file=sys.stderr)
    if original_exception is not None:
        raise original_exception
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
