"""Bound one check process and remove its owned Docker container on exit."""

import os
import json
from pathlib import Path
import signal
import subprocess
import uuid


def execute(prefix, binary, args, cwd):
    prefix = list(prefix)
    cleanup = None
    if prefix and Path(prefix[0]).name == "docker" and "run" in prefix:
        index = prefix.index("run")
        if any(part == "--name" or part.startswith("--name=") for part in prefix):
            raise ValueError("The check driver assigns its own Docker container name")
        name = "baseline-rg-check-" + uuid.uuid4().hex
        cleanup = prefix[:index] + ["rm", "--force", name]
        prefix[index + 1:index + 1] = ["--name", name]
    argv = [*prefix, binary, "--no-config", *args]
    try:
        proc = subprocess.Popen(argv, cwd=cwd, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
        try:
            stdout, stderr = proc.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            stdout, stderr = proc.communicate()
            diagnostic = {"argv": argv, "cwd": str(cwd), "timeout_seconds": 15,
                          "stdout": stdout, "stderr": stderr}
            (Path(cwd).parent / ("timeout-" + uuid.uuid4().hex + ".json")).write_text(
                json.dumps(diagnostic, ensure_ascii=False, indent=2) + "\n")
            raise subprocess.TimeoutExpired(argv, 15, output=stdout, stderr=stderr)
        return subprocess.CompletedProcess(argv, proc.returncode, stdout, stderr)
    finally:
        if cleanup:
            subprocess.run(cleanup, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=5, check=False)
