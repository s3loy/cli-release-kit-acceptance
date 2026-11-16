#!/usr/bin/env python3
"""Acquire hash-pinned official inputs and verify detached signatures on the host."""

from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument("destination", type=Path)
args = parser.parse_args()
destination = args.destination.resolve()
destination.mkdir(parents=True, exist_ok=True)
manifest = json.loads((Path(__file__).resolve().parent.parent / "inputs.json").read_text())
logs = destination / "acquisition-logs"
logs.mkdir(exist_ok=True)
commands = []


def run(name, argv, limit):
    start = time.monotonic()
    timed_out = False
    try:
        process = subprocess.run(argv, capture_output=True, timeout=limit)
    except subprocess.TimeoutExpired as error:
        timed_out = True
        process = subprocess.CompletedProcess(argv, 124, error.stdout or b"", error.stderr or b"")
    (logs / (name + ".stdout")).write_bytes(process.stdout)
    (logs / (name + ".stderr")).write_bytes(process.stderr)
    commands.append({"name": name, "argv": argv, "exit_code": process.returncode,
                     "timed_out": timed_out,
                     "seconds": round(time.monotonic() - start, 3)})
    (destination / "acquisition.json").write_text(json.dumps(commands, indent=2) + "\n")
    assert process.returncode == 0, (name, process.stderr.decode(errors="replace")[-4000:])
    return process.stdout.decode(errors="replace")


for item in manifest["downloads"]:
    target = destination / item["filename"]
    if not target.exists():
        run("download-" + item["filename"], ["curl", "--fail", "--location", "--connect-timeout", "20", "--max-time", "600",
                                              "--dump-header", str(target) + ".headers", "--output", str(target), item["url"]], 610)
    actual = hashlib.sha256(target.read_bytes()).hexdigest()
    assert actual == item["sha256"], (item["filename"], actual, item["sha256"])

home = destination / "gnupg"
home.mkdir(mode=0o700, exist_ok=True)
os.chmod(home, 0o700)
verification = []
rpm_key = manifest.get("rpm_build_dependencies", {}).get("key")
if rpm_key:
    observed = run("centos7-key-fingerprint", ["gpg", "--homedir", str(home), "--no-autostart", "--batch",
                                               "--with-colons", "--show-keys", str(destination / rpm_key["filename"])], 30)
    fingerprints = [line.split(":")[9] for line in observed.splitlines() if line.startswith("fpr:")]
    assert fingerprints == [rpm_key["primary_fingerprint"]], fingerprints
for item in manifest["signatures"]:
    keyring = destination / (item["name"] + "-signing.gpg")
    run(item["name"] + "-dearmor", ["gpg", "--homedir", str(home), "--no-autostart", "--batch", "--yes", "--dearmor",
                                    "--output", str(keyring), str(destination / item["key_file"])], 30)
    status = run(item["name"] + "-signature", ["gpgv", "--homedir", str(home), "--keyring", str(keyring), "--status-fd", "1",
                                              str(destination / item["signature_file"]), str(destination / item["signed_file"])], 30)
    valid = [line.split() for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    assert len(valid) == 1, item["name"]
    assert valid[0][2] == item["signing_fingerprint"], (item["name"], valid)
    assert valid[0][-1] == item["primary_fingerprint"], (item["name"], valid)
    verification.append({"name": item["name"], "valid_signature": True,
                         "signing_fingerprint": valid[0][2], "primary_fingerprint": valid[0][-1]})
(destination / "signature-results.json").write_text(json.dumps(verification, indent=2) + "\n")
print(json.dumps(verification, indent=2))
