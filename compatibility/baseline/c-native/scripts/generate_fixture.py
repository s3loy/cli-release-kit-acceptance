#!/usr/bin/env python3
"""Generate a local, test-only TLS certificate without changing system trust."""

from pathlib import Path
import argparse
import hashlib
import json
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("directory", type=Path)
parser.add_argument("--openssl", default="openssl")
args = parser.parse_args()
root = args.directory.resolve()
root.mkdir(parents=True, exist_ok=True)
assert not (root / "key.pem").exists(), "preserve previous fixture; use a fresh directory"
config = root / "openssl.cnf"
config.write_text("[req]\ndistinguished_name=dn\nx509_extensions=extensions\nprompt=no\n"
                  "[dn]\nCN=localhost\n[extensions]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
                  "basicConstraints=critical,CA:TRUE\n")
argv = [args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-days", "7", "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem"),
        "-config", str(config)]
process = subprocess.run(argv, capture_output=True, timeout=30)
(root / "generation.stdout").write_bytes(process.stdout)
(root / "generation.stderr").write_bytes(process.stderr)
assert process.returncode == 0, process.stderr.decode(errors="replace")
metadata = {"role": "test-only local TLS server fixture; not the curl OpenSSL dependency",
            "argv": argv, "generator_version": subprocess.check_output([args.openssl, "version"], timeout=10).decode().strip(),
            "certificate_sha256": hashlib.sha256((root / "cert.pem").read_bytes()).hexdigest(),
            "ca_installed_in_system": False}
(root / "fixture.json").write_text(json.dumps(metadata, indent=2) + "\n")
print(json.dumps(metadata, indent=2))
