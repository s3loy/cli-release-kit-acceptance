"""File identities and bounded commands for the isolated R-old experiment."""

import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tarfile


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def inventory(root):
    root = Path(root)
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise RuntimeError("Symlink input is not allowed: " + str(path))
        if path.is_file():
            rows.append({"path": path.relative_to(root).as_posix(),
                         "sha256": digest(path), "bytes": path.stat().st_size,
                         "mode": oct(path.stat().st_mode & 0o777)})
    return rows


def verify(root, rows, exact=True):
    root = Path(root)
    expected = set()
    for row in rows:
        name = Path(row["path"])
        if name.is_absolute() or ".." in name.parts or name.as_posix() in expected:
            raise RuntimeError("Unsafe or duplicate inventory path: " + str(name))
        expected.add(name.as_posix())
        path = root / name
        if path.is_symlink() or digest(path) != row["sha256"]:
            raise RuntimeError("Input digest mismatch: " + str(path))
        if "bytes" in row and path.stat().st_size != row["bytes"]:
            raise RuntimeError("Input size mismatch: " + str(path))
        if "mode" in row and oct(path.stat().st_mode & 0o777) != row["mode"]:
            raise RuntimeError("Input mode mismatch: " + str(path))
    if exact and {row["path"] for row in inventory(root)} != expected:
        raise RuntimeError("Input inventory has missing or additional files: " + str(root))


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def execute(argv, cwd=None, env=None, timeout=120):
    process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
    return {"argv": list(map(str, argv)), "exit_code": process.returncode,
            "timed_out": timed_out, "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace")}


def archive(root, destination):
    root = Path(root)
    rows = inventory(root)
    with Path(destination).open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as output:
                for row in rows:
                    path = root / row["path"]
                    item = output.gettarinfo(str(path), arcname=row["path"])
                    item.uid = item.gid = item.mtime = 0
                    item.uname = item.gname = ""
                    with path.open("rb") as stream:
                        output.addfile(item, stream)
    return rows


def extract(archive_path, destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(archive_path) as source:
        names = set()
        for item in source.getmembers():
            path = Path(item.name)
            if (path.is_absolute() or ".." in path.parts or item.name in names
                    or not (item.isfile() or item.isdir())):
                raise RuntimeError("Unsafe fixture archive member: " + item.name)
            names.add(item.name)
        # Only regular files/directories passed validation; this also works on Python 3.9.
        source.extractall(destination)
