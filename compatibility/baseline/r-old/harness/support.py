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


def _source_link_bytes(root, source_symlinks):
    links = {}
    root = Path(root).resolve()
    for name, expected in (source_symlinks or {}).items():
        relative = Path(name)
        if (relative.is_absolute() or ".." in relative.parts or not relative.parts
                or relative.as_posix() != name or Path(expected).is_absolute()):
            raise RuntimeError("Unsafe source symlink pin: " + name)
        path = root / relative
        if not path.is_symlink():
            raise RuntimeError("Pinned source symlink is missing or replaced: " + str(path))
        for parent in path.parents:
            if parent == root:
                break
            if parent.is_symlink():
                raise RuntimeError("Source symlink traverses another link: " + str(path))
        value = os.readlink(os.fsencode(path))
        if value != expected.encode("utf-8"):
            raise RuntimeError("Source symlink target mismatch: " + str(path))
        try:
            (path.parent / expected).resolve(strict=True).relative_to(root)
        except (OSError, RuntimeError, ValueError) as error:
            raise RuntimeError("Source symlink target is missing or outside the source tree: "
                               + str(path)) from error
        links[name] = value
    return links


def inventory(root, *, source_symlinks=None):
    root = Path(root)
    links = _source_link_bytes(root, source_symlinks)
    rows = []
    for path in sorted(root.rglob("*")):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            if name not in links:
                raise RuntimeError("Symlink input is not allowed: " + str(path))
            value = links[name]
            rows.append({"path": name, "type": "symlink", "link_target": value.decode("utf-8"),
                         "sha256": hashlib.sha256(value).hexdigest(), "bytes": len(value),
                         "mode": oct(path.lstat().st_mode & 0o777)})
        elif path.is_file():
            rows.append({"path": name,
                         "sha256": digest(path), "bytes": path.stat().st_size,
                         "mode": oct(path.stat().st_mode & 0o777)})
    return rows


def verify(root, rows, exact=True, *, source_symlinks=None):
    root = Path(root)
    links = _source_link_bytes(root, source_symlinks)
    expected = set()
    for row in rows:
        name = Path(row["path"])
        if name.is_absolute() or ".." in name.parts or name.as_posix() in expected:
            raise RuntimeError("Unsafe or duplicate inventory path: " + str(name))
        expected.add(name.as_posix())
        path = root / name
        if source_symlinks is not None:
            for parent in path.parents:
                if parent == root:
                    break
                if parent.is_symlink():
                    raise RuntimeError("Source input traverses a symlink: " + str(path))
        if name.as_posix() in links:
            actual = hashlib.sha256(links[name.as_posix()]).hexdigest()
            metadata = path.lstat()
        else:
            if path.is_symlink() or not path.is_file():
                raise RuntimeError("Input must be a regular file: " + str(path))
            actual = digest(path)
            metadata = path.stat()
        if actual != row["sha256"]:
            raise RuntimeError("Input digest mismatch: " + str(path))
        if "bytes" in row and metadata.st_size != row["bytes"]:
            raise RuntimeError("Input size mismatch: " + str(path))
        if "mode" in row and oct(metadata.st_mode & 0o777) != row["mode"]:
            raise RuntimeError("Input mode mismatch: " + str(path))
    if not links.keys() <= expected:
        raise RuntimeError("Source symlink pin is absent from the file manifest")
    if exact and {row["path"] for row in inventory(root, source_symlinks=source_symlinks)} != expected:
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
