"""Stage signed CentOS Perl build dependencies without installing packages."""

from pathlib import Path
import re
import shutil


def prepare(pins, inputs, out, env, run, dump, inventory, sha):
    pin = pins["rpm_build_dependencies"]
    packages = pin["packages"]
    forbidden = {"perl", "perl-libs", "glibc", "glibc-common", "glibc-devel", "gcc", "gcc-c++", "binutils", "rpm", "cpio"}
    assert not any(item["name"] in forbidden for item in packages), "do not replace the image interpreter, compiler or base libraries"
    assert len({item["filename"] for item in packages}) == len(packages)
    files = []
    for item in packages:
        path = inputs / item["filename"]
        assert sha(path) == item["sha256"], item["filename"]
        files.append(path)
    key = inputs / pin["key"]["filename"]
    assert sha(key) == pin["key"]["sha256"]
    tool_paths = {name: Path(shutil.which(name) or "") for name in ("rpm", "rpm2cpio", "cpio", "perl")}
    assert all(path.is_file() for path in tool_paths.values()), tool_paths
    tool_hashes = {name: {"resolved_path": str(path.resolve()), "sha256": sha(path.resolve())}
                   for name, path in tool_paths.items()}
    run("rpm-version", [tool_paths["rpm"], "--version"])
    run("cpio-version", [tool_paths["cpio"], "--version"])
    provider = run("rpm2cpio-provider", [tool_paths["rpm"], "--query", "--file", tool_paths["rpm2cpio"]])
    assert provider.strip() == pin["image_tools"]["rpm2cpio_provider"], provider
    provider = run("cpio-provider", [tool_paths["rpm"], "--query", "--file", tool_paths["cpio"]])
    assert provider.strip() == pin["image_tools"]["cpio_provider"], provider

    work = out / "work"
    key_db = work / "rpm-signature-db"
    key_db.mkdir()
    run("rpm-key-db-init", [tool_paths["rpm"], "--dbpath", key_db, "--initdb"])
    run("rpm-key-import", [tool_paths["rpm"], "--dbpath", key_db, "--import", key])
    for index, path in enumerate(files):
        signature_output = run("rpm-package-signature-" + str(index),
                               [tool_paths["rpm"], "--dbpath", key_db, "--checksig", "--verbose", path])
        signature_lines = [line for line in signature_output.splitlines() if "Signature" in line]
        assert signature_lines, "RPM has no checked signature: " + path.name
        assert all(re.search(r"Signature.*key ID " + pin["key"]["key_id"] + r":\s+OK\s*$", line, re.IGNORECASE)
                   for line in signature_lines), signature_lines
    actual_nevra = run("rpm-package-identities", [tool_paths["rpm"], "--dbpath", key_db, "--query", "--package",
                                                  "--qf", "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n"] + files)
    assert sorted(actual_nevra.splitlines()) == sorted(item["nvra"] for item in packages), actual_nevra
    run("rpm-package-requires", [tool_paths["rpm"], "--dbpath", key_db, "--query", "--package", "--requires"] + files)
    run("rpm-package-provides", [tool_paths["rpm"], "--dbpath", key_db, "--query", "--package", "--provides"] + files)

    real_db = Path("/var/lib/rpm")
    def database_inventory():
        return [{"path": path.name, "sha256": sha(path), "size": path.stat().st_size}
                for path in sorted(real_db.iterdir()) if path.is_file()
                and not path.name.startswith(("__db.", "log.")) and path.name != ".rpm.lock"]
    before = database_inventory()
    dependency_db = work / "rpm-dependency-db"
    shutil.copytree(real_db, dependency_db,
                    ignore=shutil.ignore_patterns("__db.*", ".rpm.lock", "log.*"))
    run("rpm-dependency-key-import", [tool_paths["rpm"], "--dbpath", dependency_db, "--import", key])
    run("rpm-image-provides", [tool_paths["rpm"], "--dbpath", dependency_db, "--query", "--all", "--provides"])
    run("rpm-requires-test", [tool_paths["rpm"], "--noplugins", "--dbpath", dependency_db,
                               "--install", "--test", "--noscripts", "--notriggers"] + files)
    assert database_inventory() == before, "the real image RPM database changed"

    prefix = work / "perl-dependencies"
    prefix.mkdir()
    payloads = []
    for index, path in enumerate(files):
        payload = work / ("perl-rpm-" + str(index) + ".cpio")
        run("rpm-to-cpio-" + str(index), [tool_paths["rpm2cpio"], path], stdout_path=payload)
        listing = run("cpio-list-" + str(index), [tool_paths["cpio"], "--list", "--quiet"], stdin_path=payload)
        for name in listing.splitlines():
            member = Path(name)
            assert not member.is_absolute() and ".." not in member.parts, name
            assert member.parts and member.parts[0] in ("usr", "."), name
        run("cpio-extract-" + str(index), [tool_paths["cpio"], "--extract", "--make-directories",
                                            "--no-absolute-filenames", "--no-preserve-owner", "--preserve-modification-time", "--quiet"],
            cwd=prefix, stdin_path=payload)
        payloads.append({"package": path.name, "cpio_sha256": sha(payload)})
    for path in prefix.rglob("*"):
        if path.is_symlink():
            assert path.resolve().is_relative_to(prefix.resolve()), "dependency symlink escapes its owned prefix: " + str(path)
    env["PERL5LIB"] = ":".join(str(prefix / relative) for relative in pin["perl5lib"])
    modules = pin["probe_modules"]
    perl_code = """use strict; use warnings;
die "unexpected Perl interpreter" unless $^V eq v5.16.3;
for my $module (@ARGV) {
    eval "require $module; 1" or die $@;
    (my $file = $module) =~ s{::}{/}g;
    $file .= '.pm';
    my $version = eval { $module->VERSION } // '';
    print join("\\t", 'MODULE', $module, $version, $INC{$file}), "\\n";
}
my $gcc = IPC::Cmd::can_run('gcc') or die "IPC::Cmd cannot locate gcc";
print "COMPILER\\t$gcc\\n";
"""
    probe = run("perl-dependency-probe", [tool_paths["perl"], "-e", perl_code] + modules)
    loaded = []
    for line in probe.splitlines():
        values = line.split("\t")
        if values[0] == "MODULE":
            assert len(values) == 4 and Path(values[3]).resolve().is_relative_to(prefix.resolve()), line
            loaded.append({"module": values[1], "version": values[2], "path": values[3], "sha256": sha(Path(values[3]))})
    assert sorted(item["module"] for item in loaded) == sorted(modules), probe
    assert all(sha(path.resolve()) == tool_hashes[name]["sha256"] for name, path in tool_paths.items())
    assert database_inventory() == before, "the real image RPM database changed"
    dump(out / "evidence/perl-dependencies.json", {
        "scope": "signed build-tool RPM payloads staged in an owned prefix; no package installation",
        "packages": packages, "key": pin["key"], "signature_check_passed": True,
        "copied_database_requires_test_passed": True, "image_database_unchanged": True,
        "image_database_snapshot": before,
        "image_tools_unchanged": tool_hashes, "perl_version": "5.16.3", "perl5lib": env["PERL5LIB"],
        "loaded_modules": loaded, "payloads": payloads, "prefix_inventory": inventory(prefix),
    })
