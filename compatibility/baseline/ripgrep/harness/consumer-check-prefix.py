import json
import os
from pathlib import Path
import tempfile
import runpy

execute = runpy.run_path(str(Path(__file__).with_name("execute-check.py")))["execute"]

binary = os.environ["KIT_BINARY"]
results = []
with tempfile.TemporaryDirectory(prefix="ripgrep-behavior-", dir=os.environ["KIT_ATTEMPT_DIR"]) as directory:
    root = Path(directory)
    (root / ".git").mkdir()
    (root / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
    (root / "visible.txt").write_text("alpha.literal\norder=42\n你好 世界\nneedle visible\n", encoding="utf-8")
    (root / ".hidden.txt").write_text("needle hidden\n", encoding="utf-8")
    (root / "ignored.txt").write_text("needle ignored\n", encoding="utf-8")

    def check(name, args, code=0, contains=(), absent=()):
        prefix = [part.replace("{fixture}", str(root)).replace("{fixture_runtime}", "/fixtures")
                  for part in json.loads(os.environ.get("KIT_EXEC_PREFIX_JSON", "[]"))]
        completed = execute(prefix, binary, args, root)
        result = {"name": name, "args": args, "command": completed.args, "exit_code": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}
        results.append(result)
        assert completed.returncode == code, result
        for value in contains:
            assert value in completed.stdout, result
        for value in absent:
            assert value not in completed.stdout, result

    check("version", ["--version"], contains=("15.2.0",))
    check("help", ["--help"], contains=("ripgrep", "USAGE:"))
    check("literal", ["-F", "alpha.literal", "visible.txt"], contains=("alpha.literal",))
    check("regex", [r"order=\d+", "visible.txt"], contains=("order=42",))
    check("unicode", ["世界", "visible.txt"], contains=("你好 世界",))
    check("default-hidden-ignore", ["needle", "."], contains=("needle visible",), absent=("needle hidden", "needle ignored"))
    check("include-hidden", ["--hidden", "needle", "."], contains=("needle visible", "needle hidden"), absent=("needle ignored",))
    check("include-ignored", ["--hidden", "--no-ignore", "needle", "."], contains=("needle visible", "needle hidden", "needle ignored"))
    check("zero-match", ["absent-pattern-20261117", "visible.txt"], code=1)
    check("invalid-regex", ["[", "visible.txt"], code=2)
print(json.dumps({"schema": 1, "binary": binary, "passed": len(results), "results": results}, ensure_ascii=False, indent=2))
