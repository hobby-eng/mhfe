"""AUD-024, role guide-tooling-other: checks of the tooling findings at commit b6fca69.

Each check prints PASS when the repository behaves as the cited rule wants, and DEFECT with what it
saw otherwise. The script exits 1 when any check finds the defect, 0 when none does. Run it through
run.sh next to it, from the repository root. It reads the repository and writes only to temporary
folders; nothing runs Argon2 at full cost.
"""

import ast
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path.cwd()
PROGRAM = sys.argv[1] if len(sys.argv) > 1 else None
FOUND = []


def report(name, defect, detail):
    print(f"{'DEFECT' if defect else 'PASS'}  {name}: {detail}")
    if defect:
        FOUND.append(name)


def run(command, **options):
    return subprocess.run(command, capture_output=True, text=True, cwd=ROOT, **options)


def blame_revs_gate():
    """scripts/check.sh's check of .git-blame-ignore-revs must refuse what git blame refuses."""
    text = (ROOT / "scripts/check.sh").read_text(encoding="utf-8")
    block = re.search(r"\nwhile read -r hash; do\n.*?\ndone < <\(grep [^\n]*\.git-blame-ignore-revs\)\n",
                      text, re.S)
    if block is None:
        report("blame-revs gate", True, "the loop of check.sh was not found; review it by hand")
        return
    full = run(["git", "rev-parse", "f6067310e5acae95b02b5bc96d78007426c8d15a"]).stdout.strip()
    with tempfile.TemporaryDirectory() as scratch:
        revs = pathlib.Path(scratch, "revs")
        gate = block.group(0).replace(".git-blame-ignore-revs", str(revs))
        accepted = []
        for line in (full[:12], "HEAD~3"):
            revs.write_text(line + "\n")
            blame = run(["git", "blame", "--ignore-revs-file", str(revs), "--", "README.md"])
            passed = run(["bash", "-c", "set -euo pipefail\n" + gate]).returncode == 0
            if passed and blame.returncode != 0:
                accepted.append(line)
    report("blame-revs gate", bool(accepted),
           f"lines the gate accepts and git blame refuses: {accepted}" if accepted
           else "the gate refuses an abbreviated hash and a ref name")


def empty_command_lines():
    """A check script refuses a command line that names nothing to check or a mistyped option."""
    lapses = []
    with tempfile.TemporaryDirectory() as scratch:
        copy = pathlib.Path(scratch)
        (copy / "scripts").mkdir()
        (copy / "src/bin/mhfe").mkdir(parents=True)
        script = copy / "scripts/generate-cell-widths.py"
        script.write_bytes((ROOT / "scripts/generate-cell-widths.py").read_bytes())
        table = copy / "src/bin/mhfe/cell_widths.rs"
        table.write_bytes((ROOT / "src/bin/mhfe/cell_widths.rs").read_bytes())
        os.utime(table, (0, 0))
        result = run([sys.executable, str(script), "--chek"])
        if result.returncode == 0 or table.stat().st_mtime != 0:
            lapses.append("generate-cell-widths.py --chek rewrote its table and exited "
                          f"{result.returncode}")
    for command in (["scripts/independent-suite3.py", "vector"],
                    ["scripts/independent-suite3.py", "passwords"],
                    ["scripts/independent-suite4.py", "validation"],
                    ["scripts/independent-suite4.py", "vector"]):
        result = run([sys.executable, *command])
        if result.returncode == 0:
            lapses.append(" ".join(command[0:2]).split("/")[-1] + " with no file exited 0")
    report("empty or mistyped command lines", bool(lapses), "; ".join(lapses) or "all refused")


def asserts_under_optimization():
    """The independent checker still refuses a changed vector when Python optimizes."""
    vector = json.loads((ROOT / "tests/fixtures/suite3-vectors/zero-12.json").read_text())
    vector["encryption"]["rounds"][0]["mask_hex"] = "00" * 16
    with tempfile.TemporaryDirectory() as scratch:
        path = pathlib.Path(scratch, "zero-12.json")
        path.write_text(json.dumps(vector))
        environment = dict(os.environ, PYTHONOPTIMIZE="1", PYTHONDONTWRITEBYTECODE="1")
        result = run([sys.executable, "scripts/independent-suite3.py", "vector",
                      "--trust-argon2-keys", str(path)], env=environment)
    report("checks under PYTHONOPTIMIZE", result.returncode == 0,
           "a vector with a changed mask was reported reproduced" if result.returncode == 0
           else "the changed vector is refused")


def checksum_lone_cr():
    """The Python launcher refuses a checksum file that mhfe serve refuses: a lone CR first."""
    spec = importlib.util.spec_from_file_location("fast_mode", ROOT / "packaging/mhfe-fast-mode.py")
    fast_mode = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode = True
    spec.loader.exec_module(fast_mode)
    page = b"<!doctype html><title>public test page</title>"
    with tempfile.TemporaryDirectory() as scratch:
        folder = pathlib.Path(scratch)
        (folder / "tool.html").write_bytes(page)
        digest = fast_mode.sha256_of(page)
        (folder / "mhfe-fast-mode.sha256").write_bytes(f"\r{digest}  tool.html\n".encode())
        try:
            fast_mode.load_checked_page(str(folder / "tool.html"))
            python_serves = True
        except fast_mode.Refused:
            python_serves = False
        rust = "not run (no program given)"
        if PROGRAM:
            try:
                result = subprocess.run([PROGRAM, "serve", "--no-browser", str(folder / "tool.html")],
                                        capture_output=True, text=True, timeout=3,
                                        env=dict(os.environ, NO_COLOR="1"))
                rust = f"refuses with exit {result.returncode}"
            except subprocess.TimeoutExpired:
                rust = "serves"
    report("checksum file with a lone CR", python_serves,
           f"Python launcher {'serves' if python_serves else 'refuses'}; mhfe serve {rust}")


def unreadable_builder_paths():
    """check-release-artifacts.sh --builder-paths fails on a file it cannot read."""
    if os.geteuid() == 0:
        report("unreadable file in --builder-paths", False, "not checked as root")
        return
    with tempfile.TemporaryDirectory() as scratch:
        program = pathlib.Path(scratch, "program")
        program.write_text(f"panic at {ROOT}/src/lib.rs:1\n")
        program.chmod(0)
        try:
            result = run(["scripts/check-release-artifacts.sh", "--builder-paths", str(program)])
        finally:
            program.chmod(0o600)
    report("unreadable file in --builder-paths", result.returncode == 0,
           f"exit {result.returncode}: {result.stdout.strip()[:80]}")


def archive_reader_copy():
    """No unmarked copy of the archive reader in the release scripts."""
    shell = (ROOT / "scripts/check-release-artifacts.sh").read_text(encoding="utf-8")
    embedded = re.search(r"<<'PY'\n(.*?)\nPY\n", shell, re.S)
    licences = ast.parse((ROOT / "scripts/third-party-licenses.py").read_text(encoding="utf-8"))

    def bodies(tree):
        found = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                body = node.body[1:] if isinstance(node.body[0], ast.Expr) else node.body
                parameter = node.args.args[0].arg if node.args.args else ""
                text = ast.dump(ast.Module(body=body, type_ignores=[]))
                found[node.name] = text.replace(f"id='{parameter}'", "id='_'")
        return found

    copies = []
    if embedded is not None:
        theirs = bodies(licences)
        for name, body in bodies(ast.parse(embedded.group(1))).items():
            copies += [f"check-release-artifacts.sh {name}() = third-party-licenses.py {other}()"
                       for other, same in theirs.items() if same == body]
    marked = "deliberate copy" in shell.lower()
    report("archive reader copy", bool(copies) and not marked, "; ".join(copies) or "no copy")


for check in (blame_revs_gate, empty_command_lines, asserts_under_optimization, checksum_lone_cr,
              unreadable_builder_paths, archive_reader_copy):
    check()
print(f"{len(FOUND)} of 6 checks found their defect" if FOUND else "No check found its defect.")
sys.exit(1 if FOUND else 0)
