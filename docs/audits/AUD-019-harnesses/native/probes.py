#!/usr/bin/env python3
"""Bounded native audit probes; public fixtures only, no completed KDF."""

import argparse
import hashlib
import importlib.util
import json
import re
import resource
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = ROOT / "docs/audits/AUD-019-evidence"
MEMORY_LIMIT = 512 * 1024 * 1024
CONTROL = "\x1b]52;c;UFVCTElDLVNZTlRIRVRJQw==\x07"
sys.dont_write_bytecode = True


def digest(data):
    return hashlib.sha256(data).hexdigest()


def limits():
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT, MEMORY_LIMIT))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (5, 5))


def load(relative, name):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def python_controls(script, raw_label):
    results = []
    for scenario in ("parent-path", "checksum-name", "bad-option", "invalid-utf8", "c1-name"):
        with tempfile.TemporaryDirectory(prefix="aud019-public-") as temporary:
            folder = Path(temporary)
            if scenario == "parent-path":
                folder = folder / ("public-" + CONTROL)
                folder.mkdir()
            elif scenario in ("checksum-name", "c1-name"):
                control = CONTROL if scenario == "checksum-name" else "\x9b2J"
                (folder / "mhfe-fast-mode.sha256").write_text(
                    "0" * 64 + "  listed-" + control + ".html\n", encoding="utf-8"
                )
            elif scenario == "invalid-utf8":
                (folder / "mhfe-fast-mode.sha256").write_bytes(b"\xff\n")
            arguments = [sys.executable, str(script), "--no-browser", str(folder / "page.html")]
            if scenario == "bad-option":
                arguments.append("--unknown-" + CONTROL)
            result = subprocess.run(
                arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, cwd=ROOT, timeout=6, preexec_fn=limits, check=False,
            )
            streams = {}
            for name, data in (("stdout", result.stdout), ("stderr", result.stderr)):
                relative = "docs/audits/AUD-019-evidence/{}-{}-{}.bin".format(
                    raw_label, scenario, name
                )
                with (ROOT / relative).open("xb") as output:
                    output.write(data)
                streams[name] = {
                    "path": relative, "sha256": digest(data), "bytes": len(data),
                    "rawOsc52Count": data.count(b"\x1b]52;"),
                    "rawCsiCount": data.count(b"\x1b["),
                    "rawC1CsiCount": data.count("\x9b".encode()),
                }
            safe = (
                result.returncode == 2 and not result.stdout
                and b"\x1b" not in result.stderr and "\x9b".encode() not in result.stderr
                and b"Traceback" not in result.stderr
                and b"Fast mode is running" not in result.stderr
            )
            if scenario in ("parent-path", "bad-option"):
                safe = safe and b"\\u{1b}" in result.stderr and b"\\u{7}" in result.stderr
            results.append({"scenario": scenario, "exitCode": result.returncode,
                            "safeRefusal": safe, "streams": streams})
    print(json.dumps({"case": "python-controls", "script": str(script.relative_to(ROOT)),
                      "scriptSha256": digest(script.read_bytes()), "cases": results,
                      "memoryLimitBytes": MEMORY_LIMIT}, indent=2))
    assert all(result["safeRefusal"] for result in results)


def source_scan(inventory_label):
    files = set(path for path in (ROOT / "src").rglob("*")
                if path.is_file() and path.suffix in (".rs", ".c", ".h", ".S"))
    files.add(ROOT / "build.rs")
    files.update(path for path in (ROOT / "vendor/phc-winner-argon2").rglob("*") if path.is_file())
    files.update(ROOT / relative for relative in (
        "packaging/mhfe-fast-mode.py", "packaging/mhfe-launch.sh",
        "packaging/mhfe-launch.command", "packaging/mhfe-launch.bat",
        "scripts/verify-hidden-input.py", "scripts/generate-cell-widths.py",
    ))
    pattern = re.compile(
        r"https?://|wss?://|socket|connect\(|send_to|Command::|process::Command|spawn\(|"
        r"system\(|exec[a-z]*\(|popen\(|fork\(|fs::|File::|OpenOptions|write_all|env::var|"
        r"std::env|include_bytes|include_str|obfuscat|backdoor|telemetry|upload|home_dir|"
        r"\.ssh|\.aws|wallet\.dat|GENKAT|FLAG_clear_internal_memory|REDUCED|"
        r"getrandom|random::|SystemTime|UNIX_EPOCH|hostname|username", re.I
    )
    records, matches = [], []
    previous = json.loads((ROOT / "docs/audits/AUD-018-evidence/native-malicious-inventory.json")
                          .read_text()) if (ROOT / "docs/audits/AUD-018-evidence/native-malicious-inventory.json").exists() else None
    old = {entry["path"]: entry["sha256"] for entry in previous["files"]} if previous else {}
    for path in sorted(files):
        data = path.read_bytes()
        relative = str(path.relative_to(ROOT))
        head = subprocess.check_output(["git", "show", "HEAD:" + relative], cwd=ROOT)
        assert data == head, relative + " changed from reviewed HEAD"
        records.append({"path": relative, "sha256": digest(data), "bytes": len(data),
                        "lines": len(data.splitlines()), "matchesHead": True,
                        "aud018Comparison": "same" if old.get(relative) == digest(data)
                        else "different" if relative in old else "absent"})
        for line, text in enumerate(data.decode(errors="replace").splitlines(), 1):
            if pattern.search(text):
                matches.append({"path": relative, "line": line, "text": text})
    vendor = (ROOT / "vendor/phc-winner-argon2.md").read_text()
    vendor_matches = []
    for expected, relative in re.findall(r"^([0-9a-f]{64})  (\S+)$", vendor, re.M):
        relative = "vendor/phc-winner-argon2/" + relative
        actual = digest((ROOT / relative).read_bytes())
        vendor_matches.append({"path": relative, "expected": expected, "actual": actual,
                               "matches": expected == actual})
    assert len(vendor_matches) == 22 and all(entry["matches"] for entry in vendor_matches)
    result = {"files": records, "candidateMatches": matches, "vendorChecks": vendor_matches,
              "fileCount": len(records), "totalLines": sum(entry["lines"] for entry in records),
              "totalBytes": sum(entry["bytes"] for entry in records)}
    path = EVIDENCE / (inventory_label + ".json")
    with path.open("x") as output:
        json.dump(result, output, indent=2)
        output.write("\n")
    print(json.dumps({"case": "source-scan", "fileCount": result["fileCount"],
                      "totalLines": result["totalLines"], "totalBytes": result["totalBytes"],
                      "candidateCount": len(matches), "vendorHashMatches": len(vendor_matches),
                      "inventorySha256": digest(path.read_bytes())}))


def platform_style():
    suite = load("scripts/verify-hidden-input.py", "aud019_terminal_suite")
    marks = (("Isolation", "not available here: this system offers none to a program"),
             ("Hidden input", "not available here: no terminal"), ("Cipher hashes", "as published"))
    lines = suite.self_test_report(marks, suite.painted)
    text = "\n".join(lines)
    assert text.count(suite.GREY + "not available here: ") == 2
    assert suite.PASS + "not available here: " not in text
    assert suite.PASS + "as published" in text
    source = (ROOT / "src/bin/mhfe/self_test.rs").read_text()
    assert 'ComponentOutcome::NotAvailable(reason) => (MUTED, format!("not available here: {reason}"))' in source
    print(json.dumps({"case": "platform-style", "expectedUnavailableStyle": "bright black",
                      "expectedPassedStyle": "bold green", "helperOutputEscaped": text,
                      "productionTrace": "self_test.rs part_row maps NotAvailable to MUTED, Passed to GOOD",
                      "limitation": "Source/helper check only; no macOS binary executed."}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("case", choices=["source-scan", "platform-style", "python-controls",
                                        "fingerprint", "path-controls", "unicode-original",
                                        "unicode-rocket", "low-memlock", "cli-options"])
    parser.add_argument("target", nargs="?", default="target/release/mhfe")
    parser.add_argument("--raw-label", default="native-python-controls")
    parser.add_argument("--inventory-label", default="native-source-inventory")
    arguments = parser.parse_args()
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    if arguments.case == "source-scan":
        assert re.fullmatch(r"[A-Za-z0-9_-]+", arguments.inventory_label)
        return source_scan(arguments.inventory_label)
    if arguments.case == "platform-style":
        return platform_style()
    if arguments.case == "python-controls":
        assert re.fullmatch(r"[A-Za-z0-9_-]+", arguments.raw_label)
        return python_controls(ROOT / arguments.target, arguments.raw_label)
    # Reuse preserved input and PTY mechanics, without modifying historical audit harnesses.
    previous = load("docs/audits/AUD-018-harnesses/native/verify-boundaries.py", "aud018_native")
    import locale
    locale.setlocale(locale.LC_CTYPE, "")
    program = str((ROOT / arguments.target).resolve())
    print(json.dumps({"binarySha256": digest(Path(program).read_bytes()),
                      "reusedHarnessSha256": digest((ROOT / "docs/audits/AUD-018-harnesses/native/verify-boundaries.py").read_bytes())}))
    cases = {"fingerprint": previous.fingerprint, "path-controls": previous.boundary.path_controls,
             "unicode-original": lambda p: previous.unicode_width(p, "\u754c", "unicode-original"),
             "unicode-rocket": lambda p: previous.unicode_width(p, "\U0001f680", "unicode-rocket"),
             "low-memlock": previous.low_memlock, "cli-options": previous.cli_options}
    cases[arguments.case](program)


if __name__ == "__main__":
    main()
