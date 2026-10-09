#!/usr/bin/env python3
"""Capture synthetic Python fallback refusals as bytes before any server starts."""

import hashlib
import json
import resource
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = ROOT / "docs/audits/AUD-018-evidence"
MEMORY_LIMIT = 512 * 1024 * 1024
DEADLINE_SECONDS = 5
# OSC 52 carries only the public text PUBLIC-SYNTHETIC; never print the raw payload.
CONTROL = "\x1b]52;c;UFVCTElDLVNZTlRIRVRJQw==\x07"


def limit_child():
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT, MEMORY_LIMIT))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def probe(script, scenario, name, raw_label):
    with tempfile.TemporaryDirectory(prefix="aud018-public-", dir=EVIDENCE) as temporary:
        folder = Path(temporary)
        if scenario == "parent-path":
            folder = folder / ("public-" + CONTROL)
            folder.mkdir()
        else:
            # Refuse a name mismatch before reading a page or creating a socket.
            (folder / "mhfe-fast-mode.sha256").write_text(
                "0" * 64 + "  listed-" + CONTROL + ".html\n", encoding="utf-8"
            )
        page = folder / "page.html"
        result = subprocess.run(
            [sys.executable, str(script), "--no-browser", str(page)],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=DEADLINE_SECONDS,
            preexec_fn=limit_child,
            check=False,
        )
        streams = {}
        for stream, data in (("stdout", result.stdout), ("stderr", result.stderr)):
            path = EVIDENCE / (raw_label + "-" + name + "-" + stream + ".bin")
            # Every run uses new evidence names; preserve previous raw bytes.
            with path.open("xb") as output:
                output.write(data)
            streams[stream] = {
                "path": str(path.relative_to(ROOT)),
                "bytes": len(data),
                "sha256": digest(data),
                "osc52Count": data.count(b"\x1b]52;"),
                "syntheticControlPresent": CONTROL.encode() in data,
            }
        confirmed = (
            result.returncode == 2
            and result.stdout == b""
            and CONTROL.encode() in result.stderr
            and b"nothing was served" in result.stderr
            and b"Fast mode is running" not in result.stderr
        )
        return {
            "script": str(script.relative_to(ROOT)),
            "scriptSha256": digest(script.read_bytes()),
            "scenario": scenario,
            "exitCode": result.returncode,
            "confirmedRawControlDiagnostic": confirmed,
            "streams": streams,
        }


def main():
    raw_label = sys.argv[1] if len(sys.argv) == 2 else "native-python-path-controls"
    if len(sys.argv) > 2 or not raw_label or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        for character in raw_label
    ):
        raise SystemExit("Usage: verify-python-path-controls.py [fresh-raw-evidence-label]")
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    cases = []
    for name, script in (
        ("packaging", ROOT / "packaging/mhfe-fast-mode.py"),
        ("dist", ROOT / "dist/core/mhfe-fast-mode.py"),
    ):
        if not script.is_file():
            raise SystemExit("Missing reviewed Python fallback: " + str(script.relative_to(ROOT)))
        for scenario in ("parent-path", "checksum-name"):
            cases.append(probe(script, scenario, name + "-" + scenario, raw_label))
    print(
        json.dumps(
            {
                "originalFindingId": "AUD-015-SEC002",
                "memoryLimitBytes": MEMORY_LIMIT,
                "childDeadlineSeconds": DEADLINE_SECONDS,
                "syntheticControlHex": CONTROL.encode().hex(),
                "cases": cases,
                "classification": "Ordinary incomplete remediation; no malicious intent established.",
                "serverBoundary": "All four cases exit through Refused before listener construction.",
            },
            indent=2,
        )
    )
    return 0 if all(case["confirmedRawControlDiagnostic"] for case in cases) else 1


if __name__ == "__main__":
    sys.exit(main())
