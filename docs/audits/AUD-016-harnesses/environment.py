#!/usr/bin/env python3
"""Record toolchain identity, procedure hashes and existing artifacts for AUD-016."""
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-016-evidence"
PROCEDURE = ROOT.parent / "multi-chain-wallet-tools/docs"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(argv):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=20)
        return {"argv": argv, "exitCode": result.returncode,
                "output": (result.stdout + result.stderr).strip()}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"argv": argv, "unavailable": str(error)}


hashes = {str(path.relative_to(ROOT.parent)): sha(path) for path in (
    PROCEDURE / "FULL_AUDIT_GUIDE.md", PROCEDURE / "audits/AUDIT_STANDARD.md",
    PROCEDURE / "audits/AUDIT_TEMPLATE.md", PROCEDURE / "audit-report.schema.json")}
(EVIDENCE / "procedure-hashes.json").write_text(json.dumps(hashes, indent=2) + "\n")
record = {"system": platform.platform(), "machine": platform.machine(),
          "tools": [command(argv) for argv in (
              ["node", "--version"], ["cargo", "--version"], ["rustc", "-Vv"],
              ["wasm-bindgen", "--version"], ["python3", "--version"],
              ["docker", "--version"], ["git", "--version"],
              ["node", "-e", "for (const p of ['prettier','playwright']) console.log(p,require(p+'/package.json').version)"]
          )], "environment": {k: os.environ[k] for k in
                                   ("CARGO_HOME", "RUSTUP_HOME", "CARGO_BUILD_JOBS") if k in os.environ}}
(EVIDENCE / "environment.json").write_text(json.dumps(record, indent=2) + "\n")
artifacts = {str(path.relative_to(ROOT)): {"sha256": sha(path), "bytes": path.stat().st_size}
             for path in (list((ROOT / "dist").rglob("*")) + [ROOT / "target/release/mhfe"])
             if path.is_file()}
(EVIDENCE / "artifacts-before.json").write_text(json.dumps(artifacts, indent=2) + "\n")
print(json.dumps(record, indent=2))
print("Procedure SHA-256:", json.dumps(hashes))
print("Existing artifacts:", len(artifacts), "(source freshness not assumed)")
