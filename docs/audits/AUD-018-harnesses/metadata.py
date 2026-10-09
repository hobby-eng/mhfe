#!/usr/bin/env python3
"""Bind current release artifacts, versions and repository identities without rebuilding."""

import datetime
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-018-evidence"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(arguments):
    result = subprocess.run(arguments, cwd=ROOT, capture_output=True, text=True, timeout=30)
    return {"argv": arguments, "exitCode": result.returncode, "output": (result.stdout + result.stderr).strip()}


def main():
    paths = [ROOT / "target/release/mhfe", *sorted((ROOT / "dist").rglob("*"))]
    paths += sorted((ROOT / "canonical-output-aud018/release").glob("*"))
    files = {str(path.relative_to(ROOT)): {"bytes": path.stat().st_size, "sha256": digest(path)} for path in paths if path.is_file()}
    record = {
        "capturedUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "tools": [command(args) for args in [["rustc", "-Vv"], ["cargo", "--version"], ["wasm-bindgen", "--version"], ["node", "--version"], ["python3", "--version"], ["target/release/mhfe", "--version"], ["node", "-e", "for (const p of ['playwright','prettier']) console.log(p,require(p+'/package.json').version)"]]],
        "environment": {key: os.environ[key] for key in ["CARGO_HOME", "RUSTUP_HOME", "PATH", "CARGO_BUILD_JOBS", "RUST_TEST_THREADS"] if key in os.environ},
        "artifacts": files,
        "hostBrowserBuildId": json.loads((ROOT / "dist/modules.json").read_text())["buildId"],
        "head": command(["git", "rev-parse", "HEAD"])["output"],
        "headHasSignatureHeader": b"\ngpgsig " in subprocess.check_output(["git", "cat-file", "-p", "HEAD"], cwd=ROOT),
        "signatureVerification": "Header observed; cryptographic signer verification not performed, no release candidate fix commit or tag created.",
        "localTags": {tag: command(["git", "rev-parse", tag + "^{commit}"])["output"] for tag in ["v0.3.0", "v0.4.0", "v0.5.0"]},
    }
    name = sys.argv[1] if len(sys.argv) > 1 else "metadata"
    target = EVIDENCE / (name + ".json")
    if target.exists():
        raise SystemExit("Metadata label already exists; use another label.")
    target.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"nativeSha256": files["target/release/mhfe"]["sha256"], "browserBuildId": record["hostBrowserBuildId"], "files": len(files)}))


if __name__ == "__main__":
    main()
