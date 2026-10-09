#!/usr/bin/env python3
"""Bind newly built artifacts and local release references to AUD-016 evidence."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-016-evidence"
metadata = json.loads((EVIDENCE / "cargo-metadata.log").read_text())
foreign = [package["name"] for package in metadata["packages"]
           if package["source"] is None and package["name"] != "mhfe-experimental"]
record = {
    "foreignLocalPackages": foreign,
    "dependencyPackagesInHostGraph": len(metadata["packages"]),
    "commitHasSignatureHeader": b"\ngpgsig " in subprocess.check_output(["git", "cat-file", "-p", "HEAD"], cwd=ROOT),
    "localReleaseTags": {tag: subprocess.check_output(["git", "rev-parse", tag + "^{commit}"], cwd=ROOT).decode().strip()
                         for tag in ("v0.3.0", "v0.4.0", "v0.5.0")},
    "artifactHashes": {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                       for path in [ROOT / "target/release/mhfe", *sorted((ROOT / "dist").rglob("*"))]
                       if path.is_file()},
    "browserBuildId": json.loads((ROOT / "dist/modules.json").read_text())["buildId"],
}
(EVIDENCE / "source-artifact-bindings.json").write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps(record, indent=2))
assert not foreign, "Unexpected local package in dependency graph"
