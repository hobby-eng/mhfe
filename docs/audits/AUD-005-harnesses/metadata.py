"""Verify source identity, corpus provenance and vendored hashes without computing vectors."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-005-evidence"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


snapshot_name = sys.argv[1] if len(sys.argv) == 2 else "snapshot.json"
snapshot = json.loads((EVIDENCE / snapshot_name).read_text())
changed = [name for name, expected in snapshot["sourceFiles"].items()
           if name != "docs/audits/README.md" and digest(ROOT / name) != expected]
assert not changed, changed
spec = ROOT.parent / "mhfe_spec"
for name, expected in snapshot["specificationFiles"].items():
    assert digest(spec / name) == expected, name
print("All baseline tracked files except the audit index, and normative specification files, are unchanged.")
print("Current specification commit:", subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=spec, text=True).strip())

vendor = ROOT / "vendor/phc-winner-argon2"
entries = re.findall(r"^([a-f0-9]{64})  (.+)$", (ROOT / "vendor/phc-winner-argon2.md").read_text(), re.M)
for expected, name in entries:
    assert digest(vendor / name) == expected, name
assert len(entries) == len([path for path in vendor.rglob("*") if path.is_file()])
print(f"All {len(entries)} vendored Argon2 files match the recorded SHA-256 hashes.")

corpus = ROOT / "tests/fixtures/suite3-vectors"
record = json.loads((corpus / "independent-verification.json").read_text())
assert record["verifier"]["sha256"] == digest(ROOT / "scripts/independent-suite3.py")
for entry in record["files"]:
    name = entry["name"]
    assert "full" in entry["checks"], name
    assert entry["sha256"] == digest(corpus / name) == digest(spec / "vectors/suite3" / name), name
assert len(record["files"]) == 18
assert digest(ROOT / "tests/fixtures/validation-cases.json") == digest(spec / "vectors/suite3/validation-cases.json")
print("The 18 corpus files and fast cases equal the specification bytes; all 18 have upstream full replay records.")
print("This checks provenance only, and does not execute the independent verifier or recompute vectors.")

artifacts = {
    str(path.relative_to(ROOT)): digest(path)
    for path in sorted((ROOT / "dist").iterdir()) if path.is_file()
}
artifacts["target/debug/mhfe"] = digest(ROOT / "target/debug/mhfe")
(EVIDENCE / "artifact-hashes.json").write_text(json.dumps(artifacts, indent=2) + "\n")
print(json.dumps(artifacts, indent=2))
