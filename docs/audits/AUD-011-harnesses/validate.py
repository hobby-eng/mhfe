"""Validate the AUD-011 report pair and local evidence; requires installed jsonschema."""

import hashlib
import json
from pathlib import Path
import re
import subprocess

import jsonschema

ROOT = Path.cwd()
BASE = ROOT / "docs/audits"
EVIDENCE = BASE / "AUD-011-evidence"
REPORT = BASE / "audit-11-2026-10-08"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, f"Duplicate JSON key: {key}"
        result[key] = value
    return result


def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


record = read_json(REPORT.with_suffix(".json"))
schema = read_json(ROOT.parent / "multi-chain-wallet-tools/docs/audit-report.schema.json")
jsonschema.Draft202012Validator(schema).validate(record)
markdown = REPORT.with_suffix(".md").read_text()
ids = {entry["id"] for entry in record["findings"] + record["observations"]}
assert len(ids) == len(record["findings"]) + len(record["observations"])
assert ids == set(re.findall(r"AUD-011-(?:SEC|FUN|API|BLD|DOC|UI|ARC)\d{3,}", markdown))
assert {entry["id"] for entry in record["remediation"]} == ids
assert len(record["checks"]) == len({check["id"] for check in record["checks"]}) == 32
allowed = {"passed", "failed", "blocked", "skipped", "not-run", "not-applicable"}
assert all(check["outcome"] in allowed for check in record["checks"])
for path, expected in record["procedureHashes"].items():
    assert digest(ROOT.parent / path) == expected, path
for command in record["commands"]:
    assert digest(EVIDENCE / (command["label"] + ".log")) == command["logSha256"]
for path, expected in record["harnessHashes"].items():
    assert digest(ROOT / path) == expected, path
baseline = read_json(EVIDENCE / "snapshot.json")
final = read_json(EVIDENCE / "final.json")
assert baseline["sourceFingerprint"] == final["sourceFingerprint"] == record["snapshot"]["sourceFingerprint"]
for target in re.findall(r"\]\(([^)]+)\)", markdown):
    if not target.startswith(("http:", "https:", "#")):
        assert (BASE / target.split("#")[0]).exists(), target
staged = subprocess.check_output(["git", "diff", "--cached", "--name-only"], text=True)
assert "AUD-011-evidence/" not in staged
assert subprocess.run(["git", "check-ignore", "docs/audits/AUD-011-evidence/snapshot.json"],
                      capture_output=True).returncode == 0
result = {"auditId": "AUD-011", "schema": "passed", "duplicateKeys": "none",
          "pairedIds": sorted(ids), "checks": 32, "sourceUnchanged": True,
          "commandHashes": "passed", "harnessHashes": "passed", "links": "passed",
          "evidenceIgnoredAndNotStaged": True}
(EVIDENCE / "report-validation.json").write_text(json.dumps(result, indent=2) + "\n")
paths = sorted(p for p in EVIDENCE.iterdir() if p.is_file() and p.name != "SHA256SUMS")
(EVIDENCE / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.name}\n" for p in paths))
print(json.dumps(result, indent=2))
