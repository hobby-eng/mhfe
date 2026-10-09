"""Validate AUD-012 paired report and local evidence; requires installed jsonschema."""

import hashlib
import json
from pathlib import Path
import re
import subprocess

import jsonschema

ROOT = Path.cwd()
BASE = ROOT / "docs/audits"
EVIDENCE = BASE / "AUD-012-evidence"
REPORT = BASE / "audit-12-2026-10-08"


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
assert ids == set(re.findall(r"AUD-012-(?:SEC|FUN|API|BLD|DOC|UI|ARC)\d{3,}", markdown))
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
final = read_json(EVIDENCE / "final.json")
assert final["sourceFingerprint"] == record["snapshot"]["sourceFingerprint"]
for path, expected in final["records"]:
    assert (not (ROOT / path).exists()) if expected == "deleted" else digest(ROOT / path) == expected
for target in re.findall(r"\]\(([^)]+)\)", markdown):
    if not target.startswith(("http:", "https:", "#")):
        assert (BASE / target.split("#")[0]).exists(), target
old = read_json(BASE / "audit-11-2026-10-08.json")
latest = old["followups"][-1]
assert latest["sourceFingerprint"] == record["snapshot"]["sourceFingerprint"]
assert latest["verification"] == record["priorFindingVerification"]
assert all(item["status"] == "verified" for item in latest["verification"])
staged = subprocess.check_output(["git", "diff", "--cached", "--name-only"], text=True)
assert "AUD-012-evidence/" not in staged
assert subprocess.run(["git", "check-ignore", "docs/audits/AUD-012-evidence/snapshot.json"],
                      capture_output=True).returncode == 0
result = {"auditId": "AUD-012", "schema": "passed", "duplicateKeys": "none",
          "pairedIds": sorted(ids), "checks": 32, "finalSourceMatches": True,
          "concurrentBaselinePreserved": True, "priorVerificationMatches": True,
          "commandHashes": "passed", "harnessHashes": "passed", "links": "passed",
          "evidenceIgnoredAndNotStaged": True}
(EVIDENCE / "report-validation.json").write_text(json.dumps(result, indent=2) + "\n")
paths = sorted(p for p in EVIDENCE.iterdir() if p.is_file() and p.name != "SHA256SUMS")
(EVIDENCE / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.name}\n" for p in paths))
print(json.dumps(result, indent=2))
