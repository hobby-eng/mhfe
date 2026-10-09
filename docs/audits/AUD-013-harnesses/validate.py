"""Validate the AUD-013 pair, source binding, retained hashes and AUD-012 follow-up."""

import hashlib
import json
from pathlib import Path
import re
import subprocess

import jsonschema

ROOT = Path.cwd()
BASE = ROOT / "docs/audits"
EVIDENCE = BASE / "AUD-013-evidence"


def unique(pairs):
    value = {}
    for key, item in pairs:
        assert key not in value, f"duplicate JSON key: {key}"
        value[key] = item
    return value


def read(path):
    return json.loads(path.read_text(), object_pairs_hook=unique)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


record = read(BASE / "audit-13-2026-10-08.json")
schema = read(ROOT.parent / "multi-chain-wallet-tools/docs/audit-report.schema.json")
jsonschema.Draft202012Validator(schema).validate(record)
markdown = (BASE / "audit-13-2026-10-08.md").read_text()
ids = {item["id"] for item in record["findings"]}
assert len(ids) == len(record["findings"])
assert ids == set(re.findall(r"AUD-013-(?:SEC|FUN|API|BLD|DOC|UI|ARC)\d{3,}", markdown))
prior = record["priorFindingVerification"]
assert {item["id"] for item in record["remediation"]} == ids | {item["id"] for item in prior}
assert len(record["checks"]) == len({item["id"] for item in record["checks"]}) == 32
assert all(item["outcome"] in {"passed", "failed", "not-run", "not-applicable", "blocked", "skipped"}
           for item in record["checks"])
final = read(EVIDENCE / "final.json")
assert record["snapshot"]["sourceFingerprint"] == final["sourceFingerprint"]
assert read(EVIDENCE / "snapshot.json")["sourceFingerprint"] == final["sourceFingerprint"]
for path, expected in final["records"]:
    assert (not (ROOT / path).exists()) if expected == "deleted" else digest(ROOT / path) == expected
for path, expected in record["procedureHashes"].items():
    assert digest(ROOT.parent / path) == expected, path
for path, expected in record["harnessHashes"].items():
    assert digest(ROOT / path) == expected, path
for item in record["commands"]:
    assert digest(EVIDENCE / (item["label"] + ".log")) == item["logSha256"], item["label"]
for item in record["incompleteEvidence"]:
    assert digest(EVIDENCE / item["path"]) == item["sha256"]
for target in re.findall(r"\]\(([^)]+)\)", markdown):
    if not target.startswith(("http:", "https:", "#")):
        assert (BASE / target.split("#")[0]).exists(), target
old = read(BASE / "audit-12-2026-10-08.json")
jsonschema.Draft202012Validator(schema).validate(old)
assert old["followups"][-1]["verification"] == prior
baseline = dict(old)
baseline.pop("followups", None)
canonical = json.dumps(baseline, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
assert hashlib.sha256(canonical.encode()).hexdigest() == record["priorBaselineCanonicalSha256"]
staged = subprocess.check_output(["git", "diff", "--cached", "--name-only"], text=True)
assert "AUD-013-evidence/" not in staged
assert subprocess.run(["git", "check-ignore", "docs/audits/AUD-013-evidence/snapshot.json"],
                      capture_output=True).returncode == 0
result = {"auditId": "AUD-013", "schema": "passed", "duplicateKeys": "none",
          "pairedIds": sorted(ids), "checks": 32, "sourceUnchanged": True,
          "priorBaselinePreserved": True, "priorFollowupMatches": True,
          "commandHarnessProcedureHashes": "passed", "links": "passed",
          "evidenceIgnoredAndNotStaged": True}
(EVIDENCE / "report-validation.json").write_text(json.dumps(result, indent=2) + "\n")
files = sorted(path for path in EVIDENCE.iterdir() if path.is_file() and path.name != "SHA256SUMS")
(EVIDENCE / "SHA256SUMS").write_text("".join(f"{digest(path)}  {path.name}\n" for path in files))
print(json.dumps(result, indent=2))
