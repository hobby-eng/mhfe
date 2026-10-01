"""Validate both audit records, command hashes, source identity and local evidence inventory."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

import jsonschema

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-004-evidence"
REPORT = ROOT / "docs/audits/audit-04-2026-10-01"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


data = json.loads(REPORT.with_suffix(".json").read_text(), object_pairs_hook=unique_object)
schema = json.loads((ROOT.parent / "multi-chain-wallet-tools/docs/audit-report.schema.json").read_text())
jsonschema.Draft202012Validator(schema).validate(data)
markdown = REPORT.with_suffix(".md").read_text()
ids = [item["id"] for item in data["findings"] + data["observations"]]
assert len(ids) == len(set(ids))
assert all(identifier in markdown for identifier in ids)
guide = (ROOT.parent / "multi-chain-wallet-tools/docs/FULL_AUDIT_GUIDE.md").read_text()
expected = set(re.findall(r"^### (CHECK-[A-Z]+-\d+)", guide, re.M))
assert len(expected) == 32
assert {item["checkId"] for item in data["checks"]} == expected
assert len(data["checks"]) == 32
for command in data["commands"]:
    assert digest(EVIDENCE / (command["label"] + ".log")) == command["logSha256"]
late = json.loads((EVIDENCE / data["snapshot"].get("inventoryFile", "snapshot.json")).read_text())
for name, expected_hash in late["sourceFiles"].items():
    if name != "docs/audits/README.md":
        assert digest(ROOT / name) == expected_hash, f"Source changed after final phase: {name}"
for name, expected_hash in late["specificationFiles"].items():
    assert digest(ROOT.parent / "mhfe_spec" / name) == expected_hash
for source in [REPORT.with_suffix(".md"), ROOT / "docs/audits/README.md", Path(__file__).with_name("README.md")]:
    for link in re.findall(r"\]\(([^)]+)\)", source.read_text()):
        if "://" not in link and not link.startswith("#"):
            target = link.split("#", 1)[0]
            assert (source.parent / target).exists(), (source, link)
staged = subprocess.check_output(["git", "diff", "--cached", "--name-only"], cwd=ROOT, text=True)
assert "AUD-004-evidence" not in staged
ignored = subprocess.run(["git", "check-ignore", "--quiet", str(EVIDENCE / "snapshot.json")], cwd=ROOT)
assert ignored.returncode == 0
record = {
    "validatedAt": datetime.now(timezone.utc).isoformat(), "schemaValid": True,
    "duplicateKeys": False, "findings": len(data["findings"]),
    "observations": len(data["observations"]), "procedureChecks": len(data["checks"]),
    "recordIdsPresentInMarkdown": True, "localLinksResolve": True,
    "commandLogHashesMatch": True, "reviewedSourceUnchanged": True,
    "evidenceIgnoredAndUnstaged": True,
    "reportHashes": {path.name: digest(path) for path in (REPORT.with_suffix(".md"), REPORT.with_suffix(".json"))},
}
(EVIDENCE / "report-validation.json").write_text(json.dumps(record, indent=2) + "\n")
manifest = "".join(f"{digest(path)}  {path.relative_to(EVIDENCE)}\n"
                   for path in sorted(EVIDENCE.rglob("*"))
                   if path.is_file() and path != EVIDENCE / "SHA256SUMS")
(EVIDENCE / "SHA256SUMS").write_text(manifest)
print(json.dumps(record, indent=2))
