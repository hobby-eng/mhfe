"""Validate the AUD-006 records, command log hashes, reviewed-source identity and local evidence.

The reviewed source is checked against the git objects of the reviewed commit, not against the
working tree, so the check stays valid after the remediation commits that follow the review.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

import jsonschema

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-006-evidence"
REPORT = ROOT / "docs/audits/audit-06-2026-10-01"
GUIDE = ROOT.parent / "multi-chain-wallet-tools/docs/FULL_AUDIT_GUIDE.md"
SCHEMA = ROOT.parent / "multi-chain-wallet-tools/docs/audit-report.schema.json"
# The guide defines 32 procedure IDs; every one must have a recorded outcome.
PROCEDURE_CHECKS = 32


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


data = json.loads(REPORT.with_suffix(".json").read_text(), object_pairs_hook=unique_object)
jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text())).validate(data)
markdown = REPORT.with_suffix(".md").read_text()

records = data["findings"] + data["observations"]
ids = [item["id"] for item in records]
assert len(ids) == len(set(ids)), "duplicate finding IDs"
for item in records:
    assert item["id"].startswith("AUD-006-" + item["category"]), item["id"]
    assert item["id"] in markdown, item["id"]
    heading = re.search(rf"^#### {item['id']} — (\w+) — (.+)$", markdown, re.M)
    assert heading and heading.group(1).lower() == item["severity"], item["id"]
    assert heading.group(2) == item["title"], item["id"]
remediation = {item["id"]: item for item in data["remediation"]}
assert {item["id"] for item in data["findings"]} <= set(remediation), "missing remediation rows"
for item in data["findings"]:
    assert remediation[item["id"]]["status"] == item["status"], item["id"]

expected_checks = set(re.findall(r"^### (CHECK-[A-Z]+-\d+)", GUIDE.read_text(), re.M))
assert len(expected_checks) == PROCEDURE_CHECKS
assert {item["checkId"] for item in data["checks"]} == expected_checks
assert len(data["checks"]) == PROCEDURE_CHECKS
for item in data["checks"]:
    assert item["checkId"] in markdown, item["checkId"]

for command in data["commands"]:
    log = EVIDENCE / (command["label"] + ".log")
    assert digest(log.read_bytes()) == command["logSha256"], command["label"]
    assert command["logSha256"] in markdown, command["label"]

snapshot = json.loads((EVIDENCE / "snapshot.json").read_text())
assert snapshot["commit"] == data["snapshot"]["commit"]
assert snapshot["sourceFingerprint"] == data["snapshot"]["sourceFingerprint"]
for name, expected in snapshot["sourceFiles"].items():
    blob = git("show", f"{snapshot['commit']}:{name}")
    assert digest(blob) == expected, f"reviewed commit does not hold the snapshot bytes: {name}"
fingerprint = digest("".join(f"{n}\0{h}\n" for n, h in snapshot["sourceFiles"].items()).encode())
assert fingerprint == snapshot["sourceFingerprint"]

# While the review runs on the reviewed commit, no tracked file but the audit index may change.
# After it, the remediation commits change the source on purpose, and the identity check above,
# against the git objects of the reviewed commit, is the one that holds.
if git("rev-parse", "HEAD").decode().strip() == snapshot["commit"]:
    for name, expected in snapshot["sourceFiles"].items():
        if name != "docs/audits/README.md":
            assert digest((ROOT / name).read_bytes()) == expected, name
# The specification as reviewed: its files at the recorded commit, not its moving working tree.
for name, expected in snapshot["specificationFiles"].items():
    blob = subprocess.check_output(
        ["git", "show", f"{snapshot['specificationCommit']}:{name}"], cwd=ROOT.parent / "mhfe_spec"
    )
    assert digest(blob) == expected, f"specification commit does not hold the reviewed bytes: {name}"
# The procedure files as used: checked while the review runs. Later edits to them are expected
# and only listed, since the report records the versions this audit followed.
reviewing = git("rev-parse", "HEAD").decode().strip() == snapshot["commit"]
for name, expected in data["procedureHashes"].items():
    if digest((ROOT.parent / name).read_bytes()) != expected:
        assert not reviewing, name
        print(f"Changed since the review: {name}")
for command in data["commands"]:
    saved = json.loads((EVIDENCE / (command["label"] + ".command.json")).read_text())
    assert all(command[key] == value for key, value in saved.items()), command["label"]

for source in [REPORT.with_suffix(".md"), ROOT / "docs/audits/README.md", Path(__file__).with_name("README.md")]:
    for link in re.findall(r"\]\(([^)]+)\)", source.read_text()):
        if "://" not in link and not link.startswith("#"):
            assert (source.parent / link.split("#", 1)[0]).exists(), (source, link)

staged = git("diff", "--cached", "--name-only").decode()
assert "AUD-006-evidence" not in staged
tracked = git("ls-files", "docs/audits/AUD-006-evidence").decode()
assert not tracked, "evidence is tracked"
ignored = subprocess.run(["git", "check-ignore", "--quiet", str(EVIDENCE / "snapshot.json")], cwd=ROOT)
assert ignored.returncode == 0

record = {
    "validatedAt": datetime.now(timezone.utc).isoformat(),
    "schemaValid": True,
    "duplicateKeys": False,
    "findings": len(data["findings"]),
    "observations": len(data["observations"]),
    "procedureChecks": len(data["checks"]),
    "recordIdsAndHeadingsMatchMarkdown": True,
    "localLinksResolve": True,
    "commandLogHashesMatch": len(data["commands"]),
    "reviewedCommitHoldsSnapshot": True,
    "evidenceIgnoredUntrackedAndUnstaged": True,
    "reportHashes": {path.name: digest(path.read_bytes()) for path in (REPORT.with_suffix(".md"), REPORT.with_suffix(".json"))},
}
(EVIDENCE / "report-validation.json").write_text(json.dumps(record, indent=2) + "\n")
manifest = "".join(
    f"{digest(path.read_bytes())}  {path.relative_to(EVIDENCE)}\n"
    for path in sorted(EVIDENCE.rglob("*"))
    if path.is_file() and path != EVIDENCE / "SHA256SUMS"
)
(EVIDENCE / "SHA256SUMS").write_text(manifest)
print(json.dumps(record, indent=2))
