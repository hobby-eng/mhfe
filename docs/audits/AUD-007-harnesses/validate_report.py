"""Validate the AUD-007 report pair, reviewed baseline, commands and local evidence.

Run from the mhfe repository root. Requires the already available jsonschema package and the
ignored AUD-007 evidence captured by this audit. Nothing in production is modified. The report
records a dirty specification snapshot; its retained diff, rather than its HEAD alone, identifies
that state. An owner-authorized later Electrum documentation follow-up is checked separately.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

import jsonschema

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-007-evidence"
REPORT = ROOT / "docs/audits/audit-07-2026-10-05"
WORKSPACE = ROOT.parent
GUIDE = WORKSPACE / "multi-chain-wallet-tools/docs/FULL_AUDIT_GUIDE.md"
SCHEMA = WORKSPACE / "multi-chain-wallet-tools/docs/audit-report.schema.json"
PROCEDURE_CHECK_COUNT = 32
# The JSON statuses of multi-chain-wallet-tools/docs/audits/AUDIT_STANDARD.md.
REMEDIATION_STATUSES = {
    "open", "fixed", "verified", "deferred", "accepted", "not-reproduced", "withdrawn", "duplicate",
}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(*args, repository=ROOT):
    return subprocess.check_output(["git", *args], cwd=repository)


def check_local_links(path):
    for target in re.findall(r"\]\(([^)]+)\)", path.read_text()):
        if "://" in target or target.startswith("#"):
            continue
        # Report file links never contain titles; strip a fragment for filesystem validation.
        target = target.strip("<>").split("#", 1)[0]
        assert (path.parent / target).exists(), (path, target)


data = read_json(REPORT.with_suffix(".json"))
jsonschema.Draft202012Validator(read_json(SCHEMA)).validate(data)
markdown = REPORT.with_suffix(".md").read_text()
assert data["auditId"] == "AUD-007" and data["auditNumber"] == 7
assert data["date"] == "2026-10-05"
assert data["reviewer"]["model"] is None
assert data["reviewer"]["reasoningEffort"] is None

records = data["findings"] + data["observations"]
ids = [item["id"] for item in records]
assert len(ids) == len(set(ids)), "duplicate finding IDs"
for item in records:
    assert item["id"].startswith("AUD-007-" + item["category"]), item["id"]
    heading = re.search(rf"^#### {item['id']} — (\w+) — (.+)$", markdown, re.M)
    assert heading and heading.group(1).lower() == item["severity"], item["id"]
    assert heading.group(2) == item["title"], item["id"]
    assert f"| {item['id']} | {item['category']} | {item['kind']} |" in markdown, item["id"]
    assert item["status"] in REMEDIATION_STATUSES, item["id"]
assert set(re.findall(r"^#### (AUD-007-[A-Z]+\d+) —", markdown, re.M)) == set(ids)
remediation = {item["id"]: item for item in data["remediation"]}
assert set(ids) == set(remediation), "missing or unexpected remediation rows"
# The remediation update records fixes made after the reviewed commit; each finding still describes
# that commit. A named fix or verification commit must exist in its repository: this one, or the
# specification when the fix commit names "mhfe_spec".
for item in records:
    row = remediation[item["id"]]
    assert row["status"] == item["status"], item["id"]
    assert f"| {item['id']} | {item['status']} |" in markdown, item["id"]
    fixed_in = WORKSPACE / "mhfe_spec" if (row["fixCommit"] or "").startswith("mhfe_spec ") else ROOT
    for commit in re.findall(r"\b[0-9a-f]{7,40}\b", row["fixCommit"] or ""):
        git("cat-file", "-e", commit + "^{commit}", repository=fixed_in)
    if item["status"] in ("fixed", "verified"):
        assert row["fixCommit"], item["id"]
    if item["status"] == "verified":
        assert re.fullmatch(r"[0-9a-f]{40}", row["verificationCommit"] or ""), item["id"]
        git("cat-file", "-e", row["verificationCommit"] + "^{commit}")
    else:
        assert row["verificationCommit"] is None, item["id"]

expected_checks = set(re.findall(r"^### (CHECK-[A-Z]+-\d+)", GUIDE.read_text(), re.M))
assert len(expected_checks) == PROCEDURE_CHECK_COUNT
assert len(data["checks"]) == PROCEDURE_CHECK_COUNT
assert {item["checkId"] for item in data["checks"]} == expected_checks
allowed_outcomes = {"passed", "failed", "blocked", "skipped", "not-run", "not-applicable"}
for item in data["checks"]:
    assert item["checkId"] in markdown, item["checkId"]
    assert item["outcome"] in allowed_outcomes, item["checkId"]

labels = [item["label"] for item in data["commands"]]
assert len(labels) == len(set(labels)), "duplicate command labels"
for command in data["commands"]:
    label = command["label"]
    log = EVIDENCE / (label + ".log")
    saved_path = EVIDENCE / (label + ".command.json")
    saved = read_json(saved_path)
    assert digest(log.read_bytes()) == command["logSha256"], label
    assert command["logSha256"] in markdown, label
    assert digest(saved_path.read_bytes()) == command["commandRecordSha256"], label
    assert saved["command"] == command["command"], label
    assert saved.get("exitCode", saved.get("exit_code")) == command["exitCode"], label
    assert saved.get("cwd") == command["cwd"], label
    if "logSha256" in saved:
        assert saved["logSha256"] == command["logSha256"], label
    assert command["evidence"].startswith("Local only:"), label

# Later command registers are separate from the immutable original audit ledger. Verify their
# retained outputs as well: the original validator checked only data["commands"].
follow_up_command_count = 0
FOLLOW_UPS = ("remediationUpdate", "independentRecheck", "ownerAuthorizedRemediation", "commitBinding")
for update_name in FOLLOW_UPS:
    update = data.get(update_name, {})
    update_labels = [command["label"] for command in update.get("commands", [])]
    assert len(update_labels) == len(set(update_labels)), update_name
    for command in update.get("commands", []):
        label = command["label"]
        assert label not in labels, (update_name, label)
        log = EVIDENCE / (label + ".log")
        saved_path = EVIDENCE / (label + ".command.json")
        saved = read_json(saved_path)
        assert digest(log.read_bytes()) == command["logSha256"], label
        assert command["logSha256"] in markdown, label
        assert saved.get("exitCode", saved.get("exit_code")) == command["exitCode"], label
        if "logSha256" in saved:
            assert saved["logSha256"] == command["logSha256"], label
        if "commandRecordSha256" in command:
            assert digest(saved_path.read_bytes()) == command["commandRecordSha256"], label
            assert saved["command"] == command["command"], label
            assert saved["cwd"] == command["cwd"], label
        follow_up_command_count += 1

if "ownerAuthorizedRemediation" in data:
    update = data["ownerAuthorizedRemediation"]
    manifest_path = EVIDENCE / "remedy-final-source.json"
    assert digest(manifest_path.read_bytes()) == update["sourceManifestSha256"]
    manifest = read_json(manifest_path)
    assert manifest["sourceFingerprint"] == update["sourceFingerprint"]
    fingerprint = digest("".join(
        f"{name}\0{expected}\n" for name, expected in manifest["files"].items()
    ).encode())
    assert fingerprint == manifest["sourceFingerprint"]
    # The manifest bound uncommitted working bytes. They were committed with later edits, so once
    # the commit binding exists it, not the working tree, identifies the fixes.
    if "commitBinding" not in data:
        for name, expected in manifest["files"].items():
            assert digest((WORKSPACE / name).read_bytes()) == expected, name

if "commitBinding" in data:
    binding = data["commitBinding"]
    bound = set()
    for entry in binding["commits"]:
        repository = WORKSPACE / entry["repository"]
        commit = entry["commit"]
        assert re.fullmatch(r"[0-9a-f]{40}", commit), commit
        # Signed, and part of the history that carries this record (for the specification: its
        # checked-out history).
        assert b"\ngpgsig " in git("cat-file", "commit", commit, repository=repository), commit
        git("merge-base", "--is-ancestor", commit, "HEAD", repository=repository)
        for identifier in entry["findings"]:
            assert remediation[identifier]["fixCommit"].replace("mhfe_spec ", "").startswith(commit[:7])
            assert commit[:7] in markdown, identifier
            bound.add(identifier)
    owner_fixed = set(data["ownerAuthorizedRemediation"]["findings"])
    assert owner_fixed <= bound, "every owner-authorized fix needs its commit"
    git("merge-base", "--is-ancestor", binding["verificationCommit"], "HEAD")
    for identifier in bound:
        if remediation[identifier]["status"] == "verified":
            assert remediation[identifier]["verificationCommit"] == binding["verificationCommit"]

if "independentRecheck" in data:
    follow = data["independentRecheck"]
    snapshot_file = EVIDENCE / "recheck-snapshot.json"
    assert digest(snapshot_file.read_bytes()) == follow["snapshotEvidenceSha256"]
    captured = read_json(snapshot_file)
    assert captured["commit"] == follow["commit"]
    assert captured["specification"] == follow["specificationFiles"]
    for name, expected in captured["sourceFiles"].items():
        assert digest(git("show", f"{captured['commit']}:{name}")) == expected, name

snapshot_path = EVIDENCE / "snapshot.json"
snapshot = read_json(snapshot_path)
assert digest(snapshot_path.read_bytes()) == data["snapshot"]["snapshotEvidenceSha256"]
assert snapshot["commit"] == data["snapshot"]["commit"]
assert snapshot["sourceFingerprint"] == data["snapshot"]["sourceFingerprint"]
fingerprint = digest(
    "".join(f"{name}\0{value}\n" for name, value in snapshot["sourceFiles"].items()).encode()
)
assert fingerprint == snapshot["sourceFingerprint"]
for name, expected in snapshot["sourceFiles"].items():
    assert digest(git("show", f"{snapshot['commit']}:{name}")) == expected, name

# An unchanged HEAD must retain the reviewed production bytes. Only the audit index is edited.
reviewing = git("rev-parse", "HEAD").decode().strip() == snapshot["commit"]
if reviewing:
    for name, expected in snapshot["sourceFiles"].items():
        if name != "docs/audits/README.md":
            assert digest((ROOT / name).read_bytes()) == expected, name

assert data["snapshot"]["specificationFiles"] == snapshot["specificationFiles"]
assert data["snapshot"]["specificationWorkingTree"] == snapshot["specificationWorkingTree"]
assert digest((EVIDENCE / "specification.diff").read_bytes()) == data["snapshot"]["specificationDiffSha256"]

# The reviewed specification was dirty, so git show(HEAD:path) is intentionally NOT treated as
# its byte identity. A later limited doc edit has its own before/after manifest and citation map.
follow_up = EVIDENCE / "electrum-follow-up.json"
if follow_up.exists():
    follow = read_json(follow_up)
    assert follow["before"] == snapshot["specificationFiles"]
    assert follow["citationMapping"] == {str(old): old + 1 for old in range(45, 64)}
    if "targetedDocumentationFollowUp" in data:
        assert digest(follow_up.read_bytes()) == data["targetedDocumentationFollowUp"]["recordSha256"]
    if reviewing:
        for name, expected in follow["afterFormatting"].items():
            assert digest((WORKSPACE / "mhfe_spec" / name).read_bytes()) == expected, name

for name, expected in data["procedureHashes"].items():
    if reviewing:
        assert digest((WORKSPACE / name).read_bytes()) == expected, name
    assert expected in markdown, name

for path in (REPORT.with_suffix(".md"), ROOT / "docs/audits/README.md", Path(__file__).with_name("README.md")):
    check_local_links(path)
assert not git("ls-files", "docs/audits/AUD-007-evidence").decode(), "evidence is tracked"
assert "AUD-007-evidence" not in git("diff", "--cached", "--name-only").decode(), "evidence is staged"
assert subprocess.run(["git", "check-ignore", "--quiet", str(snapshot_path)], cwd=ROOT).returncode == 0

validation = {
    "validatedAt": datetime.now(timezone.utc).isoformat(),
    "schemaValid": True,
    "duplicateKeys": False,
    "findings": len(data["findings"]),
    "procedureChecks": len(data["checks"]),
    "recordIdsAndHeadingsMatchMarkdown": True,
    "localLinksResolve": True,
    "commandLogHashesMatch": len(data["commands"]),
    "followUpCommandLogHashesMatch": follow_up_command_count,
    "ownerFixesBoundToSignedCommits": "commitBinding" in data,
    "reviewedCommitHoldsMhfeSnapshot": True,
    "dirtySpecificationSnapshotRetainedByDiffAndManifest": True,
    "electrumFollowUpCheckedSeparately": follow_up.exists(),
    "evidenceIgnoredUntrackedAndUnstaged": True,
    "reportHashes": {
        path.name: digest(path.read_bytes())
        for path in (REPORT.with_suffix(".md"), REPORT.with_suffix(".json"))
    },
}
(EVIDENCE / "report-validation.json").write_text(json.dumps(validation, indent=2) + "\n")
manifest = "".join(
    f"{digest(path.read_bytes())}  {path.relative_to(EVIDENCE)}\n"
    for path in sorted(EVIDENCE.rglob("*"))
    if path.is_file() and path != EVIDENCE / "SHA256SUMS"
)
(EVIDENCE / "SHA256SUMS").write_text(manifest)
print(json.dumps(validation, indent=2))
