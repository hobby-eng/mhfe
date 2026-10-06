#!/usr/bin/env python3
"""Validate the AUD-008 pair, source/procedure bindings and local command evidence."""

import hashlib
import json
from pathlib import Path
import re
import subprocess

import jsonschema

ROOT = Path(__file__).resolve().parents[3]
AUDITS = ROOT / "docs/audits"
EVIDENCE = AUDITS / "AUD-008-evidence"
STEM = "audit-08-2026-10-06"


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read(path):
    return json.loads(path.read_text(), object_pairs_hook=pairs)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    record_path = AUDITS / (STEM + ".json")
    markdown_path = AUDITS / (STEM + ".md")
    record = read(record_path)
    markdown = markdown_path.read_text()
    schema = read(ROOT.parent / "multi-chain-wallet-tools/docs/audit-report.schema.json")
    jsonschema.Draft202012Validator(schema).validate(record)
    findings = record["findings"]
    ids = [item["id"] for item in findings]
    assert len(ids) == len(set(ids))
    assert all(item["kind"] == "finding" and item["status"] == "open" for item in findings)
    assert {item["id"] for item in record["remediation"]} == set(ids)
    assert set(re.findall(r"^#### (AUD-008-[A-Z]{2,3}[0-9]{3})", markdown, re.M)) == set(ids)
    for item in findings:
        assert f'{item["id"]} — {item["severity"].capitalize()} — {item["title"]}' in markdown
        assert item["id"].split("-")[2].startswith(item["category"])
        assert all(item[key] for key in ("evidence", "reproduction", "expected", "observed", "impact", "recommendedFix", "requiredVerification"))
    assert record["assessment"]["verdict"] == "FAIL"
    assert any(item["releaseBlocking"] and item["severity"] == "high" for item in findings)
    assert record["snapshot"]["sourceFingerprint"] in markdown
    assert record["snapshot"]["commit"] in markdown
    assert record["date"] in markdown
    assert not re.search(r"[\u0400-\u04ff]", markdown + record_path.read_text())
    phases = record["reviewerPhases"]
    assert len(phases) == 11 and len({item["agent"] for item in phases}) == 11
    for phase in phases:
        assert phase["model"] is None and phase["reasoningEffort"] is None
        assert digest(EVIDENCE / phase["localEvidence"]) == phase["sha256"]
    plan = read(AUDITS / "AUD-008-harnesses/coverage-plan.json")
    assert {item["checkId"] for item in record["checks"]} == set(plan["checks"])
    assert len(record["checks"]) == 32
    assert all(item["methodAndLimits"] for item in record["checks"])
    snapshot = read(EVIDENCE / "snapshot.json")
    for key, repo in (("mhfe", ROOT), ("specification", ROOT.parent / "mhfe_spec")):
        expected = snapshot[key]
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo).decode().strip()
        assert head == expected["commit"]
        assert all(digest(repo / path) == value for path, value in expected["files"].items())
        tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=repo).decode().split("\0")
        assert {p for p in tracked if p and not p.startswith("docs/audits/") and (repo / p).is_file()} == set(expected["files"])
    for path, value in record["procedureHashes"].items():
        assert digest(Path(path)) == value
    checked_logs = 0
    for ledger in sorted(EVIDENCE.glob("*.command.json")):
        command = read(ledger)
        log = EVIDENCE / (ledger.name.removesuffix(".command.json") + ".log")
        expected_hash = command.get("logSha256", command.get("logSHA256", command.get("log_sha256")))
        assert log.is_file(), ledger.name
        if expected_hash:
            assert digest(log) == expected_hash, ledger.name
        else:
            # Earlier supplemental ledgers were incomplete. Validate their retained hashes
            # against the bound contribution, preserving the original records unchanged.
            original = read(EVIDENCE / "wallet-review.json")["evidence"]
            assert original[log.name] == digest(log), ledger.name
            assert original[ledger.name] == digest(ledger), ledger.name
        checked_logs += 1
    # Resolve links in the retained Markdown and harness entry point. Evidence is local only.
    for doc in (markdown_path, AUDITS / "AUD-008-harnesses/README.md"):
        for target in re.findall(r"\]\(([^)]+)\)", doc.read_text()):
            if target.startswith(("https://", "http://", "#")):
                continue
            local = target.split("#", 1)[0]
            assert (doc.parent / local).exists(), f"{doc}: {target}"
    staged = subprocess.check_output(["git", "diff", "--cached", "--name-only"], cwd=ROOT).decode().splitlines()
    assert not any("AUD-008-evidence/" in path for path in staged)
    assert subprocess.run(["git", "check-ignore", "-q", "docs/audits/AUD-008-evidence/snapshot.json"], cwd=ROOT).returncode == 0
    index = (AUDITS / "README.md").read_text()
    assert f"[AUD-008]({STEM}.md)" in index
    assert f"[{STEM}.json]({STEM}.json)" in index
    final_skeptic = read(EVIDENCE / "final-skeptic-review.json")
    research = read(EVIDENCE / "research-review.json")
    result = {"auditId": "AUD-008", "passed": True, "schema": "Draft202012",
              "pairedFindingIds": ids, "distinctReviewers": 11, "coverageItems": 32,
              "checkedCommandLogs": checked_logs, "productBytesUnchanged": True,
              "procedureHashesMatch": True, "evidenceIgnoredAndUnstaged": True,
              "markdownSha256": digest(markdown_path), "jsonSha256": digest(record_path),
              "finalSkepticSha256": digest(EVIDENCE / "final-skeptic-review.json"),
              "researchSha256": digest(EVIDENCE / "research-review.json")}
    assert final_skeptic and research
    (EVIDENCE / "report-validation.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
