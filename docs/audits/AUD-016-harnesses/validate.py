#!/usr/bin/env python3
"""Validate the AUD-016 pair and retained byte bindings, without executing product checks."""

import datetime
import hashlib
import json
import re
import subprocess
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[3]
AUDITS = ROOT / "docs/audits"
EVIDENCE = AUDITS / "AUD-016-evidence"
STEM = "audit-16-2026-10-09"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def load(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    report_path = AUDITS / (STEM + ".json")
    markdown_path = AUDITS / (STEM + ".md")
    report = load(report_path)
    markdown = markdown_path.read_text()
    schema_path = ROOT.parent / "multi-chain-wallet-tools/docs/audit-report.schema.json"
    jsonschema.Draft202012Validator(load(schema_path)).validate(report)
    assert report["auditId"] == "AUD-016" and report["auditNumber"] == 16
    assert len(report["findings"]) == 8
    ids = [item["id"] for item in report["findings"]]
    assert len(ids) == len(set(ids))
    for finding in report["findings"]:
        heading = f"#### {finding['id']} — {finding['severity'].capitalize()} — {finding['title']}"
        assert heading in markdown, finding["id"]
        row = next(line for line in markdown.splitlines() if re.search(r"^\|\s*" + finding["id"] + r"\s*\|", line))
        assert finding["severity"].capitalize() in row and finding["status"] in row
        assert str(finding["releaseBlocking"]).lower() in row
    assert sum(item["severity"] == "medium" for item in report["findings"]) == 3
    assert sum(item["severity"] == "low" for item in report["findings"]) == 5
    assert sum(item["releaseBlocking"] for item in report["findings"]) == 2
    expected_ids = {f"CHECK-{cat}-{number:03d}" for cat, count in [("SEC", 7), ("FUN", 7), ("API", 4), ("BLD", 5), ("UI", 3), ("ARC", 3), ("DOC", 3)] for number in range(1, count + 1)}
    assert {item["id"] for item in report["checks"]} == expected_ids
    assert len(report["checks"]) == 32
    for item in report["checks"]:
        assert item["id"] in markdown
        assert item["primaryOwner"] and item["method"] and item["expectedEvidence"]
    for command in report["commands"]:
        assert command["classification"] != "failed-unclassified", command["label"]
        assert sha(EVIDENCE / (command["label"] + ".log")) == command["logSha256"]
        assert sha(EVIDENCE / (command["label"] + ".command.json")) == command["recordSha256"]
    for name, value in report["procedureHashes"].items():
        assert sha(ROOT.parent / name) == value
    for name, value in report["harnessBindings"].items():
        assert sha(ROOT / name) == value, name
    for name, value in report["reviewEvidenceBindings"].items():
        assert sha(EVIDENCE / name) == value, name
    for name, value in report["reusedIndependentOracles"].items():
        assert sha(ROOT / name) == value, name
    for name in ("mhfe", "mhfe_spec"):
        first = load(EVIDENCE / "snapshot.json")[name]
        label = report["snapshot"]["finalSnapshotLabel"]
        last = load(EVIDENCE / (label + ".json"))[name]
        assert first["codeFingerprint"] == last["codeFingerprint"]
        assert sha(EVIDENCE / f"snapshot-{name}-code-manifest.txt") == first["codeFingerprint"]
        assert sha(EVIDENCE / f"{label}-{name}-code-manifest.txt") == last["codeFingerprint"]
    for relative, value in report["artifacts"]["artifactHashes"].items():
        assert sha(ROOT / relative) == value, relative
    if "postReviewSourceChange" in report:
        assert sha(EVIDENCE / "post-review-mhfe-code-manifest.txt") == report["postReviewSourceChange"]["laterSourceFingerprint"]
    link_count = 0
    for target in re.findall(r"\]\(([^)]+)\)", markdown):
        target = target.strip("<>")
        if re.match(r"(?:https?:|#)", target):
            continue
        path = (AUDITS / target.split("#", 1)[0]).resolve()
        assert path.exists(), target
        link_count += 1
    public_paths = [markdown_path, report_path] + list((AUDITS / "AUD-016-harnesses").rglob("README.md"))
    for path in public_paths:
        text = path.read_text()
        assert not re.search(r"/home/[a-z_][a-z0-9_-]*/", text.replace("/home/user/", "")), path
        assert not re.search(r"[\u0400-\u04ff]", text), path
        assert not re.search(r"(?:Europe/|Asia/|UTC\+|[T ][0-9:]+\+(?!00:00)[0-9]{2}:[0-9]{2})", text), path
    ignored = subprocess.run(["git", "check-ignore", "--quiet", "docs/audits/AUD-016-evidence/validation.json"], cwd=ROOT)
    assert ignored.returncode == 0
    index = (AUDITS / "README.md").read_text()
    assert f"[AUD-016]({STEM}.md)" in index
    assert "[AUD-017](audit-17-2026-10-09.md)" in index
    result = {"auditId": "AUD-016", "checkedUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
              "schemaPassed": True, "pairPassed": True, "coverageItems": 32, "findings": 8,
              "commandRecords": len(report["commands"]), "localLinksResolved": link_count,
              "evidenceIgnored": True, "privacyPassed": True, "allRetainedBindingsPassed": True,
              "reportHashes": {markdown_path.name: sha(markdown_path), report_path.name: sha(report_path)}}
    (EVIDENCE / "validation.json").write_text(json.dumps(result, indent=2) + "\n")
    files = sorted(path for path in EVIDENCE.rglob("*") if path.is_file() and path.name != "SHA256SUMS")
    (EVIDENCE / "SHA256SUMS").write_text("".join(f"{sha(path)}  {path.relative_to(EVIDENCE)}\n" for path in files))
    print(json.dumps(result))


if __name__ == "__main__":
    main()
