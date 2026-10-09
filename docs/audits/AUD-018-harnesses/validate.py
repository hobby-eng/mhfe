#!/usr/bin/env python3
"""Validate the AUD-018 pair, coverage and exact retained bindings without product execution."""

import datetime
import hashlib
import json
import re
import subprocess
from pathlib import Path

import jsonschema


class ReportValidation:
    def __init__(self):
        self._root = Path(__file__).resolve().parents[3]
        self._audits = self._root / "docs/audits"
        self._evidence = self._audits / "AUD-018-evidence"
        self._stem = "audit-18-2026-10-09"

    @staticmethod
    def _unique(pairs):
        result = {}
        for key, value in pairs:
            assert key not in result, ("Duplicate JSON key", key)
            result[key] = value
        return result

    def _load(self, path):
        return json.loads(path.read_text(), object_pairs_hook=self._unique)

    @staticmethod
    def _sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _live_code_manifest(self, root):
        names = subprocess.check_output(["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=root).decode().split("\0")
        return "".join(f"{self._sha(root / name)}  {name}\n" for name in sorted(set(names))
                       if name and not name.startswith("docs/audits/") and (root / name).is_file())

    def run(self):
        json_path = self._audits / (self._stem + ".json")
        md_path = self._audits / (self._stem + ".md")
        report = self._load(json_path)
        markdown = md_path.read_text()
        schema_path = self._root.parent / "multi-chain-wallet-tools/docs/audit-report.schema.json"
        jsonschema.Draft202012Validator(self._load(schema_path)).validate(report)
        assert report["auditId"] == "AUD-018" and report["auditNumber"] == 18
        assert report["releaseAssessment"]["verdict"] == "FAIL"
        ids = [item["id"] for item in report["findings"]]
        assert len(ids) == len(set(ids))
        assert {"AUD-018-BLD001", "AUD-015-DOC001", "AUD-016-UI001"}.issubset(ids)
        assert sum(item.get("newInThisAudit", False) for item in report["findings"]) == 1
        for item in report["findings"]:
            assert f"#### {item['id']} — {item['severity'].capitalize()} — {item['title']}" in markdown
            row = next(line for line in markdown.splitlines()
                       if re.search(r"^\|\s*" + re.escape(item["id"]) + r"\s*\|", line))
            assert item["severity"].capitalize() in row and item["status"] in row
            assert re.search(r"\|\s*" + str(item["releaseBlocking"]).lower() + r"\s*\|", row)
        expected_checks = {f"CHECK-{category}-{number:03d}"
                           for category, count in [("SEC", 7), ("FUN", 7), ("API", 4), ("BLD", 5), ("UI", 3), ("ARC", 3), ("DOC", 3)]
                           for number in range(1, count + 1)}
        assert len(report["checks"]) == 32 and {item["id"] for item in report["checks"]} == expected_checks
        for item in report["checks"]:
            assert item["id"] in markdown and item["primaryOwner"] and item["expectedEvidence"]
            assert item["sourceFingerprint"] == report["snapshot"]["nonAuditSourceFingerprint"]
            assert item["outcome"] in {"passed", "failed", "not-applicable", "not-run", "blocked", "skipped"}
        remediation_ids = [row["id"] for row in report["remediation"]]
        assert len(remediation_ids) == len(set(remediation_ids))
        for row in report["remediation"]:
            assert row["status"] == "open" and row["fixCommit"] is None and row["verificationCommit"] is None
            assert row["currentTriggerStatus"] and row["evidence"]
        command_labels = [item["label"] for item in report["commands"]]
        assert len(command_labels) == len(set(command_labels))
        for item in report["commands"]:
            assert item["classification"] != "failed-unclassified"
            assert self._sha(self._evidence / (item["label"] + ".log")) == item["logSha256"], item["label"]
            assert self._sha(self._evidence / (item["label"] + ".command.json")) == item["recordSha256"], item["label"]
        for key, base in [("procedureHashes", self._root.parent), ("harnessBindings", self._root),
                          ("reusedHarnessBindings", self._root), ("reviewEvidenceBindings", self._evidence)]:
            for name, digest in report[key].items():
                assert self._sha(base / name) == digest, (key, name)
        for name in ["mhfe", "mhfe_spec"]:
            first = self._load(self._evidence / "snapshot.json")[name]
            last_label = report["snapshot"]["finalSnapshotLabel"]
            last = self._load(self._evidence / (last_label + ".json"))[name]
            assert first["codeFingerprint"] == last["codeFingerprint"]
            for label, snapshot in [("snapshot", first), (last_label, last)]:
                manifest = self._evidence / f"{label}-{name}-code-manifest.txt"
                assert self._sha(manifest) == snapshot["codeFingerprint"]
            root = self._root if name == "mhfe" else self._root.parent / name
            live = self._live_code_manifest(root)
            assert hashlib.sha256(live.encode()).hexdigest() == first["codeFingerprint"], ("Source changed", name)
        for relative, digest in report["artifacts"]["artifactHashes"].items():
            assert self._sha(self._root / relative) == digest, relative
        canonical = report["artifacts"]["canonical"]
        assert len(canonical["archives"]) == 4
        assert canonical["comparisons"]["wasm"]["equal"] and canonical["comparisons"]["browserManifest"]["equal"]
        assert not canonical["comparisons"]["native"]["equal"]
        for item in canonical["archives"]:
            assert self._sha(self._root / "canonical-output-aud018/release" / item["name"]) == item["sha256"]
        comparison = report["artifacts"]["cachedUncachedComparison"]
        if report["releaseAssessment"]["documentedLocalReproducibilityComparisonPassed"]:
            assert comparison["passed"] and comparison["checksumFilesEqual"]
            assert len(comparison["archives"]) == 4
            for row in comparison["archives"]:
                assert row["equal"] and row["cached"] == row["uncached"]
                assert self._sha(self._root / "canonical-output-aud018_uncached/release" / row["name"]) == row["uncached"]["sha256"]
        links = 0
        for target in re.findall(r"\]\(([^)]+)\)", markdown):
            target = target.strip("<>")
            if re.match(r"(?:https?:|#)", target):
                continue
            path = (self._audits / target.split("#", 1)[0]).resolve()
            assert path.exists(), target
            links += 1
        published = [md_path, json_path] + list((self._audits / "AUD-018-harnesses").rglob("README.md"))
        for path in published:
            source = path.read_text()
            assert not re.search(r"/home/(?!user(?:/|\b))[^/\s]+", source), path
            assert not re.search(r"[\u0400-\u04ff]", source), path
            assert not re.search(r"(?:Europe/|Asia/|UTC\+|[T ][0-9:]+\+(?!00:00)[0-9]{2}:[0-9]{2})", source), path
            assert not re.search(r"^[-*] .+\n\n[-*] ", source, re.M), ("Loose list", path)
        index = (self._audits / "README.md").read_text()
        for number in [16, 17, 18]:
            assert f"[AUD-{number:03d}](audit-{number:02d}-2026-10-09.md)" in index
        ignored = subprocess.run(["git", "check-ignore", "--quiet", "docs/audits/AUD-018-evidence/report-validation.json"], cwd=self._root)
        assert ignored.returncode == 0
        staged = subprocess.check_output(["git", "diff", "--cached", "--name-only"], cwd=self._root).decode().splitlines()
        assert not any("-evidence/" in name for name in staged)
        result = {"auditId": "AUD-018", "checkedUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                  "schemaPassed": True, "pairPassed": True, "coverageItems": 32, "findings": len(ids),
                  "newFindings": 1, "commandRecords": len(command_labels), "localLinksResolved": links,
                  "privacyPassed": True, "evidenceIgnored": True, "evidenceNotStaged": True,
                  "currentNonAuditSourceMatches": True, "allRetainedBindingsPassed": True,
                  "reportHashes": {md_path.name: self._sha(md_path), json_path.name: self._sha(json_path)}}
        (self._evidence / "report-validation.json").write_text(json.dumps(result, indent=2) + "\n")
        files = sorted(p for p in self._evidence.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
        (self._evidence / "SHA256SUMS").write_text("".join(f"{self._sha(p)}  {p.relative_to(self._evidence)}\n" for p in files))
        print(json.dumps(result))


if __name__ == "__main__":
    ReportValidation().run()
