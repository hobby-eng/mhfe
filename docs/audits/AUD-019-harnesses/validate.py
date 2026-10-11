#!/usr/bin/env python3
"""Validate published AUD-019 records and their local source/evidence bindings."""

import ast
import datetime
import hashlib
import json
import re
import subprocess
from pathlib import Path

import jsonschema


class AuditValidation:
    def __init__(self):
        self.root = Path(__file__).resolve().parents[3]
        self.audits = self.root / "docs/audits"
        self.evidence = self.audits / "AUD-019-evidence"
        self.checked = 0

    @staticmethod
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key: " + key)
            result[key] = value
        return result

    def load(self, path):
        return json.loads(path.read_text(), object_pairs_hook=self.unique_pairs)

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def run(self):
        stem = "audit-19-2026-10-10"
        report = self.load(self.audits / (stem + ".json"))
        markdown = (self.audits / (stem + ".md")).read_text()
        procedure_root = self.root.parent / "multi-chain-wallet-tools"
        schema = self.load(procedure_root / "docs/audit-report.schema.json")
        jsonschema.Draft202012Validator(schema).validate(report)
        if report["auditId"] != "AUD-019" or report["auditNumber"] != 19:
            raise ValueError("Audit identity differs")
        guide = (procedure_root / "docs/FULL_AUDIT_GUIDE.md").read_text()
        expected = set(re.findall(r"^### (CHECK-[A-Z]+-\d{3}) —", guide, re.M))
        observed = [row["id"] for row in report["checks"]]
        if len(observed) != 32 or len(set(observed)) != 32 or set(observed) != expected:
            raise ValueError("Coverage ledger differs from the 32-item procedure")
        originals = set()
        for number in [15, 16, 17, 18]:
            previous = self.load(self.audits / f"audit-{number}-2026-10-09.json")
            originals.update(row["id"] for row in previous["findings"])
        rows = [row["id"] for row in report["remediation"]]
        if set(rows) != originals or len(rows) != len(originals):
            raise ValueError("Original remediation identities were lost or duplicated")
        for row in report["findings"] + report["remediation"]:
            if row["id"] not in markdown or row["status"] not in markdown:
                raise ValueError("Markdown and JSON register differ")
        for text in [markdown, json.dumps(report), *(path.read_text() for path in (self.audits / "AUD-019-harnesses").rglob("README.md"))]:
            paths = re.findall(r"/home/([^/\s`\"'<>),;:\]]+)", text)
            if any(name != "user" for name in paths):
                raise ValueError("Published home-directory identity was not anonymized")
            if re.search(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?[+-](?!00:00)\d\d:\d\d", text):
                raise ValueError("Published timestamp is not UTC")
        for path, expected_hash in report["procedureHashes"].items():
            if self.sha(procedure_root / path) != expected_hash:
                raise ValueError("Procedure hash changed: " + path)
            self.checked += 1
        for entry in report["evidenceBindings"]:
            if self.sha(self.audits / entry["path"]) != entry["sha256"]:
                raise ValueError("Evidence/harness binding differs: " + entry["path"])
            self.checked += 1
        for command in report["commands"]:
            if self.sha(self.evidence / (command["label"] + ".log")) != command["logSha256"]:
                raise ValueError("Command/log binding differs: " + command["label"])
            self.checked += 1
        # The code-only manifest excludes every audit document, including the index.
        manifest = self.evidence / "initial-mhfe-code-manifest.txt"
        for line in manifest.read_text().splitlines():
            digest, name = line.split("  ", 1)
            if self.sha(self.root / name) != digest:
                raise ValueError("Reviewed product file changed: " + name)
            self.checked += 1
        full_initial = dict(line.split("  ", 1)[::-1] for line in (self.evidence / "initial-mhfe-manifest.txt").read_text().splitlines())
        full_final = dict(line.split("  ", 1)[::-1] for line in (self.evidence / "final-formatted-mhfe-manifest.txt").read_text().splitlines())
        changed = {name for name in full_initial.keys() | full_final.keys() if full_initial.get(name) != full_final.get(name)}
        if changed != {"docs/audits/README.md"}:
            raise ValueError("Unexpected source snapshot delta: " + repr(changed))
        for name, digest in full_final.items():
            if self.sha(self.root / name) != digest:
                raise ValueError("A snapshotted file changed after closeout: " + name)
        for entry in report["artifacts"]["archives"]:
            if self.sha(self.root / "canonical-output-signing-v0.6.0" / entry["file"]) != entry["sha256"]:
                raise ValueError("Candidate changed: " + entry["file"])
        candidate = self.root / "canonical-output-signing-v0.6.0"
        if self.sha(candidate / "SHA256SUMS") != report["artifacts"]["checksumFileSha256"]:
            raise ValueError("Candidate checksum file changed")
        if (candidate / "SHA256SUMS.asc").exists() != report["artifacts"]["signaturePresent"]:
            raise ValueError("Owner signature presence changed; update publication assessment")
        if report["canonicalComparison"]["archiveCount"] != 4 or not report["canonicalComparison"]["checksumFileByteMatch"]:
            raise ValueError("Canonical reproduction is incomplete")
        for entry in report["canonicalComparison"]["files"]:
            for directory in ["canonical-output-aud019_uncached", "canonical-output-v0.6.0"]:
                if self.sha(self.root / directory / "release" / entry["file"]) != entry["sha256"]:
                    raise ValueError("Retained canonical file changed: " + entry["file"])
        commit = report["snapshot"]["commit"]
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.root, text=True).strip()
        tag = subprocess.check_output(["git", "rev-parse", "v0.6.0"], cwd=self.root, text=True).strip()
        if head != commit or tag != report["snapshot"]["tag"]["object"]:
            raise ValueError("Current local release identity changed")
        if report["resumeInspection"]["remoteTagObject"] != tag:
            raise ValueError("Remote tag identity changed during the pause")
        for name in ["SHA256SUMS"] + [row["file"] for row in report["artifacts"]["archives"]]:
            result = self.load(self.evidence / ("attestation-" + name + ".json"))[0]["verificationResult"]
            cert = result["signature"]["certificate"]
            if any(cert[key] != commit for key in ["sourceRepositoryDigest", "buildSignerDigest", "githubWorkflowSHA"]):
                raise ValueError("Attestation source/signer identity differs")
            if cert["sourceRepositoryRef"] != "refs/tags/v0.6.0" or cert["runnerEnvironment"] != "github-hosted":
                raise ValueError("Attestation tag/runner differs")
            if cert["sourceRepositoryURI"] != "https://github.com/hobby-eng/mhfe" or cert["buildSignerURI"] != "https://github.com/hobby-eng/mhfe/.github/workflows/release.yml@refs/tags/v0.6.0":
                raise ValueError("Attestation repository/workflow differs")
            expected_digest = self.sha(self.root / "canonical-output-signing-v0.6.0" / name)
            subjects = result["statement"]["subject"]
            if not any(row["name"] == name and row["digest"]["sha256"] == expected_digest for row in subjects):
                raise ValueError("Attestation subject differs: " + name)
        for link in re.findall(r"\]\(([^)]+)\)", markdown):
            if not link.startswith(("https://", "http://", "#")) and not (self.audits / link.split("#")[0]).exists():
                raise ValueError("Local report link does not resolve: " + link)
        for path in (self.audits / "AUD-019-harnesses").rglob("*.py"):
            ast.parse(path.read_text())
        difference = subprocess.check_output(["git", "diff", "--name-only", "HEAD"], cwd=self.root, text=True).splitlines()
        if difference != ["docs/audits/README.md"]:
            raise ValueError("A tracked product file changed")
        if subprocess.run(["git", "check-ignore", "-q", str(self.evidence)], cwd=self.root).returncode:
            raise ValueError("Evidence is not ignored")
        result = {"auditId": "AUD-019", "validatedUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  "schema": "passed", "uniqueKeys": "passed", "coverageItems": 32,
                  "originalRemediationIds": len(rows), "hashBindingsChecked": self.checked,
                  "privacy": "passed", "pairLinks": "passed", "sourceDelta": sorted(changed),
                  "canonicalArchives": 4, "cryptographicallyVerifiedSubjects": 7,
                  "harnessSyntax": "passed", "limits": "Evidence consistency validation; no product suite replay."}
        (self.evidence / "report-validation.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    AuditValidation().run()
