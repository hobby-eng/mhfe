#!/usr/bin/env python3
"""Retain independent final-report checks without rerunning product verification."""

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

# Any home directory other than the anonymized /home/user, as validate.py reads them.
OTHER_HOME = re.compile(r"/home/(?!user[/\s`\"'<>),;:\]])[^/\s`\"'<>),;:\]]+")


ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = ROOT / "docs/audits/AUD-019-evidence"
OUTPUT = EVIDENCE / "report-browser-challenge.json"
REPORT = ROOT / "docs/audits/audit-19-2026-10-10.json"
MARKDOWN = ROOT / "docs/audits/audit-19-2026-10-10.md"
HEAD = "66f142566464255e331763966b00ea1681c2dabd"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if OUTPUT.exists():
        raise SystemExit("Preserving existing final report challenge")
    json_bytes, markdown_bytes = REPORT.read_bytes(), MARKDOWN.read_bytes()
    report, markdown = json.loads(json_bytes), markdown_bytes.decode()
    rows = {row["id"]: row for row in report["remediation"]}
    originals = set()
    for number in range(15, 19):
        path = next((ROOT / "docs/audits").glob(f"audit-{number}-*.json"))
        originals.update(item["id"] for item in json.loads(path.read_text())["findings"]
                         if item["id"].startswith(f"AUD-{number:03}-"))
    checks, errors = [], []

    def check(claim, passed, evidence, scope):
        checks.append({"claim": claim, "result": "supported" if passed else "error",
                       "evidence": evidence, "scope": scope})
        if not passed:
            errors.append({"claim": claim, "reason": "Recorded report claim does not match retained evidence."})

    check("Exact source identity and all 49 distinct original finding IDs", report["snapshot"]["commit"] == HEAD and
          len(originals) == len(report["remediation"]) == len(rows) == 49 and set(rows) == originals,
          ["snapshot.commit", "remediation", "AUD-015 through AUD-018 original findings only"],
          "Historical remediation rows inside old reports are excluded from the original finding set.")
    check("Eight synthetic retry cases are additional control-flow/cleanup evidence", "Synthetic retry probes do not establish cryptographic correctness." in markdown and
          "actual-WASM/reduced-C-engine retry checks" in markdown and
          rows["AUD-017-UI002"]["status"] == "verified",
          ["Markdown:85", "browser-rekey-retry-current.log", "browser-shared-retry-evidence.json",
           "scripts/verify-browser-package.mjs:765", "scripts/verify-browsers.mjs:1963"],
          "Actual WASM/reduced C Argon2 and four-page browser assertions support the tested retry outputs; mocks establish only their observed orchestration and owned-byte cleanup.")
    shared = json.loads((EVIDENCE / "browser-shared-retry-evidence.json").read_text())
    check("Four real-browser engine/mode pages use the reviewed source", shared["reviewedCommit"] == HEAD and
          set(shared["retryAssertionsPerPage"].values()) == {4} and
          "Chromium 156.0.8078.4 and Firefox 157.0" in markdown and
          json.loads((ROOT / "dist/modules.json").read_text())["buildId"] == "4f5000f4290fa5eb",
          ["remote-release-checks.log", "browser-shared-retry-evidence.json", "browser-loader-source-bindings.json"],
          "Remote exact-tag observations are distinguished from local bounded probes; no new browser run was performed for this challenge.")
    check("Foreign dirty host source fix is separated from acceptance and signature closure", rows["AUD-018-BLD001"]["status"] == "fixed" and
          rows["AUD-018-BLD001"]["verificationCommit"] is None and
          "Foreign host fixes are uncommitted" in rows["AUD-018-BLD001"]["limits"] and
          "no signed host closure" in markdown,
          ["AUD-018-BLD001 remediation row", "browser-inventory.json", "browser-review.json"],
          "Matching current host package/WASM and source fields do not certify a clean host commit, signed published-package admission or complete host UI acceptance.")
    supplement = json.loads((EVIDENCE / "browser-remediation-supplement.json").read_text())
    check("API001 exact unchecked trigger is verified; UI005 exact CSP trigger remains source-only", all(rows[item["id"]]["status"] == item["status"] for item in supplement["originalFindings"]) and
          rows["AUD-015-UI005"]["verificationCommit"] is None and
          "wasm-unsafe-eval" in rows["AUD-015-UI005"]["limits"],
          ["browser-remediation-supplement.json", "browser-page-protocol-final.log",
           "scripts/verify-browser-package.mjs:4213", "web/runtime.js:1022"],
          "Current adjacent damaged-vector/failure messages do not substitute for the original Chromium compile-denial punctuation reproduction.")
    subjects = report["attestation"]["subjects"]
    matching_attestations = []
    for subject in subjects:
        path = EVIDENCE / ("attestation-" + subject["name"] + ".json")
        result = json.loads(path.read_text())[0]["verificationResult"]
        certificate = result["signature"]["certificate"]
        matching_attestations.append(certificate["sourceRepositoryDigest"] == HEAD and
                                     certificate["buildSignerDigest"] == HEAD and
                                     certificate["sourceRepositoryRef"] == "refs/tags/v0.6.0" and
                                     certificate["runnerEnvironment"] == "github-hosted" and
                                     subject in result["statement"]["subject"] and
                                     any(item["type"] == "Tlog" for item in result["verifiedTimestamps"]))
    check("Cryptographic attestation verification and its trust limits are actually retained", len(subjects) == 7 and
          all(matching_attestations) and
          json.loads((EVIDENCE / "attestations-all.command.json").read_text())["exitCode"] == 0 and
          "Verifier bootstrap used official GitHub HTTPS" in markdown,
          ["attestations-all.command.json", "attestations-all.log", "seven attestation verificationResult records",
           "tag-signature.log", "signature-history.log"],
          "Reviewed retained verifier output/constraints, without rerunning cryptographic verification. Sigstore/GitHub provenance and Git SSH signatures are distinguished from owner OpenPGP release signing.")
    candidate = ROOT / "canonical-output-signing-v0.6.0"
    check("Missing owner OpenPGP assets, inaccessible current draft and final publication checks remain caveats", report["assessment"]["publicationVerification"] == "INCOMPLETE" and
          not (candidate / "SHA256SUMS.asc").exists() and
          not (candidate / "RELEASE-SIGNING-KEY.asc").exists() and
          "Owner signing, verification against the intended OpenPGP key" in markdown and
          "current private draft Release API returned inaccessible/404" in markdown,
          ["assessment.publicationVerification", "Markdown:292-305", "retained candidate file inventory"],
          "The pair does not claim final published release verification or that inaccessible API evidence proves an absent draft.")
    check("Corrected companion-specification finding separates short verifier from wallet check", "128 bits" in report["findings"][0]["releaseBlockingReason"] and
          "16 bits" in report["findings"][0]["releaseBlockingReason"] and
          "MHFE's own current README documents the intended precedence." in report["findings"][0]["observed"],
          ["AUD-019-DOC001", "core-review.json", "scripts/verify-browsers.mjs:1441"],
          "Current pair incorporates the core correction; the reproduced 12-word short-source verifier is distinct from the 24-word source walletCheck.")
    check("Both files keep publication/scope boundaries and report privacy", not OTHER_HOME.search(markdown) and
          not OTHER_HOME.search(json_bytes.decode()) and
          report["assessment"]["fullScopeExecution"] == "INCOMPLETE" and
          "PASS WITH CAVEATS" in markdown,
          ["Markdown/JSON assessment and limits"],
          "No whole-machine absence promise or certification of all foreign/platform behavior is made.")
    result = {
        "auditId": "AUD-019", "reviewedUtc": datetime.now(timezone.utc).isoformat(),
        "reviewer": {"task": "browser independent final report challenge", "model": None, "actualReasoningEffort": None},
        "reviewedPair": [
            {"path": str(REPORT.relative_to(ROOT)), "sha256": hashlib.sha256(json_bytes).hexdigest()},
            {"path": str(MARKDOWN.relative_to(ROOT)), "sha256": hashlib.sha256(markdown_bytes).hexdigest()},
        ],
        "method": "Source/evidence/report reads only; no production edits, builds, browsers, KDFs or signature-verification reruns.",
        "concreteErrors": errors, "checks": checks,
        "adjudication": "PASS within the reviewed statement scope, with the stated publication and foreign-host limitations retained." if not errors else "Report correction required before accepting the challenged claims.",
        "evidenceBindings": [
            {"path": str(path.relative_to(ROOT)), "sha256": digest(path)} for path in [
                EVIDENCE / "browser-review.json", EVIDENCE / "browser-malicious-review.json",
                EVIDENCE / "browser-shared-retry-evidence.json", EVIDENCE / "browser-remediation-supplement.json",
                EVIDENCE / "attestations-all.command.json", EVIDENCE / "tag-signature.log",
                EVIDENCE / "signature-history.log", EVIDENCE / "remote-release-checks.log",
            ]
        ],
        "pairStableDuringReview": REPORT.read_bytes() == json_bytes and MARKDOWN.read_bytes() == markdown_bytes,
    }
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"path": str(OUTPUT.relative_to(ROOT)), "sha256": digest(OUTPUT),
                      "concreteErrors": len(errors), "checks": len(checks),
                      "pairStableDuringReview": result["pairStableDuringReview"]}))
    return 0 if not errors and result["pairStableDuringReview"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
