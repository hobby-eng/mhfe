#!/usr/bin/env python3
"""AUD-008: bind final skeptical dispositions to source and scoped local evidence."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-008-evidence"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    snapshot = json.loads((EVIDENCE / "snapshot.json").read_text())
    mismatches = []
    for name, expected in snapshot["mhfe"]["files"].items():
        path = ROOT / name
        actual = digest(path) if path.is_file() else None
        if actual != expected:
            mismatches.append({"path": name, "expected": expected, "actual": actual})

    contributions = ["interface-review.json", "devops-review.json", "qa-review.json",
                     "wallet-independent-review.json", "documentation-review.json",
                     "secrets-review.json", "crypto-review.json", "wallet-review.json",
                     "browser-independent-review.json", "architecture-independent-review.json",
                     "skeptic-review.json"]
    file_hashes = {name: digest(EVIDENCE / name) for name in contributions}
    ledgers = ["ui-terminal-final", "qa-hidden-input-xterm", "check-release-host",
               "devops-artifacts", "wallet-challenge-run", "crypto-api-run",
               "secrets-uring-host", "skeptic-uring-host-replay", "canonical-cached",
               "canonical-uncached", "release-markers", "real-browsers"]
    ledger_results = []
    for label in ledgers:
        path = EVIDENCE / (label + ".command.json")
        if not path.is_file():
            ledger_results.append({"label": label, "present": False})
            continue
        record = json.loads(path.read_text())
        log = EVIDENCE / (label + ".log")
        actual = digest(log)
        # Independent wallet evidence retains its original uppercase spelling.
        expected = record.get("logSha256", record.get("logSHA256"))
        ledger_results.append({"label": label, "present": True,
                               "exitCode": record.get("exitCode"),
                               "logSha256": actual, "hashMatches": actual == expected})
        if actual != expected:
            mismatches.append({"path": str(log.relative_to(ROOT)),
                               "expected": expected, "actual": actual})
    print(json.dumps({
        "auditId": "AUD-008",
        "reviewedCommit": snapshot["mhfe"]["commit"],
        "sourceFingerprint": snapshot["mhfe"]["sourceFingerprint"],
        "sourceFilesChecked": len(snapshot["mhfe"]["files"]),
        "mismatches": mismatches,
        "contributionSha256": file_hashes,
        "localCommandEvidence": ledger_results,
        "assemblerSha256": digest(ROOT / "docs/audits/AUD-008-harnesses/assemble-report.py"),
        "noBuildsOrRuntimeProbes": True,
        "limits": "Missing ledger labels are recorded rather than inferred successful; final report validation is coordinator-owned.",
    }, indent=2))
    return bool(mismatches)


if __name__ == "__main__":
    raise SystemExit(main())
