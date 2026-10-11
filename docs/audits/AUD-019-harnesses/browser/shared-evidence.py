#!/usr/bin/env python3
"""Reconcile coordinator-owned real-WASM and browser evidence without running it again."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = ROOT / "docs/audits/AUD-019-evidence"
OUTPUT = EVIDENCE / "browser-shared-retry-evidence.json"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if OUTPUT.exists():
        raise SystemExit("Preserving existing shared retry evidence")
    release = EVIDENCE / "release-check.log"
    remote = EVIDENCE / "remote-release-checks.log"
    remote_text = remote.read_text()
    reviewed = "66f142566464255e331763966b00ea1681c2dabd"
    if reviewed not in remote_text or "All checks passed." not in release.read_text():
        raise SystemExit("The shared evidence does not establish this source/check result")
    descriptions = [
        "after AMBIGUOUS_LENGTH the owner confirms the 12-word reading on the same recovery",
        "after LENGTH_DIFFERS the fingerprint confirms on the same recovery",
        "the page was given both lengths, and the owner was shown the reading of the one stated",
    ]
    lines = [line for line in remote_text.splitlines()
             if any(description in line for description in descriptions)]
    counts = {description: sum(description in line for line in lines)
              for description in descriptions}
    matrix_passed = "The browser package passes its checks in Chromium and Firefox, in both modes." in remote_text
    if not matrix_passed or any(value != 4 for value in counts.values()):
        raise SystemExit("Required real-browser retry evidence was not found on all four pages")
    report = EVIDENCE / "browser-review.json"
    review = json.loads(report.read_text())
    previous_hash = digest(report)
    result = {
        "capturedUtc": datetime.now(timezone.utc).isoformat(),
        "reviewedCommit": reviewed,
        "method": "Read coordinator-owned local/remote logs and matching test source; no target code rerun.",
        "source": [
            {"path": "scripts/verify-browser-package.mjs", "sha256": digest(ROOT / "scripts/verify-browser-package.mjs"), "line": 765,
             "meaning": "Real RekeySession/WASM with reduced actual C Argon2 engine; retry comparison produces no new recovery round, explicit owner reading and invalid order/refusal paths tested."},
            {"path": "scripts/verify-browsers.mjs", "sha256": digest(ROOT / "scripts/verify-browsers.mjs"), "line": 1963,
             "meaning": "Actual package onConfirmAgain owner/reference retry, compared against encryption result; test-only Argon2 cost reduction, not a full-cost production vector replay."},
        ],
        "logs": [
            {"path": str(release.relative_to(ROOT)), "sha256": digest(release),
             "commandRecordSha256": digest(EVIDENCE / "release-check.command.json"), "result": "exit0; All checks passed."},
            {"path": str(remote.relative_to(ROOT)), "sha256": digest(remote),
             "originalFetchRecordSha256": digest(EVIDENCE / "remote-release-checks.json"), "jobId": 114228126731,
             "result": "Tag v0.6.0 check at reviewed commit; Chromium and Firefox, each fast and standard, pass."},
        ],
        "retryAssertionsPerPage": counts, "exactUtcEvidenceLines": lines,
        "priorBrowserReviewSha256": previous_hash,
        "scopeLimit": "This closes the actual MHFE WASM/browser retry coverage gap; it does not run the foreign dirty host acceptance or signed-package admission.",
    }
    OUTPUT.write_text(json.dumps(result, indent=2) + "\n")
    review["coordinatorEvidence"] = {
        "path": str(OUTPUT.relative_to(ROOT)), "sha256": digest(OUTPUT),
        "actualWasmRetry": "passed shared local check", "actualBrowserRetry": "passed shared remote four-page matrix",
        "reviewRefinement": "The 8 synthetic cases are additional seam/cleanup evidence, rather than the only retry verification. Actual MHFE WASM retry has no remaining coverage gap.",
    }
    for finding in review["originalFindings"]:
        if finding["originalFindingId"] == "AUD-017-UI002":
            finding["runtimeTriggerStatus"] = "not reproduced; verified by shared actual-WASM and four-page real-browser retry tests plus independent synthetic cleanup probes"
    for check in review["checks"]:
        if check["checkId"] == "CHECK-UI-001":
            check["status"] = "passed source, shared MHFE real-browser matrix and targeted cleanup probes; foreign host acceptance gap remains"
    review["artifacts"].append({"path": str(OUTPUT.relative_to(ROOT)), "sha256": digest(OUTPUT)})
    report.write_text(json.dumps(review, indent=2) + "\n")
    print(json.dumps({"sharedEvidenceSha256": digest(OUTPUT), "browserReviewSha256": digest(report), "matrixPages": 4, "targetReruns": 0}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
