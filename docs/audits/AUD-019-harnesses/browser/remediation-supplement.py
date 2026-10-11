#!/usr/bin/env python3
"""Record two original browser remediation checks without rerunning builds or KDFs."""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
EVIDENCE = ROOT / "docs/audits/AUD-019-evidence"
OUTPUT = EVIDENCE / "browser-remediation-supplement.json"


def digest(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def main():
    if OUTPUT.exists():
        raise SystemExit("Preserving existing remediation supplement")
    remote = (EVIDENCE / "remote-release-checks.log").read_text()
    assertions = {
        description: [line for line in remote.splitlines() if description in line]
        for description in [
            "with a passphrase, walletCheck must be chosen -> TypeError",
            "no workers are refused -> TypeError",
            "the repair module stays closed -> SELF_CHECK_FAILED",
        ]
    }
    supplement = {
        "auditId": "AUD-019",
        "reviewedCommit": "66f142566464255e331763966b00ea1681c2dabd",
        "reviewedUtc": datetime.now(timezone.utc).isoformat(),
        "reviewer": {"task": "browser", "model": None, "actualReasoningEffort": None},
        "method": "Read current production source and retained current package/protocol/real-browser assertions; no build, browser, KDF or vector execution added.",
        "originalFindings": [
            {
                "id": "AUD-015-API001", "status": "verified",
                "remediationIntroducingCommit": "3a705db6945b35f8c248c44893e71ddc36902af4",
                "expected": "An unchecked draw rejects wrongly typed walletCheck and invalid workers with TypeError before a worker or passphrase copy.",
                "source": ["web/wallet.js:178", "web/wallet.js:183", "web/wallet.js:186", "web/wallet.js:329"],
                "exactTriggerEvidence": "Retained browser-page-protocol-final.log explicitly passes unchecked string/number walletCheck and zero/text/1e9 workers with TypeError. Current scripts/verify-browser-package.mjs:4213-4232 asserts these unchecked options and workers:-1 with walletCheck:false; a refused draw starts no worker. Coordinator release-check exits0 with All checks passed.",
                "realBrowserEvidence": "Four retained pages pass required walletCheck selection and workers:0 refusal with a passphrase; these support runtime validation but are not the exact unchecked-options reproduction.",
                "limits": "Exact unchecked trigger is verified through production JS class methods with a synthetic worker/compiled minimal module and package assertions, not repeated as an unchecked draw in a real browser.",
            },
            {
                "id": "AUD-015-UI005", "status": "fixed",
                "remediationIntroducingCommit": "3a705db6945b35f8c248c44893e71ddc36902af4",
                "expected": "Chromium's denied WebAssembly compile detail ending with a period produces one period before the self-test failure advice.",
                "source": ["web/runtime.js:1019", "web/runtime.js:1022", "web/runtime.js:1026"],
                "observed": "The production formatter removes every trailing period from the failed detail before adding its single period and advice. Generated runtime bytes match this source after stamping.",
                "retainedAdjacentEvidence": "scripts/verify-browser-package.mjs:4538 compares the exact SELF_CHECK_FAILED message for a damaged repair vector; :4761-4774 checks missing WebAssembly/failed compilation, but does not assert the denied-compile trailing-period message. scripts/verify-browsers.mjs:3283-3292 and four retained browser pages compare the exact damaged-repair message without a double period; that detail itself has no terminal period.",
                "verificationGap": "No retained current Chromium page omitting wasm-unsafe-eval documents the exact original trailing-period trigger. The current fix is source-verified; the finding's required csp-page.mjs Chromium reproduction was not rerun in AUD-019 and is not claimed verified.",
            },
        ],
        "bindings": [
            {"path": path, "sha256": digest(path)} for path in [
                "docs/audits/audit-15-2026-10-09.json", "web/wallet.js", "web/runtime.js",
                "scripts/verify-browser-package.mjs", "scripts/verify-browsers.mjs",
                "docs/audits/AUD-019-evidence/browser-page-protocol-final.log",
                "docs/audits/AUD-019-evidence/browser-page-protocol-final.command.json",
                "docs/audits/AUD-019-evidence/browser-loader-source-bindings.json",
                "docs/audits/AUD-019-evidence/release-check.log",
                "docs/audits/AUD-019-evidence/release-check.command.json",
                "docs/audits/AUD-019-evidence/remote-release-checks.log",
            ]
        ],
        "relatedRealBrowserAssertionCounts": {key: len(value) for key, value in assertions.items()},
        "relatedRealBrowserUtcEvidenceLines": assertions,
        "newFindingIds": [],
    }
    OUTPUT.write_text(json.dumps(supplement, indent=2) + "\n")
    print(json.dumps({"path": str(OUTPUT.relative_to(ROOT)),
                      "sha256": digest(OUTPUT.relative_to(ROOT)),
                      "statuses": {item["id"]: item["status"] for item in supplement["originalFindings"]}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
