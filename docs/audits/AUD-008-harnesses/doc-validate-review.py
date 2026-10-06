#!/usr/bin/env python3
"""Validate this review's local evidence links, JSON keys and source binding."""

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-008-evidence"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key: " + key)
        result[key] = value
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    path = EVIDENCE / "documentation-review.json"
    report = json.loads(path.read_text(), object_pairs_hook=unique_object)
    assert report["auditId"] == "AUD-008"
    assert len(report["confirmedFindings"]) == 3
    for name, expected in report["snapshot"]["scopeHashes"].items():
        assert digest(ROOT / name) == expected, name
    assert digest(ROOT.parent / "mhfe_spec/README.md") == report["snapshot"]["specSha256"]
    for finding in report["confirmedFindings"]:
        assert finding["status"] == "open" and finding["severity"] == "low"
        assert finding["releaseBlocking"] is False
        for link in finding["evidence"]:
            assert link.startswith("Local only: "), link
            assert (ROOT / link.removeprefix("Local only: ")).is_file(), link
    summary = {
        "validJson": True,
        "duplicateKeys": False,
        "confirmedLowFindings": len(report["confirmedFindings"]),
        "sourceBindingsMatched": len(report["snapshot"]["scopeHashes"]) + 1,
        "reportSha256": digest(path),
        "finalAuditSchemaValidation": "Coordinator owns the final audit pair; this is scoped reviewer evidence.",
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
