#!/usr/bin/env python3
"""Bind the scoped AUD-008 research ranking to source and shared evidence bytes."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-008-evidence"


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"Duplicate JSON key: {key}")
        value[key] = item
    return value


def main():
    review = json.loads(
        (EVIDENCE / "research-review.json").read_text(),
        object_pairs_hook=unique_object,
    )
    snapshot = json.loads((EVIDENCE / "snapshot.json").read_text())
    opportunities = review["optionalImprovements"]
    errors = []
    excerpts = []
    if not 1 <= len(opportunities) <= 8:
        errors.append("Expected one to eight ranked opportunities.")
    if [item["rank"] for item in opportunities] != list(range(1, len(opportunities) + 1)):
        errors.append("Opportunity ranks must be unique and consecutive.")
    if review["findings"] or review["remediation"]:
        errors.append("This scoped optional-improvement record must not allocate findings or fixes.")
    if review["reviewer"]["model"] is not None or review["reviewer"]["reasoningEffort"] is not None:
        errors.append("Unavailable exact model/effort metadata must remain null.")
    for relative, expected in review["snapshot"]["sourceSHA256"].items():
        actual = sha256(ROOT / relative)
        if actual != expected or actual != snapshot["mhfe"]["files"].get(relative):
            errors.append(f"Cited source differs from recorded baseline: {relative}")
    for relative, expected in review["procedureHashes"].items():
        if sha256(ROOT.parent / "multi-chain-wallet-tools" / relative) != expected:
            errors.append(f"Procedure bytes changed: {relative}")
    for name, entry in review["sharedEvidence"].items():
        if sha256(EVIDENCE / name) != entry["sha256"]:
            errors.append(f"Shared evidence bytes changed: {name}")
    for item in opportunities:
        if item["releaseBlocking"] or item["implementationState"] != "not-implemented":
            errors.append(f"Optional opportunity has an unsupported disposition: {item['key']}")
        for location in item["sourceLocations"]:
            lines = (ROOT / location["path"]).read_text().splitlines()
            start, end = location["lineStart"], location["lineEnd"]
            if not 1 <= start <= end <= len(lines):
                errors.append(f"Invalid source line range: {location}")
                continue
            excerpts.append(
                {
                    "opportunity": item["key"],
                    **location,
                    "text": "\n".join(lines[start - 1 : end]),
                }
            )
    result = {
        "auditId": "AUD-008",
        "method": "Static citation, snapshot and ranking-record validation; no product execution.",
        "reviewedCommit": review["snapshot"]["commit"],
        "opportunityCount": len(opportunities),
        "citationCount": len(excerpts),
        "sourceFileCount": len(review["snapshot"]["sourceSHA256"]),
        "sharedEvidenceCount": len(review["sharedEvidence"]),
        "errors": errors,
        "sourceExcerpts": excerpts,
    }
    (EVIDENCE / "research-static.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "sourceExcerpts"}))
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
