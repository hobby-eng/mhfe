#!/usr/bin/env python3
"""Challenge the remediation validator using in-memory record edits only."""

import copy
import importlib.util
import json
from pathlib import Path

SCRIPT = Path(__file__).with_name("remediation-validate.py")
spec = importlib.util.spec_from_file_location("aud008_remediation", SCRIPT)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


def main():
    record = validator.read(validator.AUDITS / (validator.STEM + ".json"))
    markdown = (validator.AUDITS / (validator.STEM + ".md")).read_text()
    validator.validate(record, markdown)
    cases = []

    def reject(label, mutation=None, changed_markdown=None):
        candidate = copy.deepcopy(record)
        if mutation is not None:
            mutation(candidate)
        try:
            text = markdown if changed_markdown is None else changed_markdown
            validator.validate(candidate, text)
        except (ValueError, KeyError):
            cases.append(label)
        else:
            raise ValueError("Validator accepted invalid record: " + label)

    reject("changed original finding", lambda r: r["findings"][0].update(observed="changed"))
    reject(
        "wrong original report hash",
        lambda r: r["remediationVerification"]["originalReportHashes"].update(json="0" * 64),
    )
    reject("changed original snapshot", lambda r: r["snapshot"].update(commit="0" * 40))
    reject(
        "wrong remediation source fingerprint",
        lambda r: r["remediationVerification"]["snapshot"].update(sourceFingerprint="0" * 64),
    )
    reject(
        "wrong scoped command hash",
        lambda r: r["remediationVerification"]["commands"][0].update(logSha256="0" * 64),
    )
    reject(
        "wrong verified count",
        lambda r: r["remediationVerification"]["statusCounts"].update(verified=0),
    )
    reject("unbound remediation", lambda r: r["remediation"][0].update(sourceFingerprint="0" * 64))
    reject(
        "missing scoped finding checks",
        lambda r: r["remediation"][0].update(verificationCommands=[]),
    )
    reject("deleted finding", lambda r: r["findings"].pop())
    reject(
        "Markdown status disagreement",
        changed_markdown=markdown.replace("**Status:** verified", "**Status:** open", 1),
    )
    reject("release approval inferred", lambda r: r["assessment"].update(releaseReady=True))
    duplicate = '{"auditId":"AUD-008","auditId":"AUD-008"}'
    try:
        json.loads(duplicate, object_pairs_hook=validator.unique_pairs)
    except ValueError:
        cases.append("duplicate JSON keys")
    else:
        raise ValueError("Duplicate JSON keys were accepted")
    print(json.dumps({
        "auditId": "AUD-008",
        "passed": True,
        "rejectedCases": cases,
        "sourceOrEvidenceMutated": False,
    }))


if __name__ == "__main__":
    main()
