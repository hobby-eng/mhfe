#!/usr/bin/env python3
"""Writes the AUD-023 report pair, docs/audits/AUD-023-<date>.md and .json, from the audit's
retained material in docs/audits/AUD-023-evidence/ (local, git-ignored):

- workflow-result.json: the reviewers' coverage, the critic's gaps, the confirmed and the refuted
  candidates of workflow run wf_39c5d87d-79b;
- normalized-records.json: one record per confirmed finding, in the audit standard's fields;
- curated-observations.json: the confirmed informational observations;
- baseline-*.command.json, procedure-hashes.txt, environment.txt, product-fingerprint.txt,
  initial-manifest.txt, initial-product-manifest.txt and head.txt from the snapshot;
- canonical-output-aud023/release/SHA256SUMS from the uncached canonical build.

Home-directory paths are written as /home/user/...; every time is UTC.

Usage: python3 docs/audits/AUD-023-harnesses/assemble.py <completion date YYYY-MM-DD>
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
AUDITS = ROOT / "docs" / "audits"
EVIDENCE = AUDITS / "AUD-023-evidence"
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
CATEGORY_ORDER = ["SEC", "FUN", "API", "BLD", "UI", "ARC", "DOC"]

# The CHECK items each reviewer owned (the workflow's scopes) and their logical groups, after
# multi-chain-wallet-tools/docs/FULL_AUDIT_GUIDE.md.
CHECKS = [
    ("CHECK-SEC-001", "secrets-native", "Threat model and secret ownership"),
    ("CHECK-SEC-002", "secrets-native", "Sandbox, CSP and transport"),
    ("CHECK-SEC-003", "secrets-native", "Network egress and secret guards"),
    ("CHECK-SEC-004", "core-crypto", "Randomness, encryption and authentication"),
    ("CHECK-SEC-005", "secrets-native", "Secret lifecycle and exceptional paths"),
    ("CHECK-SEC-006", "browser-wasm", "Browser injection, persistence and sensitive APIs"),
    ("CHECK-SEC-007", "secrets-native", "Read-only guarantees and availability bounds"),
    ("CHECK-FUN-001", "core-crypto", "BIP39, entropy and seed interpretation"),
    ("CHECK-FUN-002", "wallet-derivation", "HD derivation and every coin"),
    ("CHECK-FUN-003", "wallet-derivation", "BIP85, BIP38, messages and Silent Payments"),
    ("CHECK-FUN-004", "wallet-derivation", "Scripts, descriptors, Miniscript and multisig"),
    ("CHECK-FUN-005", "wallet-derivation", "Transactions, PSBT and commitments"),
    ("CHECK-FUN-006", "core-crypto", "Recovery and backup formats"),
    ("CHECK-FUN-007", "wallet-derivation", "Discovery, providers, proofs and accounting"),
    ("CHECK-API-001", "browser-wasm", "Actual dependency call contracts"),
    ("CHECK-API-002", "browser-wasm", "Async state, cancellation and revisions"),
    ("CHECK-API-003", "cli-ux", "Public export schema and fidelity"),
    ("CHECK-API-004", "cli-ux", "Encoding and import/export interoperability"),
    ("CHECK-BLD-001", "browser-wasm", "Manifest, flags and feature composition"),
    ("CHECK-BLD-002", "build-supply-chain", "Matrix depth and runtime sampling"),
    ("CHECK-BLD-003", "build-supply-chain", "Lockfiles, source provenance and licences"),
    ("CHECK-BLD-004", "build-supply-chain", "Canonical WASM and Docker bytes"),
    ("CHECK-BLD-005", "build-supply-chain", "Artifacts, CI and release workflows"),
    ("CHECK-UI-001", "browser-wasm", "Real files and representative viewports"),
    ("CHECK-UI-002", "cli-ux", "Navigation, inputs and state preservation"),
    ("CHECK-UI-003", "cli-ux", "Secret visibility, help and accessibility"),
    ("CHECK-ARC-001", "architecture-tests", "Ownership, imports and composition seams"),
    ("CHECK-ARC-002", "architecture-tests", "Dead code, duplication and false positives"),
    ("CHECK-ARC-003", "architecture-tests", "Comments, tests and production-path fidelity"),
    ("CHECK-DOC-001", "docs-claims", "User-facing capability and safety descriptions"),
    ("CHECK-DOC-002", "docs-claims", "Commands, metadata, links and legal materials"),
    ("CHECK-DOC-003", "docs-claims", "Audit records and evidence consistency"),
]


def anonymized(text):
    """Every home directory written as /home/user."""
    return re.sub(r"/home/[^/\s`\"'<>),;:\]]+", "/home/user", text) if isinstance(text, str) else text


def anonymize(value):
    if isinstance(value, dict):
        return {key: anonymize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [anonymize(item) for item in value]
    return anonymized(value)


def quoted_links(text):
    """A Markdown link quoted from another file, whose target does not resolve from this folder,
    as code, so that the report has no broken link."""

    def one(match):
        target = match.group(2).split("#")[0]
        if "://" in target or (AUDITS / target).exists():
            return match.group(0)
        return f"`{match.group(0)}`"

    return re.sub(r"\[([^\]]*)\]\(([^)\s]+)\)", one, text)


def cell(text):
    """Text that fits one Markdown table cell."""
    return quoted_links(anonymized(str(text))).replace("|", "\\|").replace("\n", " ")


def load(name):
    return json.loads((EVIDENCE / name).read_text())


def main():
    date = sys.argv[1]
    workflow = load("workflow-result.json")
    records = sorted(
        load("normalized-records.json"),
        key=lambda record: (CATEGORY_ORDER.index(record["id"].split("-")[2][:3].rstrip("0123456789")), record["id"]),
    )
    observations = load("curated-observations.json")
    baseline = {step: load(f"baseline-{step}.command.json") for step in ("check", "browsers", "canonical")}
    procedure = dict(
        (line.split()[1], line.split()[0]) for line in (EVIDENCE / "procedure-hashes.txt").read_text().splitlines()
    )
    environment = (EVIDENCE / "environment.txt").read_text().splitlines()
    head = (EVIDENCE / "head.txt").read_text().strip()
    fingerprint = (EVIDENCE / "product-fingerprint.txt").read_text().strip()
    product_files = len((EVIDENCE / "initial-product-manifest.txt").read_text().splitlines())
    all_files = len((EVIDENCE / "initial-manifest.txt").read_text().splitlines())
    canonical = [
        line.split() for line in (ROOT / "canonical-output-aud023" / "release" / "SHA256SUMS").read_text().splitlines()
    ]

    coverage = {}
    for scope in workflow["coverage"]:
        for entry in scope.get("coverage") or []:
            check_id = entry["check"].split()[0]
            coverage.setdefault(check_id, []).append({"scope": scope["scope"], **entry})

    for record in records:
        assert re.fullmatch(r"AUD-023-(SEC|FUN|API|BLD|DOC|UI|ARC)[0-9]{3}", record["id"]), record["id"]

    # The JSON envelope of docs/audit-report.schema.json, with the audit's evidence beside it.
    findings = [
        anonymize(
            {
                "id": record["id"],
                "category": record["id"].split("-")[2].rstrip("0123456789"),
                "kind": "finding",
                "title": record["title"],
                "severity": record["severity"],
                "status": "open",
                "releaseBlocking": record["releaseBlocking"],
                "releaseBlockingReason": record["releaseBlockingReason"],
                "checkId": record["checkId"],
                "affected": record["affected"],
                "evidence": record["evidence"],
                "reproduction": record["reproduction"],
                "expected": record["expected"],
                "observed": record["observed"],
                "impact": record["impact"],
                "recommendedFix": record["recommendedFix"],
                "requiredVerification": record["requiredVerification"],
                "relatedFindings": record["relatedFindings"],
            }
        )
        for record in records
    ]
    informational = [
        anonymize(
            {
                "title": item["title"],
                "scope": item.get("scope"),
                "category": item["category"],
                "checkId": item.get("checkId"),
                "files": item.get("files", []),
                "evidence": item.get("evidence"),
                "priorId": item.get("priorId"),
            }
        )
        for item in observations
    ]
    report = {
        "schemaVersion": 1,
        "auditId": "AUD-023",
        "auditNumber": 23,
        "date": date,
        "title": "Full audit of mhfe with independent verification of every finding",
        "reviewer": {
            "name": "Claude Code coordinator with 162 sub-agents (8 scoped reviewers, finding skeptics, a completeness critic and 5 gap reviewers) and 8 record writers",
            "model": "claude-opus-5-5",
            "reasoningEffort": None,
        },
        "snapshot": {
            "commit": head,
            "commitComplete": False,
            "workingTree": "HEAD plus uncommitted changes: Codex's AUD-021 host-protection fixes (src/bin/mhfe/made_password.rs, protect.rs, settings.rs, terminal.rs), the self-test label change (src/bin/mhfe/main.rs, self_test.rs), docs/releases/unreleased.md, docs/audits/README.md and the uncommitted AUD-020, AUD-021 and AUD-022 records",
            "sourceFingerprint": fingerprint,
            "productFiles": product_files,
            "inventoriedFiles": all_files,
            "manifestRule": "SHA-256 of the path-sorted 'sha256  path' rows of every tracked or untracked, not ignored file outside docs/audits/",
        },
        "scope": {
            "repository": "mhfe (library, command-line tool, WebAssembly browser package)",
            "specification": "mhfe_spec README.md and docs/DESIGN-NOTES.md at its working tree",
            "excluded": [
                "Full-cost vector replays (about an hour each), excluded by the owner",
                "macOS and Windows execution beyond the exact-commit CI logs",
                "A foreign host's application (the multi-chain Deriver)",
            ],
            "procedureHashes": procedure,
            "environment": environment,
        },
        "checks": [
            anonymize({"id": f"baseline-{step}", **record}) for step, record in baseline.items()
        ],
        "coverage": [
            anonymize(
                {
                    "check": check_id,
                    "owner": owner,
                    "group": group,
                    "entries": coverage.get(check_id, []),
                }
            )
            for check_id, owner, group in CHECKS
        ],
        "canonicalArchives": [{"file": name, "sha256": digest} for digest, name in canonical],
        "findings": findings,
        "observations": [],
        "informationalObservations": informational,
        "refutedCandidates": anonymize(workflow["rejected"]),
        "completenessGaps": anonymize(workflow["gaps"]),
        "remediation": [
            {
                "id": record["id"],
                "status": "open",
                "fixCommit": None,
                "verificationCommit": None,
                "evidence": "Original reproduction in this report.",
            }
            for record in records
        ],
        "limitations": [
            "Full-cost vector replays were not run, on the owner's instruction; the exact-tag Test vectors run of v0.6.0 is the latest full replay.",
            "Reviewers and skeptics are AI agents; this is not an independent expert review or a certification.",
            "Heavy commands ran one at a time under a 3 GiB (agents) or 6 GiB (baseline) kernel limit and a thermal governor that delayed new jobs at 90 C; the machine rebooted once during the canonical step, which was then rerun in full.",
            "Five gap reviewers stalled once and were retried automatically; their final results are included.",
            "Physical erasure of memory, allocator copies and the terminal's own buffers were not measured.",
        ],
    }
    json_path = AUDITS / f"AUD-023-{date}.json"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")

    severity_counts = {level: sum(1 for f in findings if f["severity"] == level) for level in SEVERITY_ORDER}
    blocking = sum(1 for f in findings if f["releaseBlocking"])
    lines = [
        "# AUD-023 — Full audit of mhfe with independent verification of every finding",
        "",
        f"Outcome: **{len(findings)} confirmed findings**, none release-blocking"
        if not blocking
        else f"Outcome: **{len(findings)} confirmed findings**, {blocking} release-blocking",
        "",
        "## Record metadata",
        "",
        "- **Audit number:** 23.",
        f"- **Completed (UTC):** {date}.",
        f"- **Reviewer:** {report['reviewer']['name']}.",
        "- **Model:** claude-opus-5-5 (coordinator; the sub-agents inherited it).",
        "- **Reasoning effort:** unknown; not retained by the client.",
        f"- **Reviewed commit:** `{head}`.",
        f"- **Working tree:** {report['snapshot']['workingTree']}.",
        f"- **Source fingerprint:** `{fingerprint}` over {product_files} product files ({all_files} files inventoried with the audit records); {report['snapshot']['manifestRule']}.",
        "- **Artifacts:** the uncached canonical build of this tree (below); it is not a release.",
        "- **Records:** [JSON companion](AUD-023-" + date + ".json); [harnesses](AUD-023-harnesses/README.md). Raw logs, the workflow result and manifests are in `AUD-023-evidence/`, which is local and git-ignored.",
        "",
        "## Finding register",
        "",
        "| Finding ID | Category | Kind | Severity | Status | Release blocking | Title |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for f in findings:
        lines.append(
            f"| {f['id']} | {f['category']} | finding | {f['severity']} | open | {str(f['releaseBlocking']).lower()} | {cell(f['title'])} |"
        )
    lines += [
        "",
        "Severity counts: "
        + ", ".join(f"{level} {count}" for level, count in severity_counts.items())
        + f". {len(informational)} informational observations and {len(workflow['rejected'])} refuted candidates are listed after the findings.",
        "",
        "## Review evidence",
        "",
        "### Scope and methodology",
        "",
        "The owner asked for a maximally thorough audit with maximum coverage, without the hour-long vector replays. The standard workspace procedure was applied to all 32 CHECK items of `multi-chain-wallet-tools/docs/FULL_AUDIT_GUIDE.md`, each owned by one of eight scoped reviewers: core-crypto (the cryptographic core and its conformance to the specification), secrets-native (secret ownership and native process protection), wallet-derivation, browser-wasm, cli-ux, build-supply-chain, docs-claims and architecture-tests. Every candidate finding was then given to independent skeptics told to refute it (two for medium and higher, one otherwise); a candidate was kept only when at least half of them confirmed it. A completeness critic compared what was read with the tracked files and named five gaps, each reviewed again and verified the same way. Reviewers worked read-only; heavy commands ran one at a time under a shared lock and kernel memory limits. Public test data only.",
        "",
        "Procedure files (SHA-256):",
        "",
        "| Procedure | SHA-256 |",
        "| --- | --- |",
    ]
    for path, digest in procedure.items():
        lines.append(f"| `{path}` | `{digest}` |")
    lines += ["", "Environment: " + "; ".join(cell(line) for line in environment) + ".", "", "### Coverage ledger", ""]
    lines += ["| Check ID | Owner / logical group | Outcome(s) |", "| --- | --- | --- |"]
    for item in report["coverage"]:
        outcomes = ", ".join(f"{e['outcome']} ({e['scope'].split(':')[0]})" for e in item["entries"]) or "not recorded"
        lines.append(f"| {item['check']} | {item['owner']}: {item['group']} | {cell(outcomes)} |")
    lines += ["", "\"failed\" means the reviewer recorded findings in that area; every finding is in the register. Method, evidence and limits of each entry:", ""]
    for item in report["coverage"]:
        for e in item["entries"]:
            lines.append(
                f"- **{item['check']}** ({e['scope'].split(':')[0]}, {e['outcome']}): {cell(e.get('method', ''))} Evidence: {cell(e.get('evidence', ''))}"
                + (f" Limits: {cell(e['limits'])}" if e.get("limits") else "")
            )
    lines += ["", "### Checks", "", "| Check / command | Outcome | Counts | Evidence |", "| --- | --- | --- | --- |"]
    counts = {
        "check": "library 344 passed / 2 ignored; CLI 128 passed / 3 ignored; suite 3 metadata 3 / 1 ignored; suite 4 metadata 2 / 1 ignored; 4 doctests; terminal suite, package, parity, fast-mode script and release-artifact gates passed",
        "browsers": "1958 ok, 0 FAIL: Chromium and Firefox, standard and fast modes",
        "canonical": "four archives built without cache: " + ", ".join(f"{name} `{digest[:16]}`" for digest, name in canonical),
    }
    for step, record in baseline.items():
        lines.append(
            f"| `{cell(record['command'])}` | {'passed' if record['exitCode'] == 0 else 'failed'} (exit {record['exitCode']}), {record['startedUtc']}–{record['endedUtc']} | {cell(counts[step])} | local log `{cell(record['log'])}`, SHA-256 `{record['logSha256']}` |"
        )
    lines += [
        "",
        "Reviewer and skeptic probes (reduced-cost tests, independent Python recomputations of every published vector from the recorded Argon2id outputs, the oracles' cheap modes, help and refusal runs of the release binary) are named in each finding's evidence and in the JSON coverage entries.",
        "",
        "### Findings",
        "",
    ]
    for f in findings:
        lines += [
            f"#### {f['id']} — {f['severity'].capitalize()} — {cell(f['title'])}",
            "",
            f"- **Category:** {f['category']}.",
            f"- **Severity:** {f['severity']}.",
            "- **Status:** open.",
            f"- **Release blocking:** {str(f['releaseBlocking']).lower()}; {cell(f['releaseBlockingReason'])}",
            f"- **Check:** {f['checkId']}.",
            f"- **Affected files and builds:** {cell(f['affected'])}",
            f"- **Reproduction:** {cell(f['reproduction'])}",
            f"- **Expected behavior:** {cell(f['expected'])}",
            f"- **Observed behavior:** {cell(f['observed'])}",
            f"- **Impact:** {cell(f['impact'])}",
            f"- **Evidence:** {cell(f['evidence'])}",
            f"- **Recommended fix:** {cell(f['recommendedFix'])}",
            f"- **Required verification:** {cell(f['requiredVerification'])}",
        ]
        if f["relatedFindings"]:
            lines.append(f"- **Related findings:** {', '.join(f['relatedFindings'])}.")
        lines.append("")
    lines += [
        "### Remediation and follow-up",
        "",
        "| Finding ID | Status | Fix commit | Verification commit | Evidence |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in report["remediation"]:
        lines.append(f"| {row['id']} | open | Not fixed | Not run | Original reproduction |")
    lines += ["", "### Informational observations", ""]
    for item in informational:
        summary = (item["evidence"] or "").strip()
        lines.append(
            f"- **{cell(item['title'])}** ({item['category']}, {cell(item['scope'] or '')})"
            + (f", prior {item['priorId']}" if item.get("priorId") else "")
            + f": {cell(summary[:600])}{'…' if len(summary) > 600 else ''}"
        )
    lines += ["", "### Refuted candidates", ""]
    for item in workflow["rejected"]:
        reasons = "; ".join(cell(v.get("reasoning", ""))[:400] for v in item.get("verdicts", []))
        lines.append(f"- {cell(item['title'])} ({item['severity']}, {cell(item['scope'])}): {reasons}")
    lines += ["", "### Completeness gaps reviewed again", ""]
    for gap in workflow["gaps"]:
        lines.append(f"- **{cell(gap['area'])}** ({cell(gap['checks'])}): {cell(gap['why'])}")
    lines += [
        "",
        "### Assessment and limitations",
        "",
        f"No critical, high or release-blocking defect was confirmed. The {len(findings)} findings are low-severity defects of conformance, documentation, test strength, repetition and terminal behaviour; together they describe what the next version should fix. The baseline gates, both browsers in both modes and an uncached canonical build passed on the audited tree.",
        "",
    ]
    lines += [f"- {cell(item)}" for item in report["limitations"]]
    lines += [
        "",
        "This record does not certify the absence of defects or of malicious code beyond the stated scope.",
        "",
    ]
    (AUDITS / f"AUD-023-{date}.md").write_text("\n".join(lines))
    print(f"wrote AUD-023-{date}.md and .json: {len(findings)} findings, {len(informational)} observations")


if __name__ == "__main__":
    main()
