"""Build or validate the AUD-020 report from retained offline review evidence.

Run from the repository root:
    python3 -B docs/audits/AUD-020-harnesses/build_report.py --review-dir PATH --write
    python3 -B docs/audits/AUD-020-harnesses/build_report.py --review-dir PATH --validate

PATH is the Codex Security scan's local artifacts directory. The generator requires
validated-findings.json, architecture, the peer reviews, Windows challenge and root
source-coverage reconciliation. It reads command logs
and verifies their hashes, writes only the AUD-020 Markdown/JSON pair, and prints
validation metadata. It does not execute product code or edit evidence. The
coordinator retains its stdout as local report-validation evidence. Validation
requires the existing Python jsonschema package and exits nonzero on any failure.
The reviewed source is 0155c951ab9deee0301b7e37b42ebc994cbd28b7; public data only.
"""

import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess

from jsonschema import Draft202012Validator


AUDIT_ID = "AUD-020"
REPORT_STEM = "AUD-020-2026-10-12"
MODEL_ID = "gpt-6.1-sol"
REASONING_EFFORT = "ultra"
EXPECTED_TARGETED_TESTS = 99
EXPECTED_FINDING_IDS = ("AUD-020-SEC001", "AUD-020-SEC002")
ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-020-evidence"
PROCEDURE_ROOT = ROOT.parent / "multi-chain-wallet-tools/docs"
REPORT_ROOT = ROOT / "docs/audits"
HOME_PATH = re.compile(r"/home/[^/\s\"'<>]+")
TEST_RESULT = re.compile(
    r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;"
    r" (\d+) measured; (\d+) filtered out; finished in ([^\n]+)"
)
PROCEDURES = {
    "FULL_AUDIT_GUIDE.md": "FULL_AUDIT_GUIDE.md",
    "AUDIT_STANDARD.md": "audits/AUDIT_STANDARD.md",
    "AUDIT_TEMPLATE.md": "audits/AUDIT_TEMPLATE.md",
    "audit-report.schema.json": "audit-report.schema.json",
}
REVIEW_FILES = (
    "architecture-review.json",
    "browser-review.json",
    "baseline-review.json",
    "packaging-review.json",
    "cli-review.json",
    "cli-layout-review.json",
    "windows-private-screen-challenge.json",
    "source-coverage-reconciliation.json",
    "validated-findings.json",
)
OUTCOMES = {"passed", "failed", "blocked", "skipped", "not-run", "not-applicable"}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_pairs)


def public_text(value):
    if isinstance(value, str):
        return HOME_PATH.sub("/home/user", value)
    if isinstance(value, list):
        return [public_text(item) for item in value]
    if isinstance(value, dict):
        return {public_text(key): public_text(item) for key, item in value.items()}
    return value


def cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


class AuditReport:
    """Own the report's source bindings, rendering and consistency checks."""

    def __init__(self, review_dir):
        self._review_dir = review_dir
        self._snapshot = read_json(EVIDENCE / "snapshot.json")
        self._procedures = read_json(EVIDENCE / "procedure-hashes.json")
        for name, relative in PROCEDURES.items():
            if sha256(PROCEDURE_ROOT / relative) != self._procedures[name]:
                raise ValueError(f"Audit procedure changed: {name}")
        self._reviews = {
            name: read_json(review_dir / name) for name in REVIEW_FILES
        }
        self._commands = self._read_commands()
        self._md = REPORT_ROOT / f"{REPORT_STEM}.md"
        self._json = REPORT_ROOT / f"{REPORT_STEM}.json"

    def _read_commands(self):
        commands = []
        for path in sorted(EVIDENCE.glob("*.command.json")):
            raw = read_json(path)
            log_path = path.with_name(path.name.replace(".command.json", ".log"))
            expected = raw.get("logSha256")
            if expected is None or sha256(log_path) != expected:
                raise ValueError(f"Unbound command log: {path.name}")
            log = log_path.read_text(errors="replace")
            # The independent reviewer retains the same exact argv under `command`.
            argv = raw.get("argv", raw.get("command"))
            if not isinstance(argv, list):
                raise ValueError(f"No exact argv in command record: {path.name}")
            matches = list(TEST_RESULT.finditer(log))
            counts = [
                dict(zip(
                    ("passed", "failed", "ignored", "measured", "filteredOut"),
                    map(int, match.groups()[:5]),
                ))
                for match in matches
            ]
            label = path.name.removesuffix(".command.json")
            outcome = "passed" if raw["exitCode"] == 0 else "failed"
            note = "Counts are scoped to this command; no overlapping-suite total."
            if label in ("protect", "serve"):
                note = (
                    "Initial protected execution failed at localhost bind; retained as an "
                    "environment restriction. See the separate host-permission rerun."
                )
            elif label.endswith("-host"):
                note = "Host-permission rerun; does not erase or add to the initial run."
            elif label == "swap-proof":
                note = (
                    "Exact-helper synthetic result: missing_inventory=0 known_empty=0 "
                    "visible_unknown_swap=1 unreadable_inventory=0. No actual swap paging "
                    "or secret extraction."
                )
            commands.append(public_text({
                "label": label,
                "command": shlex.join(argv),
                "argv": argv,
                "environment": {
                    key: value for key, value in raw.get("environment", {}).items()
                    if key in ("CARGO_HOME", "RUSTUP_HOME", "RUSTFLAGS", "CARGO_BUILD_JOBS", "NODE_OPTIONS")
                },
                "startUtc": raw.get("startUtc", raw.get("startedAt")),
                "endUtc": raw.get("endUtc", raw.get("endedAt")),
                "exitCode": raw["exitCode"],
                "outcome": outcome,
                "counts": counts,
                "logSha256": expected,
                "recordSha256": sha256(path),
                "diagnostics": [
                    line for line in log.splitlines()
                    if "PermissionDenied" in line or "assertion failed:" in line
                ] if label in ("protect", "serve") else [],
                "localEvidence": f"docs/audits/AUD-020-evidence/{label}.log",
                "note": note,
            }))
        return commands

    def _coverage(self):
        names = re.findall(
            r"^### (CHECK-[A-Z]+-\d{3}) — (.+)$",
            (PROCEDURE_ROOT / "FULL_AUDIT_GUIDE.md").read_text(),
            flags=re.MULTILINE,
        )
        disposition = {
            "CHECK-SEC-001": ("passed", "Source-backed independent architecture; secret owners, inherited descriptors and native/browser limits retained. Targeted memory/FFI tests; no erasure certification."),
            "CHECK-SEC-002": ("passed", "Static worker/CSP/transport tracing and launcher tests. Package workers share host authority; embedding-page runtime CSP not verified."),
            "CHECK-SEC-003": ("passed", "Static offline boundary and network-loader review; launcher is public-HTML only. No public-chain provider or live egress test."),
            "CHECK-SEC-004": ("passed", "Static Argon2/RNG/password/rekey review and targeted known-answer tests. No independent cryptographic proof, entropy proof or full-cost replay."),
            "CHECK-SEC-005": ("failed", "AUD-020-SEC001: unknown swap inventory warning omitted. AUD-020-SEC002: Windows generated-password output does not check actual private-screen activation. Paging, Windows VT failure and cancellation erasure remain unexecuted."),
            "CHECK-SEC-006": ("passed", "Static package source/error/worker dispatch review. No hostile-host isolation claim; generated bundles/binaries and production DOM host are not fully audited."),
            "CHECK-SEC-007": ("passed", "Static parser/work-factor/worker limits and bounded launcher/protection tests. No transaction spending service or deliberate host-exhaustion test."),
            "CHECK-FUN-001": ("passed", "Targeted validation/password tests and static phrase/state interpretation. Published-round table freshness checked; no full vector replay."),
            "CHECK-FUN-002": ("passed", "Source review of wallet-reference derivation integration, supplemented by scoped reviewer evidence only. Every supported coin/profile was not independently replayed."),
            "CHECK-FUN-003": ("not-applicable", "No BIP85, BIP38, message-signing or Silent Payments feature in MHFE."),
            "CHECK-FUN-004": ("not-applicable", "No descriptor, Miniscript, multisig or script-policy interpreter in MHFE."),
            "CHECK-FUN-005": ("not-applicable", "No transaction or PSBT parser/signing coordinator in MHFE."),
            "CHECK-FUN-006": ("passed", "MHFE suites, repair, recovery/rekey confirmation reviewed; targeted rekey/rehearsal tests. No full-cost suite replay or end-to-end host handoff."),
            "CHECK-FUN-007": ("not-applicable", "No blockchain discovery, provider response, proof or balance/accounting service in MHFE."),
            "CHECK-API-001": ("passed", "Native C ABI/ownership tests and source-backed WASM/class contracts. Third-party internals only where explicitly recorded; no blanket dependency audit."),
            "CHECK-API-002": ("passed", "Static cancellation, late replies and rekey state-machine review. Loading-worker delay retained as a limit; real browser timing not executed."),
            "CHECK-API-003": ("not-applicable", "No public monetary CSV/XLSX/accounting exports. MHFE plain-text/JSON result contracts are covered by API-001/API-004."),
            "CHECK-API-004": ("passed", "Targeted encoding/validation and static import/export contract review. Independent full-cost interoperability remains unexecuted."),
            "CHECK-BLD-001": ("passed", "Static Cargo feature/build/package composition review; no complete rebuild or all-feature runtime assurance."),
            "CHECK-BLD-002": ("not-run", "No complete native/browser feature and platform runtime matrix; bounded checks are separately listed."),
            "CHECK-BLD-003": ("passed", "Static pinned lockfiles, vendored provenance and licensing review; no online advisory database or external provenance refresh."),
            "CHECK-BLD-004": ("not-run", "No canonical Docker/WASM rebuild or byte-for-byte release comparison authorized for this Standard scan."),
            "CHECK-BLD-005": ("passed", "Static action pins/permissions/packaging/hash gates and draft publication boundary review. No live CI, signing or release verification."),
            "CHECK-UI-001": ("not-run", "No actual host HTML browser execution, screenshots or representative viewport acceptance."),
            "CHECK-UI-002": ("not-run", "No interactive browser navigation/state or full terminal-menu acceptance run; API source review is not UI acceptance."),
            "CHECK-UI-003": ("not-run", "Host phrase concealment, accessibility and screen cleanup need platform/UI acceptance beyond the bounded checks."),
            "CHECK-ARC-001": ("passed", "Independent source-backed ownership/worker/process/build path mapping; architecture mapping is not audited-file coverage."),
            "CHECK-ARC-002": ("passed", "Static current-source consumers/duplication review within the security scan; no exhaustive dead-code proof or renewed historical harness review."),
            "CHECK-ARC-003": ("passed", "Targeted production tests plus reviewer source/contract challenge; reduced-cost and compile-only evidence explicitly separated."),
            "CHECK-DOC-001": ("failed", "Unknown-swap and private-screen claims have conditional gaps tracked as AUD-020-SEC001/SEC002. Coordinator reconciliation qualifies the original CLI review; other limits remain explicit."),
            "CHECK-DOC-002": ("passed", "Static current documentation/flags/build/provenance review and local procedure hashes. External reachability/private reporting settings not checked."),
            "CHECK-DOC-003": ("passed", "This report's schema, IDs, command hashes, pair agreement and index are checked by the retained validator. Historical audit conclusions are excluded."),
        }
        if len(names) != 32 or set(disposition) != {name for name, _ in names}:
            raise ValueError("Coverage must bind all 32 current procedure checks")
        return [
            {
                "checkId": name,
                "category": name.split("-")[1],
                "logicalGroup": title,
                "scope": "Current MHFE CLI/library/browser package and tooling",
                "method": "Not applicable" if disposition[name][0] == "not-applicable" else "Scoped static review and separately recorded targeted checks",
                "outcome": disposition[name][0],
                "notes": disposition[name][1],
                "snapshot": self._snapshot["head"],
            }
            for name, title in names
        ]

    def _findings(self):
        findings = []
        for value in self._reviews["validated-findings.json"]:
            extension = value["extensions"]
            finding_id = extension["workspaceFindingId"]
            expected = {
                "AUD-020-SEC001": "An unreadable swap inventory must be reported as unknown before secrets are read, as SECURITY.md:79–81 promises.",
                "AUD-020-SEC002": "Generated secret output must require the actual private screen to be active; terminal-handle preflight alone must not authorize printing after Windows VT activation fails.",
            }[finding_id]
            findings.append({
                "id": finding_id,
                "category": "SEC",
                "kind": "finding",
                "title": value["title"],
                "severity": value["severity"]["level"],
                "status": "open",
                "releaseBlocking": extension["releaseBlocking"],
                "releaseBlockingReason": extension["releaseBlockingReason"],
                "affectedFiles": value["locations"],
                "reproduction": value["validation"],
                "expected": expected,
                "observed": value["rootCause"]["summary"],
                "impact": value["summary"] + " " + value["severity"]["rationale"],
                "prerequisites": value["attackPath"]["reachability"]["preconditions"],
                "evidence": value["codeEvidence"],
                "recommendedFix": value["remediation"],
                "requiredVerification": value["remediationTests"],
                "confidence": value["confidence"],
                "sourceSemanticArtifactSha256": sha256(self._review_dir / "validated-findings.json"),
            })
        if tuple(item["id"] for item in findings) != EXPECTED_FINDING_IDS:
            raise ValueError("Finding set changed: reconcile with the scan coordinator")
        return public_text(findings)

    def build(self):
        reviews = [
            {"name": name, "sha256": sha256(self._review_dir / name), "localOnly": True}
            for name in REVIEW_FILES
        ]
        limitations = [
            "Standard single-pass security scan with targeted tests; full-scope checklist mapped with incomplete execution. This is not a fully executed end-to-end audit or release acceptance.",
            "Historical docs/audits reports and harnesses are excluded from renewed security-audit coverage. Audit-only helpers may be used as tools without revalidating historical conclusions.",
            "Ignored dist/target outputs, generated glue and WASM/C binaries are not fully audited or rebuilt. Source/artifact correspondence is not established by this scan.",
            "No full release check, canonical Docker/reproducible rebuild, full-cost Argon2/vector replay, real Chromium/Firefox, Windows/macOS runtime, transaction service or external provider access was executed.",
            "No forced paging, actual swap storage read or secret extraction. Only a missing diagnostic was reproduced with the unchanged helper and synthetic metadata.",
            "Browser strings, cancelled-worker erasure, dependency/terminal copies, inherited descriptors and host compromise remain platform/caller limits. No independent cryptographic or entropy proof.",
            "Initial protected localhost-bind failures remain failed command records; host-permission reruns are separate evidence. Counts from overlapping suites/reruns are never summed.",
            "All report commands/paths are privacy-anonymized; local raw evidence is unchanged. Local artifacts are not public downloadable report assets.",
        ]
        findings = self._findings()
        environment = read_json(EVIDENCE / "environment.log")
        corpus = read_json(EVIDENCE / "spec-corpus-identity.log")
        successful_scopes = (
            "ffi", "rekey", "rehearsal", "protect-host", "serve-host",
            "password", "memory", "validation",
        )
        test_names = set()
        for label in successful_scopes:
            log = (EVIDENCE / f"{label}.log").read_text()
            test_names.update(re.findall(r"^test (\S+) \.\.\. ok$", log, re.MULTILINE))
        if len(test_names) != EXPECTED_TARGETED_TESTS:
            raise ValueError("Successful targeted test set changed; reconcile counts")
        report = {
            "schemaVersion": 1,
            "auditId": AUDIT_ID,
            "auditNumber": 20,
            "date": "2026-10-12",
            "title": "MHFE Standard security scan with targeted verification",
            "reviewer": {"name": "Codex Security coordinator and scoped independent reviewers", "model": MODEL_ID, "reasoningEffort": REASONING_EFFORT},
            "reviewerPhases": [
                {"scope": name.removesuffix("-review.json"), "model": MODEL_ID, "reasoningEffort": REASONING_EFFORT}
                for name in REVIEW_FILES
                if name.endswith("-review.json") or name == "windows-private-screen-challenge.json"
            ],
            "snapshot": {
                "commit": self._snapshot["head"],
                "commitComplete": True,
                "workingTree": "Clean before audit-only helpers/reports were added; no product remediation was applied.",
                "sourceFingerprint": self._snapshot["fingerprint"],
                "files": self._snapshot["files"],
                "fingerprintScope": "Full initial current-source inventory, including historical audit records; security-review exclusions are recorded separately.",
                "snapshotEvidenceSha256": sha256(EVIDENCE / "snapshot.json"),
            },
            "scope": {
                "repository": "https://github.com/hobby-eng/mhfe",
                "mode": "Standard security scan, targeted verification",
                "included": ["Current first-party CLI/library/browser binding/class source", "Relevant vendored Argon2 boundary and dependency integration", "Current build/packaging/workflow/security documentation"],
                "excluded": ["Renewed historical audit/harness conclusions", "Full ignored/generated binary artifact audit", "External host HTML and unrelated projects", "Full release-level execution and independent cryptographic proof"],
                "policy": "Root SECURITY.md applies; no nested policy found in reviewed scopes.",
            },
            "procedureHashes": self._procedures,
            "localReviewArtifacts": reviews,
            "environment": {
                "observedVersions": environment,
                "localEvidenceSha256": sha256(EVIDENCE / "environment.log"),
                "declaredToolchains": {"Rust": "1.99.0", "Node": "26.10.0", "wasmBindgen": "0.2.129", "Emscripten": "6.0.12", "Prettier": "3.9.9"},
                "notes": "Declared pins are source metadata, not proof that every toolchain or browser was exercised.",
            },
            "checks": {"coverageLedger": self._coverage(), "commands": self._commands},
            "targetedTests": {
                "distinctPassed": len(test_names),
                "scopes": list(successful_scopes),
                "testNames": sorted(test_names),
                "ignored": "One protection child guard remains marked ignored in the direct suite; its wrapper executes it. It is not counted again.",
            },
            "specificationCorpusIdentity": {
                "outcome": corpus["outcome"],
                "matchedFiles": corpus["matchedFiles"],
                "localEvidenceSha256": sha256(EVIDENCE / "spec-corpus-identity.log"),
                "limitation": corpus["limitation"],
            },
            "findings": findings,
            "observations": [],
            "informationalObservations": [
                "Direct CLI and menu commands have different namespace/thread controls; Linux isolation does not revoke inherited descriptors. Non-Linux/browser restrictions are weaker and reported as such.",
                "Loading-worker cancellation can defer termination until readiness/error or 60 seconds for Firefox crash avoidance. This is a qualified lifecycle limit, not a demonstrated additional attacker capability.",
                "Loopback launcher CSP only forbids framing; strict script/connect policy, secret concealment and session inactivity/unload closure belong to the embedding page, which was not audited.",
                "Adjacent HTML SHA-256 and package build IDs detect accidental damage/mixing, not malicious replacement of both content and identifier. Release authentication remains external to those checks.",
                "No confirmed Critical, High or Medium finding or new release blocker in this bounded evidence. No product fix was applied and no conclusion from a previous audit was silently reaffirmed.",
            ],
            "remediation": [{"id": item["id"], "status": "open", "fixCommit": None, "verificationCommit": None, "evidence": (
                "Source trace and exact-helper synthetic swap probe; no fix applied."
                if item["id"] == "AUD-020-SEC001"
                else "Independent source-only Windows reachability challenge; no host reproduction or fix."
            )} for item in findings],
            "limitations": limitations,
            "assessment": f"{len(findings)} confirmed Low conditional host secret-handling findings remain open. Targeted checks support the traced paths; release acceptance and exhaustive security assurance are not assessed.",
            "reportGenerator": {"path": "docs/audits/AUD-020-harnesses/build_report.py", "sha256": sha256(Path(__file__))},
            "peerReviewLimitations": {
                name: value.get("limitations", value.get("coverage_limits", []))
                for name, value in self._reviews.items() if isinstance(value, dict)
            },
            "sourceCoverage": {
                "kind": "Scoped reviewer-declared source review; not end-to-end runtime coverage",
                "architectureCountsAsFileCoverage": False,
                "reviewerInventories": {
                    name: value.get("fully_reviewed_files", [])
                    for name, value in self._reviews.items()
                    if isinstance(value, dict) and name != "architecture-review.json"
                },
                "exclusions": [
                    "Historical audit reports/test harnesses and their old conclusions",
                    "Ignored/generated artifact graphs except specifically inspected control seams",
                    "Inactive unbuilt vendored utility C outside the Argon2 engine integration",
                    "Unrelated external host pages/deployments",
                ],
                "coordinatorReconciliation": self._reviews["source-coverage-reconciliation.json"],
            },
            "optionalRecommendations": [
                value["details"]
                for value in self._reviews["packaging-review.json"].get("dispositions", [])
                if value["outcome"].startswith("Optional")
            ],
            "optionalHardeningAndResearch": [
                value["remaining_question"] + " No lower-trust log or disclosure sink was established."
                for value in self._reviews["baseline-review.json"].get("resolved_questions", [])
                if value["id"] == "BASELINE-Q001"
            ],
            "reviewerReconciliation": [
                "The original CLI supplement classified Windows generated-password screen activation as optional hardening. The coordinator independently traced a supported direct command with --repair-words 0 that bypasses menu-based cancellation, and accepted the conditional private-screen guard omission as AUD-020-SEC002, Low with medium confidence. No Windows runtime failure or real secret exposure was demonstrated; the original reviewer artifact is unchanged.",
                "Original baseline wording names ../mhfe_spec/DESIGN-NOTES.md; the actual current companion reference is ../mhfe_spec/docs/DESIGN-NOTES.md. This is a coordinator correction of an artifact statement, not a product finding or new review execution.",
                "Original baseline BASELINE-Q007 says the Python launcher delegates to an executable. Current packaging/mhfe-fast-mode.py:307–355 owns its listener/server directly; browser opening uses Python webbrowser. The original review artifact is retained unchanged, while the architecture/packaging mapping supplies the corrected fact.",
            ],
        }
        return public_text(report)

    def write(self):
        report = self.build()
        self._json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        self._md.write_text(self._markdown(report))

    def _markdown(self, report):
        environment = report["environment"]["observedVersions"]
        environment_summary = (
            f"Python {environment['python']}; Node {environment['node']}; "
            f"{environment['rustc']}; {environment['cargo']}; "
            f"{environment['os']} {environment['kernel']}, {environment['architecture']}"
        )
        lines = [
            f"# {AUDIT_ID} — {report['title']}", "", "## Record metadata", "",
            "- **Audit number:** 20.", "- **Completed (UTC):** 2026-10-12.",
            "- **Reviewer:** Codex Security coordinator and scoped independent reviewers.",
            f"- **Model:** {MODEL_ID} (retained client metadata).", f"- **Reasoning effort:** {REASONING_EFFORT}.",
            f"- **Reviewer phases:** Independent architecture, native baseline, browser/WASM, packaging/documentation, CLI and layout supplements, and source-only Windows challenge; inherited {MODEL_ID} / {REASONING_EFFORT} settings.",
            f"- **Reviewed commit:** `{report['snapshot']['commit']}`.",
            f"- **Working tree:** {report['snapshot']['workingTree']}",
            f"- **Source inventory:** {report['snapshot']['files']} initial files; SHA-256 `{report['snapshot']['sourceFingerprint']}`. Historical audit records contribute to the inventory fingerprint but are excluded from renewed security coverage.",
            "- **Artifacts:** Ignored generated/released binaries were not fully audited or rebuilt; correspondence to current source is not certified.",
            "", "## Finding register", "",
            "| Finding / record ID | Category | Kind | Severity | Recorded status | Title |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for finding in report["findings"]:
            lines.append("| " + " | ".join(cell(finding[key]) for key in ("id", "category", "kind", "severity", "status", "title")) + " |")
        lines += ["", "## Review evidence", "", "### Scope and methodology", "",
            "This is a Standard single-pass security scan with scoped independent reviewers and targeted public-data tests. The workspace's full-scope procedure is mapped below with incomplete execution; this is not a fully executed end-to-end audit or release acceptance. Current CLI/library/browser/package boundaries were traced, candidate claims challenged, and command outcomes bound to retained logs. Root SECURITY.md is the applicable inherited policy.",
            "", "Historical reports/harnesses are excluded from renewed vulnerability coverage. Ignored dist/target binaries and generated files were inspected only where a reviewer identifies a seam; they were not fully audited. External production host HTML, real funds, online services and release-level execution are excluded.",
            "", "Root coverage reconciliation separately excludes 375 historical audit files, five inactive C utilities, a deeper audit of the large verification/independent harnesses, fresh license/mascot/historical measurement/release claims, and generated binaries. Reused specification identity and structural/table/provenance checks are evidence within that scope, not independent runtime or upstream/advisory/legal freshness verification. The full coordinator reconciliation is retained in the JSON companion and hash-bound as a local artifact.",
            "", "Declared source pins: Rust 1.99.0, Node 26.10.0, wasm-bindgen 0.2.129, Emscripten 6.0.12 and Prettier 3.9.9. They are not inferred runtime measurements. Exact executed commands and selected environment values appear in the JSON companion; unknown browser/cross-platform versions remain unverified.",
            "", f"Recorded environment: {environment_summary}. No browser engine was executed. Local environment-log SHA-256: `" + report["environment"]["localEvidenceSha256"] + "`.",
            "", "Procedure sources are in the sibling multi-chain-wallet-tools checkout. Their exact SHA-256 bindings are:", "",
            "| Procedure | SHA-256 |", "| --- | --- |",
        ]
        for name, digest in report["procedureHashes"].items():
            relative = PROCEDURES[name]
            lines.append(f"| [{name}](../../../multi-chain-wallet-tools/docs/{relative}) | `{digest}` |")
        lines += ["", "### Coverage ledger", "",
            "A `passed` static row means the described source review/targeted evidence completed within its stated scope; it does not imply the procedure's full runtime matrix ran. Failed rows reference the two tracked findings across more than one discipline; they are not counted again.",
            "", "| Check ID | Category / logical group | Tool / build scope | Method | Outcome | Evidence / gap reason |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for check in report["checks"]["coverageLedger"]:
            values = [check["checkId"], f"{check['category']} / {check['logicalGroup']}", check["scope"], check["method"], check["outcome"], check["notes"]]
            lines.append("| " + " | ".join(cell(value) for value in values) + " |")
        lines += ["", "### Checks", "",
            "Raw command records/logs are local-only under `docs/audits/AUD-020-evidence/`; they are not committed or linked as public evidence. Every row preserves its own outcome and log hash. Original protected failures and host reruns are separate; overlapping suite counts are not added.",
            "", f"The eight successful scoped test logs contain **{report['targetedTests']['distinctPassed']} distinct passing test names**. One protection child guard is marked ignored in its direct suite and executed by its wrapper; it is not counted twice. The byte-identity comparison matched all **{report['specificationCorpusIdentity']['matchedFiles']} specification JSON files** to current implementation fixtures, without a fresh Argon2 replay. Local corpus-log SHA-256: `" + report["specificationCorpusIdentity"]["localEvidenceSha256"] + "`.",
            "", "| Check / exact command | Outcome | Counts / environment | Local evidence SHA-256 |",
            "| --- | --- | --- | --- |",
        ]
        for command in report["checks"]["commands"]:
            counts = "; ".join(
                f"{item['passed']} passed, {item['failed']} failed, {item['ignored']} ignored, {item['filteredOut']} filtered"
                for item in command["counts"]
            ) or "No Rust suite count"
            lines.append(f"| `{cell(command['command'])}` | {command['outcome']}; exit {command['exitCode']} | {counts}. {cell(command['note'])} | `{command['label']}.log`: `{command['logSha256']}` |")
        lines += ["", "Original protected-run diagnostics (privacy-only path anonymization):", ""]
        for command in report["checks"]["commands"]:
            for diagnostic in command["diagnostics"]:
                lines.append(f"- `{command['label']}`: {diagnostic}")
        lines += ["", "### Findings", "", "#### Security — Host secret-handling guards", ""]
        for finding in report["findings"]:
            affected = "; ".join(
                f"[{location['path']}](../../{location['path']}) lines {location['startLine']}–{location['endLine']}"
                for location in finding["affectedFiles"]
            )
            lines += [f"##### {finding['id']} — {finding['severity'].capitalize()} — {finding['title']}", "",
                f"- **Category:** {finding['category']}.", f"- **Severity:** {finding['severity']}.", f"- **Status:** {finding['status']}.",
                f"- **Confidence:** {finding['confidence']['level']}; {finding['confidence']['rationale']}",
                f"- **Release blocking:** {str(finding['releaseBlocking']).lower()}; {finding['releaseBlockingReason']}",
                f"- **Affected files and builds:** {affected}.",
                f"- **Reproduction:** {finding['reproduction']['summary']}",
                "- **Validation assertions:** " + " ".join(finding["reproduction"].get("assertions", [])),
                f"- **Expected behavior:** {finding['expected']}", f"- **Observed behavior:** {finding['observed']}",
                f"- **Impact:** {finding['impact']}",
                "- **Prerequisites:** " + " ".join(finding["prerequisites"]),
                "- **Evidence:** Exact source anchors/excerpts and validation limitations are retained in the JSON finding and the hash-bound local semantic review artifact. Executed command evidence, where applicable, is listed above; static proof is not a host-runtime reproduction.",
                f"- **Recommended fix:** {finding['recommendedFix']}",
                "- **Required verification:** " + " ".join(finding["requiredVerification"]), "",
            ]
        lines += ["### Remediation and follow-up", "",
            "| Finding ID | Status | Fix commit | Verification commit | Evidence |", "| --- | --- | --- | --- | --- |",
        ]
        for row in report["remediation"]:
            lines.append(f"| {row['id']} | {row['status']} | Not fixed | Not run | {row['evidence']} |")
        lines += ["", "No product remediation, commit, push or release was performed.", "",
            "### Informational observations and recommendations", "",
        ]
        lines += [f"- {item}" for item in report["informationalObservations"]]
        lines += ["", "Coordinator reconciliation of original peer conclusions and wording:", ""]
        lines += [f"- {item}" for item in report["reviewerReconciliation"]]
        lines += ["", "Optional documentation clarifications, separate from the confirmed security finding:", ""]
        lines += [f"- {item}" for item in report["optionalRecommendations"]]
        lines += ["", "Optional security hardening and research questions, with no additional validated finding:", ""]
        lines += [f"- {item}" for item in report["optionalHardeningAndResearch"]]
        lines += ["", "Independent review artifacts are retained locally by Codex Security. Their hashes, which a report reader can compare if the local artifacts are supplied, are:", "",
            "| Local-only artifact | SHA-256 |", "| --- | --- |",
        ]
        lines += [f"| `{item['name']}` | `{item['sha256']}` |" for item in report["localReviewArtifacts"]]
        lines += ["", f"Report generator: [build_report.py](AUD-020-harnesses/build_report.py), SHA-256 `{report['reportGenerator']['sha256']}`. It reads immutable retained inputs, anonymizes published paths and validates the paired records without modifying raw evidence.", "",
            "### Assessment and limitations", "", report["assessment"], "",
        ]
        lines += [f"- {item}" for item in report["limitations"]]
        lines += ["", f"Machine-readable companion: [{REPORT_STEM}.json]({REPORT_STEM}.json).", ""]
        return public_text("\n".join(lines))

    def validate(self):
        report = read_json(self._json)
        markdown = self._md.read_text()
        schema = read_json(PROCEDURE_ROOT / "audit-report.schema.json")
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(report)
        metadata = (
            (report["auditId"], AUDIT_ID),
            (report["auditNumber"], 20),
            (report["date"], "2026-10-12"),
            (report["reviewer"]["model"], MODEL_ID),
            (report["reviewer"]["reasoningEffort"], REASONING_EFFORT),
        )
        for actual, expected in metadata:
            if actual != expected or str(expected) not in markdown:
                raise ValueError("Markdown/JSON audit/reviewer metadata disagree")
        records = report["findings"] + report["observations"]
        ids = [record["id"] for record in records]
        if len(ids) != len(set(ids)):
            raise ValueError("Finding IDs are not unique")
        headings = re.findall(r"^##### (AUD-\d{3,}-[A-Z]+\d{3,}) — (\w+) — (.+)$", markdown, re.MULTILINE)
        if set(ids) != {heading[0] for heading in headings}:
            raise ValueError("Markdown/JSON finding sets disagree")
        for finding in report["findings"]:
            expected = (finding["id"], finding["severity"].capitalize(), finding["title"])
            if expected not in headings or f"- **Status:** {finding['status']}." not in markdown:
                raise ValueError("Markdown/JSON finding severity/title/status disagree")
        if report["snapshot"]["commit"] not in markdown or report["snapshot"]["sourceFingerprint"] not in markdown:
            raise ValueError("Markdown/JSON snapshot bindings disagree")
        checks = report["checks"]["coverageLedger"]
        if len(checks) != 32 or len({check["checkId"] for check in checks}) != 32:
            raise ValueError("Incomplete or duplicate coverage ledger")
        for check in checks:
            if check["outcome"] not in OUTCOMES or check["checkId"] not in markdown:
                raise ValueError("Invalid coverage outcome or missing Markdown row")
            rows = [line for line in markdown.splitlines() if line.startswith(f"| {check['checkId']}")]
            if len(rows) != 1 or check["outcome"] not in rows[0]:
                raise ValueError("Markdown/JSON coverage outcome disagrees")
        for item in report["checks"]["commands"]:
            if item["logSha256"] not in markdown:
                raise ValueError("Missing Markdown command hash")
            source = next((row for row in self._commands if row["label"] == item["label"]), None)
            if source != item:
                raise ValueError(f"Command record changed: {item['label']}")
            rows = [line for line in markdown.splitlines() if f"`{item['label']}.log`:" in line]
            if len(rows) != 1 or f"{item['outcome']}; exit {item['exitCode']}" not in rows[0]:
                raise ValueError("Markdown/JSON command outcome disagrees")
            for count in item["counts"]:
                expected = f"{count['passed']} passed, {count['failed']} failed, {count['ignored']} ignored, {count['filteredOut']} filtered"
                if expected not in rows[0]:
                    raise ValueError("Markdown/JSON command counts disagree")
        if report["targetedTests"]["distinctPassed"] != EXPECTED_TARGETED_TESTS or len(report["targetedTests"]["testNames"]) != EXPECTED_TARGETED_TESTS:
            raise ValueError("Distinct test-name count disagrees")
        if report["specificationCorpusIdentity"]["localEvidenceSha256"] != sha256(EVIDENCE / "spec-corpus-identity.log"):
            raise ValueError("Specification corpus identity evidence changed")
        if report["environment"]["localEvidenceSha256"] != sha256(EVIDENCE / "environment.log"):
            raise ValueError("Environment evidence changed")
        for link in re.findall(r"\[[^\]]+\]\(([^)]+)\)", markdown):
            if link.startswith(("http://", "https://", "#")):
                continue
            if not (self._md.parent / link.split("#")[0]).resolve().is_file():
                raise ValueError(f"Missing committed/source link: {link}")
        index = (REPORT_ROOT / "README.md").read_text()
        if f"[{AUDIT_ID}]({REPORT_STEM}.md)" not in index:
            raise ValueError("Missing audit index row")
        text = markdown + self._json.read_text()
        if re.search(r"/home/(?!user(?:/|\b))", text) or re.search(r"[\u0400-\u04ff]", text):
            raise ValueError("Published report contains private home path or non-English text")
        staged = subprocess.check_output(
            ["git", "diff", "--cached", "--name-only"], cwd=ROOT, text=True,
        ).splitlines()
        if any("-evidence/" in name for name in staged):
            raise ValueError("Local evidence is staged")
        if sha256(Path(__file__)) != report["reportGenerator"]["sha256"]:
            raise ValueError("Report generator source binding changed")
        source_bindings = 0
        for name, expected in self._snapshot["hashes"].items():
            if name.startswith("docs/audits/"):
                continue
            if sha256(ROOT / name) != expected:
                raise ValueError(f"Reviewed product source changed: {name}")
            source_bindings += 1
        for finding in report["findings"]:
            for evidence in finding["evidence"]:
                source = (ROOT / evidence["path"]).read_text()
                if evidence["code"].rstrip() not in source:
                    raise ValueError(f"Source evidence changed: {evidence['path']}")
                if evidence["startLine"] < 1 or evidence["endLine"] > len(source.splitlines()):
                    raise ValueError("Finding source location is outside its file")
                cited = "\n".join(source.splitlines()[evidence["startLine"] - 1:evidence["endLine"]])
                if cited.rstrip() != evidence["code"].rstrip():
                    raise ValueError(f"Finding excerpt does not match its exact lines: {evidence['path']}")
        reconciliation = report["sourceCoverage"]["coordinatorReconciliation"]
        paths = reconciliation["source_path_dispositions"]
        if len(paths) != len(self._snapshot["hashes"]):
            raise ValueError("Source reconciliation does not cover the initial inventory")
        bound = {row["path"]: row["sha256"] for row in paths}
        if len(bound) != len(paths) or bound != self._snapshot["hashes"]:
            raise ValueError("Source reconciliation has duplicate or mismatched bindings")
        counts = {}
        for row in paths:
            counts[row["disposition"]] = counts.get(row["disposition"], 0) + 1
            if row["path"].startswith("src/") and row["disposition"] == "explicitly_excluded":
                raise ValueError("Active source path is excluded from final reconciliation")
        if counts != reconciliation["counts"]:
            raise ValueError("Source reconciliation disposition counts disagree")
        if report["procedureHashes"] != self._procedures:
            raise ValueError("Report procedure binding changed")
        expected_review = {name: sha256(self._review_dir / name) for name in REVIEW_FILES}
        if {row["name"]: row["sha256"] for row in report["localReviewArtifacts"]} != expected_review:
            raise ValueError("Peer-review artifact binding changed")
        return {
            "auditId": AUDIT_ID,
            "validatedUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "schema": "Draft 2020-12; canonical workspace audit schema",
            "result": "passed",
            "checks": ["No duplicate JSON keys", "Canonical JSON schema", "Unique finding/check IDs", "Markdown/JSON pair agreement", "Local source/committed links", "English and anonymized paths", "Unchanged command/review/procedure hashes", "No staged local evidence", "Audit index row"],
            "findingIds": ids,
            "coverageChecks": len(checks),
            "commandRecords": len(report["checks"]["commands"]),
            "unchangedProductSourceBindings": source_bindings,
            "reports": {self._md.name: sha256(self._md), self._json.name: sha256(self._json)},
            "generatorSha256": sha256(Path(__file__)),
            "limitations": "Valid report structure and bindings do not prove product security or replace unexecuted checks.",
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-dir", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    report = AuditReport(args.review_dir)
    if args.write:
        report.write()
        print("Wrote the AUD-020 Markdown/JSON pair; format and validate it next.")
    else:
        print(json.dumps(report.validate(), indent=2))


if __name__ == "__main__":
    main()
