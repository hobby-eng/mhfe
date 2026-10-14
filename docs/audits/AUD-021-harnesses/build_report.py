"""Build and validate the scoped AUD-021 remediation record from local evidence.

Run from the repository root with --write or --validate. This script reads the
retained baseline, final snapshot and command logs; it never runs product code or
changes raw evidence. It writes only the AUD-021 Markdown/JSON pair. The original
AUD-020 generator supplies shared JSON, hashing and privacy helpers unchanged.
"""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess


ROOT = Path(__file__).resolve().parents[3]
REPORT_ROOT = ROOT / "docs/audits"
EVIDENCE = REPORT_ROOT / "AUD-021-evidence"
REPORT_STEM = "AUD-021-2026-10-12"
FINDING_IDS = ("AUD-020-SEC001", "AUD-020-SEC002")
PRODUCT_FILES = (
    "src/bin/mhfe/protect.rs",
    "src/bin/mhfe/settings.rs",
    "src/bin/mhfe/terminal.rs",
    "src/bin/mhfe/made_password.rs",
)
NODE = Path.home() / ".local/share/nodejs/node-v26.10.0-linux-x64/bin/node"
PRETTIER = ROOT / "node_modules/prettier/bin/prettier.cjs"
BASELINE_HELPERS = REPORT_ROOT / "AUD-020-harnesses/build_report.py"
spec = importlib.util.spec_from_file_location("aud020_report_helpers", BASELINE_HELPERS)
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)


class RemediationReport:
    """Own the remediation record, source bindings and paired-record checks."""

    def __init__(self):
        self._initial = helpers.read_json(EVIDENCE / "snapshot.json")
        self._final = helpers.read_json(EVIDENCE / "remediation-snapshot.json")
        self._baseline = helpers.read_json(REPORT_ROOT / "AUD-020-2026-10-12.json")
        self._commands = self._read_commands()
        self._md = REPORT_ROOT / f"{REPORT_STEM}.md"
        self._json = REPORT_ROOT / f"{REPORT_STEM}.json"
        self._check_inputs()

    def _check_inputs(self):
        if self._initial["head"] != self._final["head"]:
            raise ValueError("Remediation HEAD changed without a new snapshot")
        if self._final["head"] != self._baseline["snapshot"]["commit"]:
            raise ValueError("Remediation baseline does not match AUD-020")
        findings = self._baseline["findings"]
        if tuple(item["id"] for item in findings) != FINDING_IDS:
            raise ValueError("Original AUD-020 findings changed")
        if any(item["status"] != "open" for item in findings):
            raise ValueError("Historical AUD-020 findings must remain open")
        for name in ("AUD-020-2026-10-12.md", "AUD-020-2026-10-12.json"):
            relative = f"docs/audits/{name}"
            if helpers.sha256(REPORT_ROOT / name) != self._initial["hashes"][relative]:
                raise ValueError(f"Original audit record changed: {name}")
        scan_root = Path(self._final["originalScanDir"])
        for name, expected in self._final["originalScanBindings"].items():
            if helpers.sha256(scan_root / name) != expected:
                raise ValueError(f"Sealed original scan changed: {name}")
        review_root = Path(self._final["reviewDir"])
        for artifact in self._baseline["localReviewArtifacts"]:
            if helpers.sha256(review_root / artifact["name"]) != artifact["sha256"]:
                raise ValueError(f"Original review artifact changed: {artifact['name']}")
        for name, relative in helpers.PROCEDURES.items():
            actual = helpers.sha256(helpers.PROCEDURE_ROOT / relative)
            if actual != self._baseline["procedureHashes"][name]:
                raise ValueError(f"Shared procedure changed: {name}")
        for name, expected in self._final["hashes"].items():
            if helpers.sha256(ROOT / name) != expected:
                raise ValueError(f"Final source changed after verification: {name}")
        if helpers.sha256(EVIDENCE / "product.patch") != self._final["patchSha256"]:
            raise ValueError("Retained product patch changed")
        if helpers.sha256(ROOT / "target/debug/mhfe") != self._final["cliBinarySha256"]:
            raise ValueError("Scoped CLI binary changed")
        required = {"before-swap", "before-display", "after-swap", "after-display"}
        by_label = {item["label"]: item for item in self._commands}
        if not required.issubset(by_label):
            raise ValueError("Original failures and post-fix regression logs are required")
        for label in ("before-swap", "before-display"):
            if by_label[label]["exitCode"] != 101:
                raise ValueError(f"Expected retained regression failure: {label}")
        for item in self._commands:
            if not item["label"].startswith("before-") and item["exitCode"] != 0:
                raise ValueError(f"Unresolved post-fix command failure: {item['label']}")

    def _read_commands(self):
        result = []
        for path in sorted(EVIDENCE.glob("*.command.json")):
            label = path.name.removesuffix(".command.json")
            # Report validation captures this script's stdout and is kept separately,
            # avoiding a self-referential report/log hash.
            if label.startswith("report-") or label == "docs-format":
                continue
            raw = helpers.read_json(path)
            log_path = EVIDENCE / f"{label}.log"
            if helpers.sha256(log_path) != raw["logSha256"]:
                raise ValueError(f"Command log changed: {label}")
            log = log_path.read_text(errors="replace")
            counts = [
                dict(zip(
                    ("passed", "failed", "ignored", "measured", "filteredOut"),
                    map(int, match.groups()[:5]),
                ))
                for match in helpers.TEST_RESULT.finditer(log)
            ]
            note = "Counts belong to this command; overlapping reruns are not added."
            if label.startswith("before-"):
                note = "Expected regression failure after tests were added, before fixes."
            case_counts = None
            if label == "terminal-controls":
                case_counts = {"focusedUnixFunctionsPassed": 3}
                note = "Three existing Unix PTY functions, with their subcases; not the full terminal suite."
            elif label == "terminal-direct":
                case_counts = {"explicitPasswordKindsPassed": 3}
                note = "Words/check-word/chars exact explicit path; cancelled before Argon2; terminal restored."
            elif label == "specification-control":
                case_counts = json.loads(log)
                if case_counts["matchedFiles"] != 31:
                    raise ValueError("Expected 31 byte-identical specification fixtures")
                note = "31 fixture files byte-identical; no full-cost vector replay."
            result.append(helpers.public_text({
                "label": label,
                "command": shlex.join(raw["argv"]),
                "argv": raw["argv"],
                "environment": {
                    key: value for key, value in raw.get("environment", {}).items()
                    if key in ("CARGO_HOME", "RUSTUP_HOME", "CARGO_BUILD_JOBS", "RUSTFLAGS")
                },
                "startUtc": raw["startUtc"],
                "endUtc": raw["endUtc"],
                "exitCode": raw["exitCode"],
                "outcome": "passed" if raw["exitCode"] == 0 else "failed",
                "counts": counts,
                "caseCounts": case_counts,
                "testNames": re.findall(r"^test (\S+) \.\.\. ok$", log, re.MULTILINE),
                "diagnostics": [
                    line for line in log.splitlines()
                    if "assertion" in line or "reached stderr" in line or "panicked at" in line
                ] if label.startswith("before-") else [],
                "logSha256": raw["logSha256"],
                "recordSha256": helpers.sha256(path),
                "localEvidence": f"docs/audits/AUD-021-evidence/{label}.log",
                "localOnly": True,
                "note": note,
            }))
        return result

    def _fingerprint(self, hashes):
        rows = "".join(f"{value}  {name}\n" for name, value in sorted(hashes.items()))
        return hashlib.sha256(rows.encode()).hexdigest()

    def _source_binding(self):
        before = self._initial["hashes"]
        after = self._final["hashes"]
        names = [name for name in before if not name.startswith("docs/audits/")]
        before_source = {name: before[name] for name in names}
        after_source = {name: after[name] for name in names}
        if self._fingerprint(before_source) != self._final["beforeSourceFingerprint"]:
            raise ValueError("Initial source fingerprint differs from retained manifest")
        if self._fingerprint(after_source) != self._final["sourceFingerprint"]:
            raise ValueError("Final source fingerprint differs from retained manifest")
        for phase, hashes in (("before", before_source), ("after", after_source)):
            if helpers.sha256(EVIDENCE / f"{phase}-source-manifest.txt") != self._fingerprint(hashes):
                raise ValueError(f"Retained {phase} source manifest changed")
        return {
            "fingerprintMethod": "SHA-256 of path-sorted file SHA-256 + two spaces + path + LF rows",
            "fingerprintScope": "Initial non-audit source inventory, including release notes",
            "files": len(names),
            "beforeSourceFingerprint": self._fingerprint(before_source),
            "afterSourceFingerprint": self._fingerprint(after_source),
            "initialSnapshotSha256": helpers.sha256(EVIDENCE / "snapshot.json"),
            "finalSnapshotSha256": helpers.sha256(EVIDENCE / "remediation-snapshot.json"),
            "localSourceManifests": {"before": "docs/audits/AUD-021-evidence/before-source-manifest.txt", "after": "docs/audits/AUD-021-evidence/after-source-manifest.txt", "localOnly": True},
            "patchSha256": self._final["patchSha256"],
            "patchLocalEvidence": "docs/audits/AUD-021-evidence/product.patch",
            "patchCommand": "git diff --no-ext-diff -- docs/releases/unreleased.md src/bin/mhfe/protect.rs src/bin/mhfe/settings.rs src/bin/mhfe/terminal.rs src/bin/mhfe/made_password.rs",
            "cliBinarySha256": self._final["cliBinarySha256"],
            "patchReview": self._final["patchReview"],
            "changedFiles": [
                {"path": name, "beforeSha256": before[name], "afterSha256": after[name]}
                for name in names if before[name] != after[name]
            ],
            "note": "The initial snapshot precedes added regression tests; original failed-command logs retain those tests' results. The final snapshot binds fixes and retained tests together. No signed fix or verification commit exists.",
        }

    def _coverage(self):
        names = re.findall(
            r"^### (CHECK-[A-Z]+-\d{3}) — (.+)$",
            (helpers.PROCEDURE_ROOT / "FULL_AUDIT_GUIDE.md").read_text(),
            re.MULTILINE,
        )
        applicable = {
            "CHECK-SEC-001": "Scoped source trace of pre-secret swap warning and shared generated-password display; broader ownership review not repeated.",
            "CHECK-SEC-005": "Retained pre-fix failures and post-fix swap/private-screen refusal regressions; actual swap paging and Windows VT failure not executed.",
            "CHECK-API-001": "CLI-internal inventory enum and screen capability callers checked; public library/WASM APIs unchanged.",
            "CHECK-UI-003": "Scoped terminal privacy/refusal and cleanup probes only; browser/viewport/accessibility matrix not run.",
            "CHECK-ARC-001": "Swap state belongs to protection code; warning formatting and secret display use their existing owners.",
            "CHECK-ARC-002": "VT capability check shared by preflight and screen entry; no full dead-code review.",
            "CHECK-ARC-003": "Production helper/sink regressions fail before fixes and pass afterward; formatter and Clippy recorded separately.",
            "CHECK-DOC-001": "Unreleased notes describe both corrections; no wider capability-claim review.",
            "CHECK-DOC-003": "Shared-schema validation, 32 dispositions, original IDs, paired report agreement and source/log hashes checked.",
        }
        not_applicable = {
            "CHECK-FUN-003": "MHFE has no BIP85/BIP38/message-signing/Silent Payments feature.",
            "CHECK-FUN-004": "MHFE has no descriptor/Miniscript/multisig/script-policy interpreter.",
            "CHECK-FUN-005": "MHFE has no transaction or PSBT parser/signing coordinator.",
            "CHECK-FUN-007": "MHFE has no discovery/provider/proof/balance service.",
            "CHECK-API-003": "MHFE has no public monetary CSV/XLSX exports.",
        }
        if len(names) != 32:
            raise ValueError("Expected all 32 shared procedure checks")
        result = []
        for check_id, title in names:
            if check_id in applicable:
                outcome, note = "passed", applicable[check_id]
            elif check_id in not_applicable:
                outcome, note = "not-applicable", not_applicable[check_id]
            else:
                outcome = "not-run"
                note = "Outside this two-finding remediation follow-up; AUD-020 baseline is preserved and not counted as new execution."
            result.append({
                "checkId": check_id,
                "category": check_id.split("-")[1],
                "logicalGroup": title,
                "scope": "MHFE native CLI host-protection remediation only",
                "method": "Scoped source review and retained command evidence" if outcome == "passed" else "Disposition only",
                "outcome": outcome,
                "evidence": note,
            })
        return result

    def _remediation(self, binding):
        by_label = {item["label"]: item for item in self._commands}
        details = (
            (FINDING_IDS[0], "Unreadable Linux swap inventory suppresses the secret-memory warning", ("protect.rs", "settings.rs"), ("before-swap", "after-swap", "after-settings", "swap-classification-controls"),
             "SwapInventory::Unavailable preserves a failed read; the settings warning names unknown encryption. A readable empty inventory remains silent. Existing visible plaintext/unknown-device escaping and encrypted/zram classifications remain in the scoped tests.",
             "Missing and directory-valued synthetic inventories and an injected PermissionDenied result are distinguished from a readable empty inventory. Warning strings and visible-area escaping/classification are checked. No actual swap paging, storage read or secret extraction."),
            (FINDING_IDS[1], "Generated password can reach the main Windows console when VT activation fails", ("terminal.rs", "made_password.rs"), ("before-display", "after-display", "after-terminal", "terminal-controls", "terminal-direct"),
             "Shared terminal eligibility now requires VT capability. After acquiring PrivateScreen, the common generated-password sink refuses unless shows_privately() confirms an actual or enclosing private screen, before any password text is written.",
             "Before the patch, the isolated no-terminal regression detected generated-password output; afterward it confirms refusal and no output. Scoped PTY acceptance covers the shared words/check-word/chars display and enclosing flow according to the recorded harness output. Windows VT API failure, console retention and real Windows runtime remain unexecuted."),
        )
        result = []
        for finding_id, title, names, labels, correction, verification in details:
            evidence = [{
                "localEvidence": by_label[label]["localEvidence"],
                "logSha256": by_label[label]["logSha256"],
                "outcome": by_label[label]["outcome"],
                "localOnly": True,
            } for label in labels]
            evidence.extend(item for item in binding["changedFiles"] if Path(item["path"]).name in names)
            result.append({
                "id": finding_id,
                "category": "SEC",
                "title": title,
                "severity": "low",
                "status": "fixed",
                "releaseBlocking": False,
                "fixCommit": None,
                "verificationCommit": None,
                "verifiedWorkingTree": True,
                "correction": correction,
                "verification": verification,
                "evidence": evidence,
                "sourceFingerprint": binding["afterSourceFingerprint"],
                "formalClosure": "Pending a signed fix/verification commit; fixed is a working-tree disposition, not formal verified closure. Original AUD-020 remains open at its reviewed snapshot.",
            })
        return result

    def build(self):
        binding = self._source_binding()
        names = sorted({
            name for command in self._commands
            if command["outcome"] == "passed" for name in command["testNames"]
        })
        if len(names) != 23:
            raise ValueError("Expected 23 distinct passing scoped Rust tests")
        report = {
            "schemaVersion": 1,
            "auditId": "AUD-021",
            "auditNumber": 21,
            "date": self._final["completedUtc"][:10],
            "completedUtc": self._final["completedUtc"],
            "title": "MHFE AUD-020 host-protection remediation follow-up",
            "reviewer": {"name": "Codex remediation coordinator and report reviewer", "model": "gpt-6.1-sol", "reasoningEffort": "ultra"},
            "snapshot": {
                "commit": self._final["head"],
                "commitComplete": True,
                "workingTree": {"state": "dirty", "preExistingStatus": self._initial["preExistingStatus"], "note": "Product fixes and regression tests are uncommitted; pre-existing AUD-020 records are preserved."},
                "sourceFingerprint": binding["afterSourceFingerprint"],
                "artifacts": "Scoped local debug binary/PTY harness only; no release or browser artifact acceptance.",
            },
            "scope": {
                "repository": "https://github.com/hobby-eng/mhfe",
                "mode": "Scoped authorized remediation follow-up, not a new full security scan",
                "findings": list(FINDING_IDS),
                "included": list(PRODUCT_FILES),
                "excluded": ["Algorithm, vectors and public library/WASM/browser APIs", "Fresh full security scan and historical audit conclusions", "Full-cost Argon2, browser suites, canonical/release builds and publication"],
            },
            "procedureHashes": self._baseline["procedureHashes"],
            "environment": {
                "observedVersions": helpers.read_json(EVIDENCE / "environment.log"),
                "localEvidence": "docs/audits/AUD-021-evidence/environment.log",
                "localOnly": True,
                "sha256": helpers.sha256(EVIDENCE / "environment.log"),
                "formatter": "Prettier 3.9.9 from the pinned local package",
            },
            "sourceBinding": binding,
            "originalAudit": {
                "auditId": "AUD-020",
                "commit": self._baseline["snapshot"]["commit"],
                "sourceFingerprint": self._baseline["snapshot"]["sourceFingerprint"],
                "markdownSha256": helpers.sha256(REPORT_ROOT / "AUD-020-2026-10-12.md"),
                "jsonSha256": helpers.sha256(REPORT_ROOT / "AUD-020-2026-10-12.json"),
                "localReviewArtifacts": self._baseline["localReviewArtifacts"],
                "sealedScanBindings": self._final["originalScanBindings"],
                "sealedScanLocalOnly": True,
                "note": "Original findings and sealed scan artifacts are historical evidence, unchanged and not reopened or re-executed.",
            },
            "checks": {"coverageLedger": self._coverage(), "commands": self._commands},
            "targetedTests": {"distinctPassed": len(names), "testNames": names, "note": "Distinct passing Rust test names only; duplicated scoped runs and PTY cases are not added."},
            "findings": [],
            "observations": [],
            "remediation": self._remediation(binding),
            "limitations": [
                "Both fixes and scoped regressions pass in the dirty working tree; no signed fix or verification commit was requested or created. Formal status remains fixed, not verified.",
                "Original three failing assertions remain in before-swap/before-display logs. They were regression runs after tests were added, not new findings or passing baseline checks.",
                "No actual Windows VT activation failure, Windows/macOS runtime, console retention, forced paging, swap storage read or secret extraction was exercised.",
                "Injected PermissionDenied and missing/directory synthetic procfs inventories test error handling, not host encryption itself.",
                "No new full security scan, full-cost Argon2/vector replay, real browser suite, canonical Docker/WASM rebuild, release verification or publication. Algorithm, formats and public APIs did not change.",
                "Terminal control support cannot guarantee privacy on a hostile terminal/host; the new guard proves the program refuses an inactive private-screen state in the tested path.",
                "Local raw evidence is unchanged and ignored. Published home paths are anonymized; local-only artifacts are not public downloadable assets.",
            ],
            "assessment": "Both original Low findings are fixed with passing scoped dirty-source verification. No new finding IDs or release-acceptance claim; signed-commit formal closure remains pending.",
            "reportGenerator": {"path": "docs/audits/AUD-021-harnesses/build_report.py", "sha256": helpers.sha256(Path(__file__))},
        }
        return helpers.public_text(report)

    def _format(self, text, parser):
        package = helpers.read_json(ROOT / "node_modules/prettier/package.json")
        if package["version"] != "3.9.9":
            raise ValueError("Expected pinned Prettier 3.9.9")
        return subprocess.run(
            [str(NODE), str(PRETTIER), "--parser", parser, "--config", str(ROOT / ".prettierrc.json")],
            input=text, text=True, capture_output=True, check=True,
        ).stdout

    def render(self, report):
        binding = report["sourceBinding"]
        lines = [
            f"# AUD-021 — {report['title']}", "", "## Record metadata", "",
            "- **Audit number:** 21.",
            f"- **Completed (UTC):** {report['completedUtc']}.",
            "- **Reviewer:** Codex remediation coordinator and report reviewer.",
            "- **Model:** gpt-6.1-sol (retained client metadata).",
            "- **Reasoning effort:** ultra.",
            f"- **Reviewed commit:** `{report['snapshot']['commit']}`; fixes and tests are uncommitted.",
            "- **Working tree:** Dirty; the initial snapshot preserves pre-existing AUD-020 reports/harnesses and index changes.",
            f"- **Before/after source fingerprints:** `{binding['beforeSourceFingerprint']}` / `{binding['afterSourceFingerprint']}` ({binding['files']} non-audit files; path-sorted file SHA-256 + two spaces + path + LF rows).",
            "- **Artifacts:** Scoped local debug/PTY execution; no browser or release artifact acceptance.",
            "", "## Finding register", "",
            "No new findings. This authorized follow-up retains the original IDs as remediation rows; both remain Low. [AUD-020](AUD-020-2026-10-12.md) remains open at its original snapshot.",
            "", "## Review evidence", "", "### Scope and methodology", "",
            "The scope is AUD-020-SEC001 and AUD-020-SEC002: native pre-secret swap warnings and generated-password display. Production-path regressions were first recorded failing, then replayed after the corrections. Source and command hashes bind the dirty tree. This is a scoped remediation follow-up; the other procedure areas are explicitly dispositioned below.",
            "", "The MHFE algorithm, vectors, encodings, public library/WASM APIs and browser features did not change. Existing AUD-020 and sealed Codex Security scan evidence are retained without rewriting their historical conclusions. No commit, push or release was performed.",
            "", f"Recorded environment: Python {report['environment']['observedVersions']['python']}; {report['environment']['observedVersions']['os']} {report['environment']['observedVersions']['architecture']}; {report['environment']['observedVersions']['rustc']}; Node {report['environment']['observedVersions']['node']}; pinned Prettier 3.9.9. Environment-log SHA-256 (local only): `{report['environment']['sha256']}`. No browser or Windows/macOS runtime was executed.",
            "", "Shared procedure bindings:", "", "| Procedure | SHA-256 |", "| --- | --- |",
        ]
        for name, relative in helpers.PROCEDURES.items():
            lines.append(f"| local-only: `multi-chain-wallet-tools/docs/{relative}` | `{report['procedureHashes'][name]}` |")
        lines += ["", "Source and original-audit bindings:", "", "| Record / source | Before SHA-256 | After SHA-256 |", "| --- | --- | --- |"]
        for item in binding["changedFiles"]:
            lines.append(f"| [{item['path']}](../../{item['path']}) | `{item['beforeSha256']}` | `{item['afterSha256']}` |")
        lines += [
            f"| Initial snapshot (local only) | `{binding['initialSnapshotSha256']}` | — |",
            f"| Final snapshot (local only) | — | `{binding['finalSnapshotSha256']}` |",
            f"| Original AUD-020 Markdown (unchanged) | `{report['originalAudit']['markdownSha256']}` | Same |",
            f"| Original AUD-020 JSON (unchanged) | `{report['originalAudit']['jsonSha256']}` | Same |",
            f"| Product patch (local only) | — | `{binding['patchSha256']}` |",
            f"| Scoped debug CLI (local only) | — | `{binding['cliBinarySha256']}` |",
            "", binding["note"], "",
            f"The local product.patch contains exact `{binding['patchCommand']}` output, with no binary-diff flag. Its hash and the local debug CLI hash are rechecked by the report validator.",
            "", "### Coverage ledger", "",
            "A passed row covers only the named remediation slice. It does not claim the shared procedure's complete runtime matrix or a fresh full scan.",
            "", "| Check ID | Category / logical group | Method | Outcome | Evidence / gap reason |", "| --- | --- | --- | --- | --- |",
        ]
        for item in report["checks"]["coverageLedger"]:
            lines.append(f"| {item['checkId']} | {item['category']} / {helpers.cell(item['logicalGroup'])} | {helpers.cell(item['method'])} | {item['outcome']} | {helpers.cell(item['evidence'])} |")
        lines += ["", "### Checks", "", "| Command | Outcome | Counts / scope | Local-only evidence / SHA-256 |", "| --- | --- | --- | --- |"]
        for item in report["checks"]["commands"]:
            counts = "; ".join(f"{c['passed']} passed, {c['failed']} failed, {c['ignored']} ignored, {c['filteredOut']} filtered" for c in item["counts"]) or "No Rust suite count."
            command = "python3 -B -c (exact multiline argv retained in JSON)" if "\n" in item["command"] else item["command"]
            lines.append(f"| `{helpers.cell(command)}` | {item['outcome']}; exit {item['exitCode']} | {counts} {helpers.cell(item['note'])} | `{item['label']}.log`: `{item['logSha256']}` |")
        lines += [
            "", f"{report['targetedTests']['distinctPassed']} distinct passing Rust test names are retained in JSON. Scoped reruns overlap; their totals are not summed, and terminal-harness cases are separate. Exact UTC times, argv, selected environment, command-record hashes and failures are in the JSON companion.",
            "", "Original failures (preserved; privacy-only path anonymization):", "",
        ]
        for command in report["checks"]["commands"]:
            for diagnostic in command["diagnostics"]:
                lines.append(f"- `{helpers.cell(command['label'])}`: {helpers.cell(diagnostic)}")
        lines += ["", "### Findings", "", "No new defects are assigned in this scoped remediation record.", "", "### Remediation and follow-up", "", "| Finding ID | Status | Fix commit | Verification commit | Evidence |", "| --- | --- | --- | --- | --- |"]
        for item in report["remediation"]:
            lines.append(f"| {item['id']} | fixed | null (uncommitted) | null (uncommitted) | Passing scoped dirty-source verification; source fingerprint `{item['sourceFingerprint']}`. |")
        lines += ["", "`verifiedWorkingTree: true` records passing checks on exact uncommitted source. Formal `verified` status requires a recorded signed fix/verification commit; no such commit exists. This working-tree disposition does not silently close the historical AUD-020 rows."]
        for item in report["remediation"]:
            lines += ["", f"#### {item['id']} — Low — {item['title']}", "", item["correction"], "", item["verification"]]
        lines += ["", "### Informational observations and recommendations", "", "No additional optional hardening or research task was undertaken. Existing AUD-020 recommendations retain their earlier scope.", "", "Original Codex Security review artifacts (local only; historical hashes retained):", "", "| Artifact | SHA-256 |", "| --- | --- |"]
        for item in report["originalAudit"]["localReviewArtifacts"]:
            lines.append(f"| `{item['name']}` | `{item['sha256']}` |")
        lines += ["", "Original sealed scan bindings (local only; rechecked without changing the scan):", "", "| Record | SHA-256 |", "| --- | --- |"]
        for name, value in report["originalAudit"]["sealedScanBindings"].items():
            lines.append(f"| `{name}` | `{value}` |")
        lines += ["", "The independent post-patch diff/caller review reported no concrete bypass or regression; it was source-only, with no additional runtime execution."]
        lines += ["", "### Assessment and limitations", "", report["assessment"], ""]
        lines += [f"- {item}" for item in report["limitations"]]
        lines += ["", f"Report generator: [build_report.py](AUD-021-harnesses/build_report.py), SHA-256 `{report['reportGenerator']['sha256']}`. It reads retained inputs, anonymizes published paths, and does not rewrite raw evidence.", "", f"Machine-readable companion: [{REPORT_STEM}.json]({REPORT_STEM}.json).", ""]
        return self._format("\n".join(lines), "markdown")

    def write(self, report):
        self._json.write_text(self._format(json.dumps(report, indent=2) + "\n", "json"))
        self._md.write_text(self.render(report))

    def validate(self, expected):
        actual = helpers.read_json(self._json)
        helpers.Draft202012Validator(helpers.read_json(helpers.PROCEDURE_ROOT / "audit-report.schema.json")).validate(actual)
        if actual != expected or self._md.read_text() != self.render(expected):
            raise ValueError("Paired report differs from retained evidence")
        if actual["findings"] or [item["id"] for item in actual["remediation"]] != list(FINDING_IDS):
            raise ValueError("Remediation must retain only the two original finding IDs")
        if any(item["status"] != "fixed" or item["fixCommit"] is not None or item["verificationCommit"] is not None for item in actual["remediation"]):
            raise ValueError("Uncommitted fixes cannot claim signed-commit verification")
        for path in (self._json, self._md, Path(__file__).with_name("README.md")):
            if helpers.public_text(path.read_text()) != path.read_text():
                raise ValueError(f"Published home path is not anonymized: {path.name}")
        for target in re.findall(r"\]\(([^)]+)\)", self._md.read_text()):
            if not (self._md.parent / target).resolve().exists():
                raise ValueError(f"Report link does not resolve: {target}")
        index = (REPORT_ROOT / "README.md").read_text()
        if f"[AUD-021]({REPORT_STEM}.md)" not in index:
            raise ValueError("AUD-021 index row missing")
        staged = subprocess.check_output(["git", "diff", "--cached", "--name-only"], cwd=ROOT, text=True).splitlines()
        if any("-evidence/" in path for path in staged):
            raise ValueError("Local evidence must not be staged")
        return {
            "auditId": "AUD-021", "schemaValid": True, "pairAgreement": True,
            "coverageChecks": len(actual["checks"]["coverageLedger"]),
            "newFindings": 0, "originalFindingIds": list(FINDING_IDS),
            "distinctPassingRustTests": actual["targetedTests"]["distinctPassed"],
            "markdownSha256": helpers.sha256(self._md), "jsonSha256": helpers.sha256(self._json),
            "sourceFingerprint": actual["snapshot"]["sourceFingerprint"],
            "sourceAndLogHashesValid": True, "pathsAnonymized": True,
            "evidenceStaged": False, "signedCommitClosure": False,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    owner = RemediationReport()
    report = owner.build()
    if args.write:
        owner.write(report)
    print(json.dumps(owner.validate(report), indent=2))


if __name__ == "__main__":
    main()
