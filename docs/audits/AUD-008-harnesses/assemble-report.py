#!/usr/bin/env python3
"""Assemble AUD-008 from retained specialist contributions and command ledgers."""

import datetime
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
AUDITS = ROOT / "docs/audits"
EVIDENCE = AUDITS / "AUD-008-evidence"
STEM = "audit-08-2026-10-06"


def read(name):
    return json.loads((EVIDENCE / name).read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized(raw, number, severity=None):
    category = raw["category"]
    locations = raw.get("affectedFiles", raw.get("locations", []))
    if not locations and "location" in raw:
        loc = raw["location"]
        locations = [f'{loc["file"]}:{loc["line"]}']
    record = {
        "id": f"AUD-008-{category}{number:03}",
        "category": category,
        "kind": "finding",
        "title": raw.get("title", raw.get("name")),
        "severity": severity or raw["severity"],
        "status": "open",
        "releaseBlocking": raw.get("releaseBlocking", False),
        "releaseBlockingReason": raw.get("releaseBlockingReason", "Bounded defect; no direct secret compromise demonstrated."),
        "affectedFiles": locations,
    }
    for key in ("evidence", "reproduction", "expected", "observed", "impact", "recommendedFix", "requiredVerification"):
        record[key] = raw[key]
    for key in ("prerequisites", "limits", "relatedFindings", "publicInputs"):
        if key in raw:
            record[key] = raw[key]
    return record


def table_text(value):
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=True)
    return str(value).replace("|", "\\|").replace("\n", " ")


def main():
    snapshot = read("snapshot.json")
    roster = [
        ("mhfe_crypto", "Cryptography, mathematics and suite conformance", "crypto-review.json"),
        ("mhfe_secrets", "Native secret lifecycle and adversarial isolation", "secrets-review.json"),
        ("mnc_security", "Independent skeptic, wave challenges and final dispositions", "skeptic-review.json"),
        ("mhfe_qa", "Tests, boundary cases and actual CLI dispatch", "qa-review.json"),
        ("mhfe_documentation", "Specification, documentation and public claims", "documentation-review.json"),
        ("mhfe_browser", "Browser boundaries, worker state and live WASM seams", "browser-independent-review.json"),
        ("mhfe_architecture", "Architecture, duplication and production-path fidelity", "architecture-independent-review.json"),
        ("mhfe_wallet", "Independent wallet/reference and recovery validation", "wallet-independent-review.json"),
        ("mhfe_interface", "Terminal interface, visibility and narrow viewports", "interface-review.json"),
        ("mhfe_devops", "CI, release artifacts, provenance and build composition", "devops-review.json"),
        ("mhfe_research", "Focused compatible improvements and research opportunities", "research-review.json"),
    ]
    contributions = []
    for name, role, file in roster:
        contribution = read(file)
        contributions.append({"agent": name, "role": role, "model": None, "reasoningEffort": None,
                              "localEvidence": file, "sha256": digest(EVIDENCE / file)})
    secrets = read("secrets-review.json")["findings"]
    doc = read("documentation-review.json")["confirmedFindings"]
    ui = read("interface-review.json")
    devops = read("devops-review.json")
    findings = [normalized(secrets[0], 1, "high"), normalized(secrets[1], 2), normalized(secrets[2], 3)]
    findings[0]["severityHistory"] = [{"previous": "medium", "current": "high", "date": "2026-10-06",
                                      "reason": "Independent replay confirms failure of the mandatory tampered-dependency egress boundary; AUDIT_STANDARD includes such isolation failures at high. Native code execution remains an explicit prerequisite."}]
    findings[1]["relatedFindings"] = ["AUD-005-SEC001: same allocation class, a new CLI caller outside the earlier library fix"]
    findings += [normalized(read("wallet-review.json")["confirmedFindings"][0], 1),
                 normalized(read("qa-review.json")["findings"][0], 2)]
    findings += [normalized(item, index + 1) for index, item in enumerate(doc)]
    counts = {"SEC": 3, "FUN": 2, "DOC": 3, "UI": 0, "BLD": 0, "API": 0, "ARC": 0}
    for contribution in (ui, devops):
        for raw in contribution.get("findings", contribution.get("confirmedFindings", [])):
            counts[raw["category"]] += 1
            findings.append(normalized(raw, counts[raw["category"]]))
    split_terminal = next(f for f in findings if f["id"] == "AUD-008-SEC004")
    split_terminal["affectedFiles"] = ["src/bin/mhfe/terminal.rs:317-327", "src/bin/mhfe/terminal.rs:414-437",
                                       "src/bin/mhfe/terminal.rs:467-475", "src/bin/mhfe/new_wallet.rs:54-60",
                                       "src/bin/mhfe/plate_repair.rs:194-222"]
    split_terminal["limits"] = "Only public repair-word output persistence and new's early guard acceptance were executed. Later new/wallet secret-output persistence is a source-traced implication, not a generated-phrase runtime reproduction. No real secret was exposed."
    findings.sort(key=lambda f: (0 if f["severity"] == "high" else 1, f["id"]))

    descriptions = {
        "SEC-001": ("failed", "Source ownership trace, moving allocator and page-map probes; new-wallet and retained-password copies remain.", "secrets-review.json"),
        "SEC-002": ("failed", "Native exact-module io_uring isolation bypass; browser worker/CSP review and real browser package checks pass in their separate trusted scope.", "secrets-review.json; browser-independent-review.json"),
        "SEC-003": ("failed", "Fresh isolated UDP socket sends public loopback marker. Browser assets have no remote loader and real browser request logs are clean.", "skeptic-review.json; real-browsers.log"),
        "SEC-004": ("passed-scoped", "Protocol/domain/packing arithmetic and native/browser primitive reference checks; RNG error propagation traced, no complete upstream primitive audit.", "crypto-review.json; wasm-argon2.log; argon2-full-single.log"),
        "SEC-005": ("failed", "Owned-buffer cleanup, locks and cancellation traced; two bounded native hygiene defects. Compiler/register copies explicitly outside best-effort wiping guarantee.", "secrets-review.json; browser-independent-review.json"),
        "SEC-006": ("passed-scoped", "Offline package has no DOM rendering, storage, clipboard or imported remote resources; consuming application UI is outside this library.", "browser-independent-review.json"),
        "SEC-007": ("passed-scoped", "CLI line/password caps and loopback server limits traced; 14 launcher regressions pass. No fresh flood test or OS-RNG outage injection.", "secrets-review.json; fast-mode-host.log"),
        "FUN-001": ("passed-scoped", "27 published positive transcripts, 648 forward/inverse round records, all BIP39 widths and suite4 geometries; retained Argon2 keys trusted for arithmetic, not recomputed.", "crypto-review.json; crypto-static-protocol.log"),
        "FUN-002": ("failed", "43 literal addresses independently rederived across 12 coins; 138 reference cases plus separate 34-case Dash/tdash challenge. Malformed padding aliases accepted.", "wallet-review.json; wallet-independent-review.json"),
        "FUN-003": ("not-applicable", "No BIP85, BIP38, message signatures or Silent Payments interface in MHFE.", "wallet-independent-review.json"),
        "FUN-004": ("not-applicable", "No descriptor/Miniscript/multisig parser or policy compiler. P2TR address reference arithmetic is covered in FUN-002.", "wallet-review.json"),
        "FUN-005": ("not-applicable", "No transaction/PSBT ingestion, signing or broadcasting in MHFE.", "wallet-independent-review.json"),
        "FUN-006": ("failed", "Suites3/4, source check, repair and password-check formulas/vectors inspected; actual rekey dispatch ignores explicit short length. Repair algorithm conforms; API rejection promise is overstated.", "crypto-review.json; qa-review.json; wallet-independent-review.json"),
        "FUN-007": ("not-applicable", "No discovery scanner, provider requests, proof or balance accounting in MHFE; address search is local deterministic reference matching.", "wallet-independent-review.json"),
        "API-001": ("passed-scoped", "Native C and browser Argon contracts/domain bytes, validated WorkFactor/WordCount and core guards traced; broader source-check widths retained as an unstandardized extension observation.", "crypto-review.json"),
        "API-002": ("passed-scoped", "Actual JS worker state tested with stand-ins, real browsers at reduced cost, fresh WASM callback seams with synthetic engine; each evidence scope stays distinct.", "browser-review.json; browser-independent-review.json"),
        "API-003": ("passed-scoped", "API version7, declared exports and returned JSON checked; no monetary CSV/XLSX/report schema exists.", "browser-independent-review.json; browser-package-node.log"),
        "API-004": ("failed", "Independent word/checksum, repair/password-check and address decoding; equivalent malformed Dash encodings violate validation, one FUN finding only.", "wallet-review.json; wallet-independent-review.json"),
        "BLD-001": ("passed-scoped", "Pinned manifests, feature gates, native and wasm-target clippy, rustdoc, fresh host release and canonical cross-builds; native Windows/macOS/ARM runtime not run here.", "check-release-host.log; devops-review.json"),
        "BLD-002": ("partial", "Library131/CLI78/metadata2+2/doc2 pass; original full script stops at TERM=dumb PTY fixture. Entire unchanged PTY gate separately passes with xterm. User excludes long full vector replays.", "qa-review.json; check-release-host.log; qa-hidden-input-xterm.log"),
        "BLD-003": ("passed-scoped", "Frozen dependency/license/vendor checks, fresh RustSec and npm audits, archive legal-byte checks. Unsigned historical commits are separately retained as a release-preparation policy gap.", "rustsec-host.log; npm-audit-host.log; devops-review.json"),
        "BLD-004": ("passed", "Documented canonical Docker builds with and without cache yield four byte-identical archives; native/browser integrity and test-only engine exclusion gates pass.", "artifacts-compared.json; devops-artifacts.json"),
        "BLD-005": ("partial", "Local workflow/publish/packaging and four artifact contents verified. Signing subgroup fails policy: seven unsigned unreleased commits. Trusted prechecked tagging is an assumption; final notes require preparation. No paid Actions runs dispatched.", "devops-review.json"),
        "UI-001": ("failed", "Actual Linux terminal widths80/60/40 and private-screen descriptors tested; browser integration page runs in Chromium/Firefox. No Windows/macOS GUI or mobile terminal runtime.", "interface-review.json"),
        "UI-002": ("failed", "Menu navigation, cancellation and actual public repair/new dispatch probed; narrow redraw leaves stale selection markers. Existing full hidden-input gate shared.", "interface-review.json; qa-hidden-input-xterm.log"),
        "UI-003": ("failed", "Color/plain help and private-screen visibility reviewed; separate stdout/stderr TTYs reveal missing same-terminal boundary. QR, downloads and application-level accessibility do not exist in MHFE library.", "interface-review.json"),
        "ARC-001": ("passed-scoped", "Core/CLI/native-WASM/worker ownership and all30 error codes traced; no exhaustive resolved import graph.", "architecture-independent-review.json"),
        "ARC-002": ("failed", "CLI duplicate formatter bypasses reserved canonical library formatter; current browser/EFF limits agree. Refer to SEC002 rather than duplicate finding.", "architecture-independent-review.json"),
        "ARC-003": ("passed-scoped", "Active tests and helper dispatch traced; test-only engine remains cfg(test). Library helper coverage explicitly distinguished from CLI dispatch and PTY probes.", "architecture-independent-review.json; qa-review.json"),
        "DOC-001": ("failed", "Current docs and counterpart normative profiles compared; repair guarantee and profile status/passphrase comments require edits.", "documentation-review.json"),
        "DOC-002": ("failed", "11 help commands and16 source links pass; copied package README has broken measurements link. Legal/source notices and public private-reporting flag checked.", "documentation-review.json"),
        "DOC-003": ("partial", "Current report schema, pair, hashes, index and eleven-agent ledger validated separately. Historical AUD007 validator fails owner-authorized workspace AGENTS hash drift; independent evidence/signature recheck passes.", "prior-report-validator.log; prior-evidence-validator.log; report-validation.json"),
    }
    owners = json.loads((AUDITS / "AUD-008-harnesses/coverage-plan.json").read_text())["checks"]
    coverage = [{"checkId": "CHECK-" + key, "primaryOwner": owners["CHECK-" + key], "outcome": value[0],
                 "methodAndLimits": value[1], "localEvidence": value[2]} for key, value in descriptions.items()]
    commands = []
    for path in sorted(EVIDENCE.glob("*.command.json")):
        command = json.loads(path.read_text())
        command.setdefault("logSha256", command.get("logSHA256", command.get("log_sha256")))
        if not command["logSha256"]:
            command["logSha256"] = digest(path.with_name(path.name.removesuffix(".command.json") + ".log"))
            command["metadataLimit"] = "Original supplemental ledger lacks UTC timing/log hash; this hash is computed from retained bytes. Complete fresh wallet-metadata-replay ledgers independently repeat these bounded checks; original evidence was not rewritten."
        commands.append({"localLedger": path.name, **command})
    record = {
        "schemaVersion": 1, "auditId": "AUD-008", "auditNumber": 8, "date": "2026-10-06",
        "title": "Expanded eleven-reviewer pre-release audit of MHFE 0.5.0",
        "completedUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "reviewer": {"name": "Codex coordinator with eleven distinct scoped agents", "model": None, "reasoningEffort": None},
        "reviewerPhases": contributions,
        "finalSkepticReview": {"localEvidence": "final-skeptic-review.json",
                               "sha256": digest(EVIDENCE / "final-skeptic-review.json"),
                               "disposition": "Ten findings accepted with explicit limits; one high isolation blocker, nine low. Earlier BLD candidates reconciled as observations."},
        "snapshot": {"commit": snapshot["mhfe"]["commit"], "commitComplete": False,
                     "workingTree": snapshot["mhfe"]["workingTree"], "sourceFingerprint": snapshot["mhfe"]["sourceFingerprint"],
                     "specificationCommit": snapshot["specification"]["commit"],
                     "specificationSourceFingerprint": snapshot["specification"]["sourceFingerprint"],
                     "localEvidence": "snapshot.json; mhfe-initial.patch; specification-initial.patch"},
        "procedureHashes": read("procedure-hashes.json"),
        "scope": "Pre-release source/security/protocol/recovery/API/CLI/browser/architecture/documentation/dependency/build audit. Review-only; long full Rust and Python Argon2 vector replays explicitly excluded by the owner.",
        "checks": coverage, "executedCommands": commands, "findings": findings, "observations": [],
        "remediation": [{"id": f["id"], "status": "open", "fixCommit": None, "verificationCommit": None,
                         "evidence": "Original baseline reproduction; no remediation authorized in this audit."} for f in findings],
        "artifacts": read("artifacts-compared.json"),
        "optionalImprovements": [
            {"title": "Set a capable TERM in the default PTY fixture while retaining explicit dumb-terminal tests", "reason": "Original check.sh failure is a harness environment issue; unchanged standalone PTY gate and hidden fallback independently pass.", "localEvidence": "qa-review.json"},
            {"title": "Clarify wider source-check predicates as an unstandardized library extension", "reason": "Current profile defines24 words; generic API accepts all entropy widths and returns false for the tested short input. No demonstrated algorithm defect.", "localEvidence": "documentation-review.json"},
            {"title": "Explicitly gate tag publication on the expected branch checks", "reason": "Current trusted-prechecked tagging convention is not automatically enforced. It is an optional policy hardening, not a demonstrated current pipeline violation.", "localEvidence": "devops-review.json"},
            {"title": "Unify canonical CLI phrase formatting and retain cross-layer constant/dispatch regressions", "reason": "Formatter repair belongs to SEC002; broader refactoring and drift checks are optional.", "localEvidence": "architecture-independent-review.json"},
        ],
        "researchOpportunities": read("research-review.json"),
        "specialistObservations": {"browser": read("browser-independent-review.json").get("compilerCopyObservation"),
                                  "devops": devops.get("observations", []), "interface": ui.get("observations", [])},
        "publicationPrerequisites": devops.get("confirmedPolicyPrerequisites", []),
        "limitations": [
            "FAIL for release acceptance: reproduced mandatory Linux egress-isolation failure remains open. This does not demonstrate a cipher break, an existing hostile dependency or stolen funds.",
            "No production/test/fixture/dependency/workflow modifications, commits, pushes, tags, publication or paid CI dispatch in this audit. Existing dirty source and prior audit remedies preserved.",
            "Full-cost Rust and Python suite3/suite4 vector replays excluded by owner. The independent648-round arithmetic review trusts recorded Argon keys; one2GiB native Argon2 reference call and small published browser tags are not a full transcript replay.",
            "Fresh Chromium153.0.8010.12 and Firefox155.0 runtime use reduced Argon2 cost. No full-cost browser operation or native Windows/macOS/ARM runtime; macOS artifacts not locally rebuilt.",
            "Original restricted-sandbox socket/network failures and TERM-dependent full check.sh exit1 retained; successful host/scoped reruns do not rewrite the original full command into PASS.",
            "Best-effort zeroization cannot prove physical erasure or eliminate compiler/register/inactive-stack copies. Browser marker residue is a documented limitation, not a new source-owner wiping defect.",
            "Historical AUD007 full validator still fails authorized workspace instruction hash drift; its separately checked old evidence and signatures remain intact. Old records were not rewritten.",
            "Three early supplemental wallet command records lack UTC timing/log hashes; retained bytes were hashed without rewriting the originals, and cheap fresh replay ledgers now retain complete timing/output. These are repeated evidence, not additional coverage totals.",
            "Exact service model identifier and reasoning effort unavailable; all reviewer fields null. Eleven agents are eleven distinct scoped AI reviews, not eleven external cryptographers or certifications.",
        ],
        "assessment": {"verdict": "FAIL", "releaseReady": False, "reason": "AUD-008-SEC001: mandatory Linux isolation bypass; full release scope also retains explicitly stated execution gaps."},
    }
    (AUDITS / (STEM + ".json")).write_text(json.dumps(record, indent=2) + "\n")
    lines = ["# AUD-008 — Expanded eleven-reviewer pre-release audit of MHFE 0.5.0", "", "## Record metadata", "",
             "- **Audit number:**8; **Completed (UTC):**2026-10-06.",
             "- **Reviewer:**Codex coordinator plus eleven distinct scoped reviewer agents. Exact model and reasoning effort are unknown, recorded as null.",
             f'- **Reviewed commit:**`{record["snapshot"]["commit"]}` on main; actual dirty source reviewed, not a clean-commit claim.',
             f'- **Source fingerprint:**`{record["snapshot"]["sourceFingerprint"]}`; tracked non-audit bytes. Existing wallet/hidden-input/release-note and AUD007 changes preserved.',
             f'- **Counterpart specification:**`{record["snapshot"]["specificationCommit"]}`, fingerprint `{record["snapshot"]["specificationSourceFingerprint"]}`.',
             "- **Artifacts:**four fresh canonical v0.5.0 archives from this modified source; cached/uncached SHA-256 equality. No published-release provenance claimed.",
             "- **Verdict:**FAIL; the mandatory native Linux network boundary is bypassable. Remaining source findings are open. No remediation or publication was performed.",
             "", "### Reviewer phases", "", "| Distinct agent | Assigned scope | Retained contribution SHA-256 (local evidence) |", "| --- | --- | --- |"]
    for phase in contributions:
        lines.append(f'| {phase["agent"]} | {phase["role"]} | `{phase["localEvidence"]}` — `{phase["sha256"]}` |')
    lines += ["", f'Final skeptic contribution (same distinct agent): local `final-skeptic-review.json`, SHA-256 `{record["finalSkepticReview"]["sha256"]}`.']
    lines += ["", "Supplemental wallet/browser/architecture passes by earlier agents reused shared evidence; they do not count as additional reviewers. The skeptic challenged wave evidence and the final register; actual final challenge is retained locally. Heavy execution belonged only to the coordinator, sequentially.", "", "### Procedure binding", ""]
    for path, value in record["procedureHashes"].items():
        lines.append(f"- `{path}` — `{value}`.")
    lines += ["", "## Finding register", "", "| Finding / record ID | Category | Kind | Severity | Recorded status | Release blocking | Title |", "| --- | --- | --- | --- | --- | --- | --- |"]
    for finding in findings:
        lines.append("| " + " | ".join(table_text(finding[k]) for k in ("id", "category", "kind", "severity", "status", "releaseBlocking", "title")) + " |")
    lines += ["", "## Review evidence", "", "### Scope and methodology", "", record["scope"], "",
              "Pinned environment: Linux7.0.0-38 x86_64, Rust/Cargo1.99.0, wasm-bindgen0.2.129, Node26.10.0, Python3.14.4, Emscripten6.0.10, Docker29.8.2, Playwright1.63.0. Canonical recipes use their documented pinned container toolchains. Only public vectors, synthetic passwords and loopback markers were used. No live blockchain queries or secrets were used.", "",
              "Independent arithmetic compared27 positive suite transcripts and648 forward/inverse round records without replaying their Argon2 keys. It also checked two source-check digest vectors, four GF(2^11) generators,16 repair parity vectors and four password-check vectors. Independent BIP39/BIP32/address arithmetic rederived43 literal addresses across12 coins;138 reference cases and a separate34-case Dash/tdash challenge are different scopes, not a combined exhaustive total.", "",
              "Original failed commands remain in the command ledger below. Restricted task sockets prevented some ordinary checks; narrow authorized host reruns are listed separately. The PTY fixture expects a capable terminal: with inherited TERM=dumb check.sh exited1 after unit/static/rustdoc/build passes; the entire unchanged standalone hidden-input gate later passed with TERM=xterm-256color. This is not a newly reproduced product bug and does not change the original command status.", "", "### Coverage ledger", "", "| Check ID | Primary owner | Outcome | Method and limits | Local evidence / reason |", "| --- | --- | --- | --- | --- |"]
    for check in coverage:
        lines.append("| " + " | ".join(table_text(check[k]) for k in ("checkId", "primaryOwner", "outcome", "methodAndLimits", "localEvidence")) + " |")
    lines += ["", "### Checks", "", "Counts are not added across overlapping runs. Host check: library131 pass/1 ignored; CLI78 pass; suite3 metadata2 pass/1 ignored; suite4 metadata2 pass/1 ignored; doctests2 pass. Browser package tags:3 published Argon2 tags per engine. Real browsers:14 assertions per browser per mode,56 total at reduced cost. Launcher host suite:14 pass. One full-size native Argon2 call used the actual2GiB/12passes/4lanes parameters under a3GiB address-space cap, one test thread; passed in7.96s. RustSec:109 crates,0 vulnerabilities,0 warnings, database commit `ef6173cbc5c50ec8166f9a5b28f07834144373ee`. npm:3 development packages,0 vulnerabilities.", "",
              "Every command below has a local-only retained ledger and log. Three early supplemental wallet ledgers lacked UTC times/log hashes; complete fresh wallet-metadata-replay ledgers repeat those bounded checks in seconds, while original bytes remain untouched. Hashes below are checked from the retained logs; missing original timestamps are not fabricated. Exit 1 in a diagnostic often means a confirmed defect, not a suite pass. Initial harness/setup failures remain alongside corrected diagnostics.", "", "| Command / local ledger | Actual exit | Log SHA-256 |", "| --- | --- | --- |"]
    for command in commands:
        cmd = command.get("command", command.get("argv", command.get("args", "See exact ledger")))
        lines.append(f'| {table_text(cmd)} — `{command["localLedger"]}` | {command.get("exitCode", command.get("exit_code", "See ledger"))} | `{command.get("logSha256", command.get("log_sha256", "See ledger"))}` |')
    lines += ["", "### Artifacts and reproducibility", "", "| Fresh canonical archive | SHA-256, cached and uncached equal |", "| --- | --- |"]
    for artifact in record["artifacts"]["archives"]:
        lines.append(f'| `{artifact["archive"]}` | `{artifact["sha256"]}` |')
    lines += ["", "Archives were verified for exact file inventory, licenses/notices, source/build metadata, runtime hashes and absence of the reduced-test engine. Native x86_64 archive executable ran --version. The host release executable is a distinct build (`5318979d30fc20d5fdfe46e7d57e7540fa713f003063f2735b544babb88dc304`); it is not claimed equal to the canonical executable. Both archive sets explicitly report the reviewed HEAD plus modified source. No remote attestation or release signature was created.", "", "### Findings", ""]
    for finding in findings:
        lines += [f'#### {finding["id"]} — {finding["severity"].capitalize()} — {finding["title"]}', "",
                  f'- **Category:**{finding["category"]}; **Status:**open.',
                  f'- **Release blocking:**{str(finding["releaseBlocking"]).lower()}; {finding["releaseBlockingReason"]}',
                  f'- **Affected files and builds:**{table_text(finding["affectedFiles"])}.']
        for label, key in [("Reproduction", "reproduction"), ("Expected behavior", "expected"), ("Observed behavior", "observed"),
                           ("Impact and prerequisites", "impact"), ("Recommended fix", "recommendedFix"), ("Required verification", "requiredVerification")]:
            lines.append(f'- **{label}:**{table_text(finding[key])}')
        lines.append(f'- **Evidence (local only):**{table_text(finding["evidence"])}')
        for label, key in [("Additional prerequisites", "prerequisites"), ("Evidence limits", "limits"), ("Related historical finding", "relatedFindings"), ("Severity disposition", "severityHistory")]:
            if key in finding:
                lines.append(f'- **{label}:**{table_text(finding[key])}')
        lines.append("")
    lines += ["### Remediation and follow-up", "", "| Finding ID | Status | Fix commit | Verification commit | Evidence |", "| --- | --- | --- | --- | --- |"]
    for finding in findings:
        lines.append(f'| {finding["id"]} | open | Not fixed | Not run | Original baseline reproduction |')
    lines += ["", "### Informational observations and recommendations", ""]
    for improvement in record["optionalImprovements"]:
        lines.append(f'- **{improvement["title"]}.** {improvement["reason"]} Local evidence: `{improvement["localEvidence"]}`.')
    lines += ["", "Inactive WASM stack key markers remained after source-level moves in the synthetic-engine probe; password buffers were wiped. The existing SECURITY/API warning excludes compiler/register/stack-copy erasure, so this is a documented limitation rather than an additional source-owned-buffer finding. Per-operation worker termination remains relevant. The original overstrict diagnostic and clarified probe are retained separately.", "",
              "Historical AUD007 validator fails at owner-authorized workspace AGENTS hash drift; its remaining assertions were not executed by that invocation. Separate old evidence hashes and five named SSH signatures passed. No historical record or hash was rewritten.", "", "#### Ranked compatible opportunities", "",
              "The research contribution is retained locally as `research-review.json`; these proposals are not claims of implemented protection, findings or new normative cipher suites.", ""]
    research = record["researchOpportunities"]
    for opportunity in research.get("optionalImprovements", []):
        lines.append(f'- **{opportunity["rank"]}. {opportunity["title"]}** — usefulness {opportunity["usefulness"]}; complexity {opportunity["complexity"]}. {opportunity["proposal"]} Assumptions and proposed tests are retained in the JSON contribution; not implemented.')
    lines += ["", "#### Release-preparation prerequisites", "",
              "Seven of thirty commits since v0.4.0 have no gpgsig header; the other twenty-three present SSH signatures verify against the configured hobby-eng public signer. This signing-policy gap must be resolved by an authorized preparation decision before publication; no history was rewritten. It does not invalidate the reproduced archive bytes. The historical annotated v0.4.0 tag has no signature; this is recorded without implying permission to rewrite a published tag. Final v0.5.0 release notes are intentionally still in unreleased.md and the publishing workflow refuses a tag lacking its version-specific notes.", ""]
    for prerequisite in record["publicationPrerequisites"]:
        lines.append(f'- **{prerequisite["title"]}:** {table_text(prerequisite["observed"])}. {prerequisite["recommendedFix"]}')
    lines += ["", "### Assessment and limitations", ""]
    for limitation in record["limitations"]:
        lines.append("- " + limitation)
    lines += ["", "The JSON companion contains the exact phase records, complete command metadata and artifact hashes. Command logs, patches and specialist contributions under AUD-008-evidence are local only and ignored by Git. The rerunnable scripts under AUD-008-harnesses are audit material; no files were staged or committed. Final record consistency is reported locally in report-validation.json and SHA256SUMS.", ""]
    markdown = "\n".join(lines)
    # Keep generated report labels and numerical prose readable without reformatting
    # any retained specialist harness or evidence.
    markdown = re.sub(r"(\*\*[^\n]*?:\*\*)(?=\S)", r"\1 ", markdown)
    (AUDITS / (STEM + ".md")).write_text(markdown)
    print(json.dumps({"findings": len(findings), "reviewers": len(roster), "coverage": len(coverage), "verdict": "FAIL"}))


if __name__ == "__main__":
    main()
