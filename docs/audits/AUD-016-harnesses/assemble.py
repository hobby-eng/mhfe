#!/usr/bin/env python3
"""Assemble the AUD-016 report from preserved baseline evidence, without running checks."""

import datetime
import hashlib
import json
import re
import shlex
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
AUDITS = ROOT / "docs/audits"
EVIDENCE = AUDITS / "AUD-016-evidence"
HARNESS = AUDITS / "AUD-016-harnesses"
STEM = "audit-16-2026-10-09"


def read(name):
    return json.loads((EVIDENCE / name).read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def redact(value):
    # Published metadata is anonymized; original local evidence is never rewritten.
    if isinstance(value, str):
        return re.sub(r"/home/[a-z_][a-z0-9_-]*", "/home/user", value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, dict):
        return {redact(key): redact(item) for key, item in value.items()}
    return value


def describe(value):
    if isinstance(value, list):
        return "; ".join(describe(item) for item in value)
    if isinstance(value, dict):
        return "; ".join(f"{key}: {describe(item)}" for key, item in value.items())
    return str(value)


def cell(value):
    return describe(value).replace("|", "\\|").replace("\n", "<br>")


def source_link(value):
    match = re.fullmatch(r"([^:]+):(\d+)(?:-\d+)?", value)
    path = match[1] if match else value
    return f"[{value}](../../{path})" if (ROOT / path).is_file() else f"`{value}`"


def local_ref(value):
    match = re.search(r"docs/audits/AUD-016-evidence/([\w.-]+)", value)
    if match:
        name = match[1]
        return f"[local-only {name}](AUD-016-evidence/{name})"
    if value.startswith("docs/audits/AUD-016-harnesses/"):
        return f"[{value.removeprefix('docs/audits/')} ]({value.removeprefix('docs/audits/')})"
    return source_link(value) if re.match(r"(?:src/|web/|scripts/|\.github/)", value) else value


def result_class(label, exit_code):
    harness_errors = {
        "remaining-rust-tests": "Invalid Cargo command combined --test and --doc; corrected separate commands retained.",
        "rustsec-offline": "Unsupported --offline argument to cargo-audit; corrected --no-fetch and fresh database commands retained.",
        "core-address-table": "Reused oracle expected an older fixture location; corrected wrapper retained.",
        "native-dumb-container-existing": "Probe expected an ANSI prompt from TERM=dumb; corrected probe retained.",
        "native-low-memlock-current": "Initial witness assertion aborted; final non-aborting production API witness retained.",
    }
    environment_failures = {
        "cargo-tests": "338 library tests passed; sandbox denies baseline socket probes: CLI 112 pass, 3 fail, 2 ignored. Same compiled CLI tests pass outside sandbox.",
        "fast-mode-script": "10 pass, 4 socket permission errors in sandbox; all 14 pass outside sandbox.",
        "browser-package": "Node subprocess spawnSync is denied by sandbox after earlier checks; unchanged suite passes outside sandbox.",
    }
    if label in harness_errors:
        return "harness-error", harness_errors[label]
    if label in environment_failures:
        return "environment-failure", environment_failures[label]
    if label == "provenance":
        return "incomplete-coverage", "Initial checksum layout assumption checked zero registry sources. Superseded by provenance-archives; no passing provenance claim from this attempt."
    if label == "core-search-inputs":
        return "stale-comment-observation", "90 input cases disagree with a module comment; current API documentation correctly requires explicit ? placeholders. No incorrect recovered phrase established."
    if label == "real-browsers":
        return "failed-mandatory-gate", "17 distinct stale assertions in each of four engine/mode pages, 68 failed assertions total; printed twice, not 136 independent failures. AUD-016-BLD002."
    if label == "no-copies":
        return "failed-mandatory-gate", "Three duplicate test/known-answer blocks of 82, 70 and 69 tokens. AUD-016-BLD001; independently overlaps AUD-017-BLD001."
    if label == "commit-fields":
        return "prior-finding-reproduced", "116 current and 12 specification references resolve; 4 specification commit fields remain missing. Original AUD-015-DOC001."
    if label == "browser-page-protocol":
        return "finding-reproduced", "20 assertions pass and 6 fail: malformed worker envelope handling and explicit-null argument contract. AUD-016-API002/API003."
    if label == "browser-real-wasm-api":
        return "finding-reproduced", "19 pass, 3 fail: null argument error classification; rebuilt real WASM via VM transport, not a real-browser run. AUD-016-API003."
    if label == "core-cancel":
        return "finding-reproduced", "Cancellation callback reached; a running address comparison remains active after a two-second deadline. Bounded watchdog terminates it. AUD-016-API001."
    if label.startswith("native-") and exit_code:
        return "boundary-probe-reproduced", "Public-data negative boundary probe; source/artifact relationship and distinct triggers documented in native-review.json. Expected failing reproduction, not an acceptance pass."
    if label.endswith("-existing-rerun"):
        return "passed-duplicate-attempt", "Repeat of an identical artifact probe; not additional unique test coverage."
    return ("passed" if exit_code == 0 else "failed-unclassified"), "Exact argv, UTC timing, outcome and log SHA-256 retained below."


def main():
    initial = read("snapshot.json")
    final_label = "closeout" if (EVIDENCE / "closeout.json").exists() else "final-baseline"
    final = read(final_label + ".json")
    assert initial["mhfe"]["codeFingerprint"] == final["mhfe"]["codeFingerprint"]
    assert initial["mhfe_spec"]["codeFingerprint"] == final["mhfe_spec"]["codeFingerprint"]
    reviews = {name: read(f"{name}-review.json") for name in ("core", "native", "browser")}
    findings = [finding for review in reviews.values() for finding in review["findings"]]
    for finding in findings:
        finding["kind"] = "finding"
        finding["severity"] = finding["severity"].lower()
    findings.append({
        "id": "AUD-016-BLD001", "category": "BLD", "kind": "finding",
        "title": "Three duplicated test blocks fail the mandatory copy gate",
        "severity": "low", "status": "open", "releaseBlocking": True,
        "releaseBlockingReason": "scripts/check.sh invokes the copy gate; the unchanged baseline fails it. Test-code duplication has bounded maintainability impact, while a red required gate independently blocks release acceptance.",
        "affectedFiles": ["src/rekey/known_answers.rs:145-156", "src/rekey/known_answers.rs:165-176", "src/rehearsal.rs:617-626", "src/rehearsal.rs:644-653", "src/rekey.rs:481-488", "src/rekey.rs:505-512", "scripts/check.sh:32"],
        "reproduction": "node scripts/verify-no-copies.mjs on the captured source. The detector self-test passes separately. No production, test or checker edits were made.",
        "expected": "New tests obey the workspace no-copy rule and the documented mandatory gate passes without weakening coverage.",
        "observed": "Exit 1: known-answer blocks of 82 tokens, rehearsal test blocks of 70 tokens and rekey test blocks of 69 tokens repeat. The log retains all six locations.",
        "impact": "Test setup/assertion maintenance is duplicated and required CI/release verification fails. The duplicates do not establish a production cryptographic defect. Concurrent AUD-017 independently reproduced the same root and assigns Medium; this record rates bounded duplication impact Low and records release blocking separately.",
        "evidence": ["local-only: docs/audits/AUD-016-evidence/no-copies.log", "local-only: docs/audits/AUD-016-evidence/no-copies.command.json", "local-only: docs/audits/AUD-016-evidence/no-copies-self-test.log"],
        "recommendedFix": "Factor common setup/assertion sequences into narrow parameterized test helpers, preserving distinct cases and every assertion. Do not relax the detector or allowlist these copies.",
        "requiredVerification": "Copy detector and detector self-test pass; affected rekey/rehearsal known-answer tests still pass and still reject their negative cases.",
        "relatedFindings": ["AUD-017-BLD001"],
        "concurrentEquivalent": "Both coordinators reproduced and assigned their IDs independently before exchanging finished reports; retain those IDs and repair the shared cause once.",
    })
    browser_gate = next(item for item in findings if item["id"] == "AUD-016-BLD002")
    browser_gate["observed"] = "The completed unchanged verifier exits 1 after 461.11 seconds: Chromium 153.0.8010.12 and Firefox 155.0, standard and fast mode, all four pages. Each has the same 17 distinct failed assertions (68 total). Failure descriptions are printed immediately and again in each page failure list. All 17 were traced to stale expectations for length precedence, extra documented rekey walletCheck fields, callback/refusal timing, case-sensitive messages or scalar error text; no new erroneous recovered entropy or key was established."
    browser_gate["evidenceLogSha256"] = read("real-browsers.command.json")["logSha256"]
    findings.sort(key=lambda item: ({"critical": 0, "high": 1, "medium": 2, "low": 3}[item["severity"]], item["id"]))

    commands = []
    for path in sorted(EVIDENCE.glob("*.command.json")):
        record = json.loads(path.read_text())
        log = EVIDENCE / (record["label"] + ".log")
        assert sha(log) == record["logSha256"], path
        classification, explanation = result_class(record["label"], record["exitCode"])
        commands.append({**record, "classification": classification, "interpretation": explanation,
                         "recordSha256": sha(path), "evidence": f"local-only: docs/audits/AUD-016-evidence/{log.name}"})

    # Every procedure task has a primary owner, expected evidence, and explicit gaps.
    rows = [
        ("SEC", 1, "Threat model and secret ownership", "native", "Source ownership/Debug/redaction and public-data stderr/lock probes", "reviewed-with-findings", "SEC001/SEC002; no real secrets used", "native-fingerprint-redaction-current,native-low-memlock-current-final"),
        ("SEC", 2, "Secret Vault, CSP, sandbox, and transport", "native+browser", "Process isolation source, actual protection tests and browser package security tests", "reviewed", "CLI tests pass outside orchestration sandbox; no host browser UI acceptance", "cli-tests-outside-sandbox,browser-package-outside-sandbox,real-browsers"),
        ("SEC", 3, "Network egress and secret guards", "native+browser", "Secret command isolation, loopback serving, worker request/resource paths", "reviewed", "No new network behavior; hosted third-party browser integration not accepted", "cli-terminal,browser-static-surface,browser-package-outside-sandbox"),
        ("SEC", 4, "Randomness, encryption, and authentication", "core", "RNG/packing/domain separation/Feistel source; independent transcript and profile oracles; engine KATs", "bounded-pass", "27 transcripts use recorded Argon2 keys; full-cost KDF replay not run", "core-transcripts,core-profiles,argon2-wasm,cargo-tests"),
        ("SEC", 5, "Secret lifecycle and exceptional paths", "native+browser", "Zeroizing buffers, exceptional cleanup, caller byte ownership, cancellation and PTY probes", "reviewed-with-findings", "SEC001/SEC002; original SEC002 terminal controls persist; no forensic swap measurement", "browser-worker-cleanup,browser-real-wasm-api,native-path-controls-current"),
        ("SEC", 6, "Browser injection, persistence, and sensitive APIs", "browser", "Trusted action dispatch, persistence/CSP/worker source and hostile envelope tests", "reviewed-with-findings", "Inherited action probes pass; malformed trusted replies API002; no actual malicious production reply", "browser-static-surface,browser-page-protocol,browser-package-outside-sandbox"),
        ("SEC", 7, "Read-only guarantees and availability bounds", "core+native", "Memory/range validation, search bounds, serving deadlines and huge-scope cancellation", "reviewed-with-findings", "API001 cancellation; cgroup v1 ancestor-accounting observation remains source-only", "core-cancel,cli-tests-outside-sandbox,cli-terminal"),
        ("FUN", 1, "BIP39, entropy, and seed interpretation", "core", "Published KATs, normalization, packing, suites and invalid cases", "bounded-pass", "Native, WASM and independent profiles tested; full-cost vectors excluded", "cargo-tests,core-transcripts,core-profiles,vector-fixture-fast-tests"),
        ("FUN", 2, "HD derivation and every coin/profile", "core", "Independent Node oracle for current wallet table and BIP49/84/86 plus negative fixture", "bounded-pass", "43 address fixtures/12 coins plus three Bitcoin published outputs; not exhaustive paths/networks", "core-address-table-r2,core-wallet,browser-real-wasm-api"),
        ("FUN", 3, "BIP85, BIP38, messages, and Silent Payments", "core", "Inventory of supported modules", "not-applicable", "MHFE has none of these features", "source inventory"),
        ("FUN", 4, "Scripts, descriptors, Miniscript, and multisig", "core", "Inventory of wallet reference/output formats", "not-applicable", "No descriptor/Miniscript/multisig feature; supported address encodings covered by FUN002", "source inventory"),
        ("FUN", 5, "Transactions, PSBT version context, and commitments", "core", "Inventory of public API and CLI", "not-applicable", "No transaction/PSBT parsing/signing feature", "source inventory"),
        ("FUN", 6, "Recovery and backup formats", "core+browser", "Rekey, rehearsal, repair cards, hidden/search/wishes, length and wallet-check guards", "reviewed-with-gaps", "Current cryptographic length rules match spec; mandatory browser expectations stale; cross-audit parity observations retained", "core-profiles,cargo-tests,browser-package-outside-sandbox,real-browsers"),
        ("FUN", 7, "Discovery, providers, proofs, and accounting", "core", "Inventory of online integration", "not-applicable", "No provider/discovery/balance/history feature; offline address search covered by FUN002/API002", "source inventory"),
        ("API", 1, "Actual dependency call contracts", "browser+core", "Argon2 engines/FFI, wallet oracle, public JS classes and actual rebuilt WASM", "reviewed-with-findings", "API003 explicit null errors; scalar overflow hypothesis rejected", "argon2-wasm,browser-real-wasm-api,core-wallet"),
        ("API", 2, "Async state, cancellation, and revisions", "browser+core", "Worker ownership/callback/late-message and native cancellation probes", "reviewed-with-findings", "API001/API002; browser worker termination distinct from native thread joining", "browser-page-protocol,browser-worker-cleanup,core-cancel"),
        ("API", 3, "Public export schema and monetary fidelity", "browser", "Keep/result declarations, strict inputs and CLI/browser parity", "reviewed-with-findings", "API003; concurrent AUD017 docs/owner-callback schema observations; no monetary/CSV API", "cli-browser-parity,browser-real-wasm-api,browser-package-outside-sandbox"),
        ("API", 4, "Encoding and import/export interoperability", "core+browser", "UTF8 caller ownership, repair card/codeword oracle, wallet address outputs", "bounded-pass", "No production export formats rewritten; metadata tests are not full-cost replay", "core-profiles,core-address-table-r2,browser-real-wasm-api"),
        ("BLD", 1, "Manifest, flags, and feature composition", "coordinator", "Exact pins/metadata, native+WASM and four independent module builds; copy gate", "failed-required-gate", "BLD001 test copies; detector self-test passes", "no-copies,no-copies-self-test,clippy-native,clippy-wasm,clippy-browser-core,clippy-browser-repair,clippy-browser-passwords,clippy-browser-wallet"),
        ("BLD", 2, "Matrix depth and runtime sampling", "coordinator+browser", "Native/debug/release, package/actual WASM and two-engine/two-mode reduced-cost suite", "failed-required-gate", "BLD002; Windows/macOS/aarch64 not executed; separate module artifacts not all packaged/run", "cargo-tests,build-native,build-wasm,browser-package-outside-sandbox,real-browsers"),
        ("BLD", 3, "Lockfiles, source provenance, and licenses", "coordinator", "Cargo archive and unpacked file comparisons, vendored SHA, licenses and current RustSec DB", "passed-scoped", "25 pins/22 vendor/108 archives/4075 files; 109 lock dependencies no reported advisories; yanked status excluded", "provenance-archives,third-party-licenses,rustsec-current"),
        ("BLD", 4, "Canonical WASM and Docker bytes", "coordinator", "Fresh host WASM+Argon2 build and source/artifact hashes; Docker recipe inspection", "not-run-canonical", "Canonical pinned Docker comparison/rebuild not run; host build is not reproducibility evidence", "build-wasm,artifact-bindings"),
        ("BLD", 5, "Artifacts, CI, and release workflows", "coordinator", "Local artifacts/tag mapping/signature-header and CI release dependency source", "reviewed-with-gaps", "BLD001/BLD002 block acceptance; historical external asset binding original AUD015BLD001 not reverified", "artifact-bindings,cli-version,no-copies,real-browsers"),
        ("UI", 1, "Real files and representative viewports", "native+browser", "Real native PTY and real browser functional fixture", "reviewed-with-gaps", "UI001 wide character cursor; browser fixture is not product viewport/visual host acceptance", "cli-terminal,native-unicode-cursor-current,real-browsers"),
        ("UI", 2, "Navigation, inputs, and state preservation", "native+browser", "Terminal cancellation/startup/refusal, fake-worker questions and malformed results", "reviewed-with-findings", "UI001/API002/API003; external AUD017 CLI parity; no full host navigation sweep", "cli-terminal,browser-page-protocol,browser-worker-cleanup"),
        ("UI", 3, "Secret visibility, help, QR, and accessibility", "native", "Input isolation/hints, public-field redaction, actual lock status and terminal width", "reviewed-with-findings", "SEC001/SEC002/UI001; no QR feature; no full screen-reader/browser accessibility matrix", "native-fingerprint-redaction-current,native-low-memlock-current-final,native-unicode-cursor-current,cli-terminal"),
        ("ARC", 1, "Ownership, imports, and composition seams", "core+browser", "Independent library modules, narrow host traits, front-end logic ownership", "reviewed-with-gaps", "Current browser host package is stale; cross-audit CLI policy/message copies separately referenced", "clippy-browser-core,clippy-browser-repair,clippy-browser-passwords,clippy-browser-wallet,browser-static-surface"),
        ("ARC", 2, "Dead code, duplication, and false positives", "coordinator", "Clippy -Dwarnings, detector self-test and diagnosed detector output", "failed-required-gate", "BLD001 actual test copies; no checker relaxation", "clippy-native,no-copies-self-test,no-copies"),
        ("ARC", 3, "Comments, tests, and production-path fidelity", "coordinator+skeptic", "Independent public probes; diagnose all browser failures and reject unsupported hypotheses", "reviewed-with-findings", "BLD002 stale assertions; explicit-? comment stale; roundtrip alone not counted as oracle", "core-search-inputs,real-browsers,browser-real-wasm-api"),
        ("DOC", 1, "User-facing capability and safety descriptions", "coordinator+browser", "Spec/implementation/readme/release/API contract trace and cross-audit claims challenge", "reviewed-with-gaps", "False lock claim SEC002; concurrent AUD017 documentation/parity records independently source-challenged", "core-review.json,browser-review.json,native-review.json"),
        ("DOC", 2, "Commands, metadata, links, and legal materials", "coordinator", "Rustdoc, documented symbol checks, local links, licenses and command help tests", "passed-scoped", "No complete prose-to-API semantic proof; cross-audit missing prose contracts remain", "rustdoc,documented-symbols,markdown-links,third-party-licenses,cli-tests-outside-sandbox"),
        ("DOC", 3, "Audit records and evidence consistency", "coordinator", "Historical recorded byte hashes/structured commit resolution plus new pair/schema/hash validation", "reviewed-with-findings", "106 previous file hashes bound; original AUD015DOC001 retains four missing spec commit fields", "audit-bindings,commit-fields"),
    ]
    ledger = [{"id": f"CHECK-{cat}-{number:03d}", "category": cat, "logicalGroup": name,
               "scope": "MHFE 0.5.1 dirty source, suites 3/4 and companion specification",
               "primaryOwner": owner, "method": method, "outcome": outcome,
               "evidenceOrGap": gap, "expectedEvidence": evidence.split(","),
               "sourceFingerprint": initial["mhfe"]["codeFingerprint"]}
              for cat, number, name, owner, method, outcome, gap, evidence in rows]

    prior = [
        {"id": "AUD-015-SEC002", "status": "open", "fixCommit": None, "verificationCommit": None,
         "evidence": "Public ESC/control bytes in the parent serve path still reach the missing-checksum diagnostic via path.display(); native-path-controls-current reproduces. Narrow checksum-file control filtering does not cover the entire path. Original low-severity finding retained; no new ID."},
        {"id": "AUD-015-DOC001", "status": "open", "fixCommit": None, "verificationCommit": None,
         "evidence": "Current MHFE history replacements resolve, but 4 structured specification commit fields remain unresolvable (audit02 e87eb5cdbd02b41c15aa512cd32055d56d3bd760; audit08 28e50e049d48cf1d5a8a529380192b6371458a57 in three fields). Existing recorded evidence not rewritten."},
        {"id": "AUD-015-BLD001", "status": "open", "fixCommit": None, "verificationCommit": None,
         "evidence": "Partly addressed: history-rewrite-2026-10-09.md is already committed in reviewed HEAD and local tags match it. Historical external published-asset/provenance bindings were not re-fetched/reverified here; this is an explicit residual acceptance gap, not a newly reproduced artifact defect."},
    ]
    limitations = [
        "Full-scope review with bounded execution; not end-to-end release verification, independent certification, or proof that no defects remain.",
        "Ignored full-size Argon2 and full-cost suite3/suite4 vector replays not run. Reduced-cost encryption checks and independent transcripts trusting published Argon2 keys do not prove production-cost KDF execution.",
        "Canonical reproducible Docker/WASM/native archive build and byte comparison not run. Fresh host artifacts are identified, not declared canonical.",
        "Windows, macOS, aarch64 and separate complete runtime artifacts for every module/feature combination not exercised.",
        "Both real browser engines/modes ran the full functional verifier with its documented reduced-cost wrapper; it fails on stale assertions. Product UI host, representative viewport screenshots and full accessibility acceptance not run.",
        "The multi-chain host still embeds build 6a91d106c1b87634 from abb16671b641378c0fc3c4d855f8d126498e754b, rather than fresh 0ead1c7b89fe6106. Its UI exposes modules, but current-version integration and host regressions remain unaccepted.",
        "Resource guard sums RSS of the launched Linux process group every 250 ms, with 3 GiB/1200s stop thresholds. It is not a hard cgroup cap, omits independent browser groups, and its reported peak is not whole-machine/process-tree peak. Heavy work was serialized; no specified cryptographic parameter was weakened to claim production validation.",
        "No forensic residual-memory or swap-out measurement, malicious emitted production worker reply, wrong accepted secret bytes, or practical secret compromise established by the bounded probes.",
        "Coordinator exact model and actual effort metadata unavailable; user requested ultra. Core reviewer and skeptic record ultra; browser/native retained effort metadata unknown. Client preference is not retroactive evidence of exact service settings.",
        "Historical AUD015 trigger closure is not inferred from passing aggregate tests. Scoped current reproductions and source observations are distinguished, original statuses/records preserved.",
        "Concurrent AUD017 findings are separately attributed; their commands were not executed by this coordinator, and source cross-review is not a fresh runtime replay.",
        "RustSec database was freshly fetched and pinned, but --no-yanked excludes registry yanked-version checks; advisories cannot establish cryptographic safety.",
    ]
    observations = [
        "Current suite/length precedence agrees with the changed companion specification. The prior AUD015FUN001 trigger has a changed contract; do not relabel compliant current cryptographic behavior as the unchanged historical defect.",
        "The module comment in src/search.rs suggests invalid BIP39 words identify missing positions, whereas the supported implementation/API require explicit ? markers. The 90-case comment probe is an observation, not a finding of wrong recovered entropy.",
        "TERM=dumb displays encrypted container words. That alone is not evidence of original mnemonic/password disclosure.",
        "Cgroup-v1 ancestor limit accounting may overestimate spare capacity under sibling use; source-only observation, no native cgroup-v1 execution.",
        "Full vector self-test failure returns vectorsPassed=false without a second sticky lock; current docs require refusal by the host, while startup failure is sticky. No unsupported sticky guarantee finding accepted.",
        "Future research: benchmark cancellation/large scopes and independent production-cost KDF/reproducibility in a separately authorized controlled verification run; no algorithm redesign is recommended from these findings.",
    ]
    report = {
        "schemaVersion": 1, "auditId": "AUD-016", "auditNumber": 16, "date": "2026-10-09",
        "title": "MHFE 0.5.1 full-scope baseline audit with bounded execution",
        "completedUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "reviewer": {"name": "Codex coordinator with core, native and browser reviewers and independent skeptic", "model": None, "reasoningEffort": None},
        "requestedReasoningEffort": "ultra",
        "reviewerPhases": [{"phase": name, **review["reviewer"]} for name, review in reviews.items()] + [{"phase": "skeptic", **read("skeptic-review.json")["reviewer"]}],
        "snapshot": {"commit": initial["mhfe"]["head"], "commitComplete": False,
                     "workingTree": "Pre-existing dirty 0.5.1 tree reviewed in place. HEAD alone does not represent reviewed bytes. No production/test/fixture/dependency/workflow edits, commits or pushes by this audit.",
                     "sourceFingerprint": initial["mhfe"]["codeFingerprint"],
                     "fingerprintDefinition": "SHA-256 of sorted SHA256<two spaces>relativePath<newline> manifest over existing git tracked/nonignored untracked files, excluding docs/audits. Deleted files absent. Initial full fingerprint additionally includes existing audit files and excludes AUD016-owned report/harness/evidence prefixes.",
                     "initialFullSnapshot": initial["mhfe"], "finalFullSnapshot": final["mhfe"],
                     "companionSpecification": initial["mhfe_spec"],
                     "sourceManifest": "local-only: docs/audits/AUD-016-evidence/snapshot-mhfe-code-manifest.txt",
                     "unchangedNonAuditBytes": True, "finalSnapshotLabel": final_label},
        "procedureHashes": read("procedure-hashes.json"),
        "scope": {"projects": ["mhfe", "mhfe_spec"], "version": "0.5.1", "algorithmSuites": [3, 4],
                  "surfaces": ["library encryption/recovery/passwords/repair/wallet", "native CLI and memory/process protections", "WASM modules/worker/page classes", "documentation/specification", "tests/provenance/CI/artifact evidence"],
                  "coordination": "AUD016 reserved first; AUD017 uses separate files, reading/small probes only. Original source bytes unchanged. Coordinator alone serialized builds/heavy checks. Index updated from latest bytes without replacing AUD017 row.",
                  "verificationLevel": "full audit scope, bounded security-sensitive checks; complete release-level procedure not executed"},
        "environment": read("environment.json"), "artifacts": read("source-artifact-bindings.json"),
        "advisories": {"toolVersion": "cargo-audit 0.22.2", "databaseCommit": "7eebec69c352c7191b1f13eb95dd510eeca5d1de", "databaseUpdatedUtc": "2026-10-09T08:12:02Z", "advisoryCount": 1296, "lockDependencies": 109, "vulnerabilities": 0, "warnings": 0, "yankedChecked": False},
        "checks": ledger, "commands": commands, "findings": findings, "observations": [],
        "remediation": [{"id": finding["id"], "status": "open", "fixCommit": None, "verificationCommit": None, "evidence": "Baseline reproduction retained; no remediation was made in this audit."} for finding in findings] + prior,
        "priorFindingAssessment": prior, "untrackedObservations": observations, "limitations": limitations,
        "reviewEvidenceBindings": {path.name: sha(path) for path in sorted(EVIDENCE.glob("*-review.json"))},
        "harnessBindings": {str(path.relative_to(ROOT)): sha(path) for path in sorted(HARNESS.rglob("*")) if path.is_file() and "__pycache__" not in path.parts},
        "reusedIndependentOracles": {str(path.relative_to(ROOT)): sha(path) for path in [AUDITS / "AUD-015-harnesses/r1-crypto/oracle.py", AUDITS / "AUD-015-harnesses/r1-crypto/address-oracle.mjs"] if path.is_file()},
        "referenceSources": ["Companion specification pinned by initial source manifest; public vectors independently checked with retained Python/Node oracles.", "https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki", "https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki", "https://www.rfc-editor.org/rfc/rfc9106"],
        "assessment": {"findings": 8, "medium": 3, "low": 5, "releaseBlockers": ["AUD-016-BLD001", "AUD-016-BLD002"], "newUniqueRelativeToConcurrentAudit": 7, "concurrentEquivalent": "AUD-016-BLD001 / AUD-017-BLD001", "releaseAccepted": False},
    }
    later_snapshot = EVIDENCE / "post-review.json"
    if later_snapshot.exists():
        later = read("post-review.json")["mhfe"]
        before_manifest = dict(line.split("  ", 1)[::-1] for line in (EVIDENCE / f"{final_label}-mhfe-code-manifest.txt").read_text().splitlines())
        after_manifest = dict(line.split("  ", 1)[::-1] for line in (EVIDENCE / "post-review-mhfe-code-manifest.txt").read_text().splitlines())
        changed = [{"path": path, "reviewedSha256": before_manifest.get(path), "laterSha256": after_manifest.get(path)} for path in sorted(before_manifest.keys() | after_manifest.keys()) if before_manifest.get(path) != after_manifest.get(path)]
        report["postReviewSourceChange"] = {"capturedUtc": later["capturedUtc"], "laterSourceFingerprint": later["codeFingerprint"], "changedFiles": changed, "evidence": "local-only: docs/audits/AUD-016-evidence/post-review.json", "interpretation": "Another actor changed source after the baseline closeout snapshot. This audit and the freshly built artifacts remain bound to the earlier reviewed bytes. No remediation or verification claim is made for later changes."}
        if changed:
            report["limitations"].append("After baseline closeout, external edits changed " + ", ".join(item["path"] for item in changed) + ". The report does not audit or verify those later bytes; it preserves the completed earlier baseline and its original findings.")
    cross_paths = sorted(EVIDENCE.glob("cross*-review.json"))
    if cross_paths:
        report["concurrentSourceCrossReview"] = [{"evidence": f"local-only: docs/audits/AUD-016-evidence/{path.name}", "sha256": sha(path), "review": json.loads(path.read_text())} for path in cross_paths]
    other = AUDITS / "audit-17-2026-10-09.json"
    if other.is_file():
        report["concurrentAudit"] = {"auditId": "AUD-017", "reportSha256": sha(other), "findings": [{key: finding[key] for key in ("id", "title", "severity", "status", "releaseBlocking")} for finding in json.loads(other.read_text())["findings"]], "method": "External audit on identical non-audit source. IDs and severities attributed to that report; coordinator did not rerun its commands. Selected core/API/doc findings challenged independently against current source."}
    report = redact(report)
    (AUDITS / (STEM + ".json")).write_text(json.dumps(report, indent=2) + "\n")

    lines = ["# AUD-016 — MHFE 0.5.1 full-scope baseline audit", "",
             "Eight independently reproduced findings: three Medium and five Low, all open. Two mandatory verification gates fail and block release acceptance. One copy-gate finding independently overlaps concurrent AUD-017. No production fix was made. Full-scope review was completed with the execution gaps recorded below; this is not a passing full release verification.", "", "## Record metadata", "",
             "- **Audit number:** 16; completion date 2026-10-09 UTC.",
             f"- **Completed (UTC):** {report['completedUtc']}.",
             "- **Reviewer:** Codex coordinator, three reviewers with distinct scopes, then an independent skeptic.",
             "- **Model:** Unknown exact service identifier.",
             "- **Reasoning effort:** User requested ultra; coordinator actual service metadata unknown. Core reviewer and skeptic record ultra; native/browser retained metadata unknown. No exact setting is inferred retrospectively from the preference.",
             f"- **Reviewed commit:** `{report['snapshot']['commit']}`; dirty working tree, not a complete commit snapshot.",
             f"- **Reviewed source fingerprint:** `{report['snapshot']['sourceFingerprint']}`; non-audit bytes remained identical from initial to final snapshot.",
             f"- **Initial full fingerprint:** `{initial['mhfe']['sourceFingerprint']}` ({initial['mhfe']['files']} files); final `{final['mhfe']['sourceFingerprint']}` ({final['mhfe']['files']} files). Concurrent audit report/harness/index additions explain audit-file changes; non-audit manifests match.",
             f"- **Companion specification:** `{initial['mhfe_spec']['head']}`; full fingerprint `{initial['mhfe_spec']['sourceFingerprint']}`; non-audit fingerprint `{initial['mhfe_spec']['codeFingerprint']}`.",
             "- **Native artifact:** Fresh remapped host build, `target/release/mhfe`, version 0.5.1, SHA-256 `8f114cd22a6aa6d7cfc4df03f65ac6cb526f23d5ff1c21820ac05c3e8914e4a1`.",
             "- **Browser artifact:** Fresh host build `0ead1c7b89fe6106`; `dist/runtime/mhfe.wasm` SHA-256 `804143616f7c9b31709be422639f6d8445c8962af8318b78599ab14d9c3fc895`; module manifest SHA-256 `5b75845049884e03628ba221cfaf43292dfd2a97f1dfd1c9730e6a76ef6b6a25`. Host-built bytes are not a canonical reproducibility result.",
             f"- **Structured companion:** [{STEM}.json]({STEM}.json). [Rerunnable harnesses](AUD-016-harnesses/README.md); command logs/records and snapshots are [local-only evidence](AUD-016-evidence/), ignored by Git.",
             "", "## Finding register", "", "| Finding / record ID | Category | Kind | Severity | Recorded status | Release blocking | Title |", "| --- | --- | --- | --- | --- | --- | --- |"]
    if report.get("postReviewSourceChange", {}).get("changedFiles"):
        change = report["postReviewSourceChange"]
        note = "After baseline closeout, a separate actor changed " + ", ".join(f"`{item['path']}`" for item in change["changedFiles"]) + f" (captured {change['capturedUtc']}; later source fingerprint `{change['laterSourceFingerprint']}`). This report and its freshly built artifacts cover the earlier reviewed bytes; later edits have not received these checks."
        position = lines.index("## Finding register")
        lines[position:position] = [note, ""]
    for finding in findings:
        lines.append(f"| {finding['id']} | {finding['category']} | finding | {finding['severity'].capitalize()} | open | {str(finding['releaseBlocking']).lower()} | {finding['title']} |")
    lines += ["", "## Review evidence", "", "### Scope and methodology", "",
              "Reviewed native library/CLI, suites 3 and 4, containers/hidden data/rekey/rehearsal/search, password/repair/wallet modules, memory/process protections, WASM/worker/page contracts, specification/documentation, dependencies, tests, build and release evidence. Independent roles shared evidence; the skeptic challenged all candidates. Only public vectors and synthetic inputs were used. Baseline production, tests, fixtures, dependencies and workflows were preserved; no commit or push occurred.", "",
              "The shared [procedure](../../../multi-chain-wallet-tools/docs/FULL_AUDIT_GUIDE.md), [standard](../../../multi-chain-wallet-tools/docs/audits/AUDIT_STANDARD.md), [template](../../../multi-chain-wallet-tools/docs/audits/AUDIT_TEMPLATE.md) and [schema](../../../multi-chain-wallet-tools/docs/audit-report.schema.json) were applied without inventing another checklist. SHA-256 bindings:", "", "| Procedure | SHA-256 |", "| --- | --- |"]
    lines += [f"| `{name}` | `{value}` |" for name, value in report["procedureHashes"].items()]
    lines += ["", "Initial/final sorted source manifests hash existing tracked and nonignored untracked files; deleted files are absent. The code fingerprint excludes all `docs/audits/`, and the full snapshot excludes AUD-016-owned report/harness/evidence paths to avoid circular self-binding. Separate harness/log bindings identify this audit's additions. Source byte binding matters because HEAD does not include the extensive pre-existing 0.5.1 changes.", "",
              "Linux x86_64; Rust/Cargo 1.99.0, Node 26.10.0, Python 3.14.4, wasm-bindgen 0.2.129, Emscripten 6.0.10, Prettier 3.9.9, Playwright 1.63.0. Real engines: Chromium 153.0.8010.12 and Firefox 155.0. Toolchain homes follow workspace instructions; exact anonymized environment/argv are in the JSON companion. Heavy work was serialized. The runner's 3 GiB process-group RSS guard is sampled and is not a hard whole-browser/machine memory cap.", "",
              "The retained independent Python oracle checked 17 suite-3 and 10 suite-4 Feistel transcripts using published Argon2 keys, wallet/repair/password profiles and negative cases. A Node oracle checked 43 wallet address fixtures across 12 coins; three published BIP49/84/86 addresses and a corrupted refusal were also checked. Oracle scripts and current fixtures are source-hash bound. Background upstream references are BIP39/BIP32 and RFC 9106; live master URLs are context, not newly content-pinned independent implementations.", "", "### Coverage ledger", "",
              "All 32 stable procedure items have an explicit primary owner, method and evidence/gap. `bounded-pass` and `reviewed` describe the recorded scope and do not imply unexecuted matrix/release acceptance.", "", "| Check ID | Category / logical group | Primary owner / build scope | Method | Outcome | Evidence / gap reason |", "| --- | --- | --- | --- | --- | --- |"]
    for item in ledger:
        lines.append(f"| {item['id']} | {item['category']} / {item['logicalGroup']} | {item['primaryOwner']} / 0.5.1 suites 3/4 | {item['method']} | {item['outcome']} | {item['evidenceOrGap']}; {', '.join(item['expectedEvidence'])} |")
    lines += ["", "### Checks", "",
              "Counts are separate suites, not a sum of overlapping reruns: library **338 passed, 2 ignored**; compiled CLI outside sandbox **115 passed, 2 ignored**; suite-3 fixture metadata **3 passed, 1 ignored**; suite-4 metadata **2 passed, 1 ignored**; doctests **4 passed**; fast-mode script **14 passed** outside sandbox. Native PTY suite, host builds, clippy/format/rustdoc, browser package suite and CLI/browser parity pass in their stated scope. Actual real-browser acceptance fails on **17 distinct assertions in each of four pages (68 total)**. Original sandbox and harness failures are preserved rather than silently replaced.", "",
              "Dependency verification: 25 exact pin declarations, 22 vendored files, 108 cached Cargo archives and 4,075 unpacked source files match recorded bytes. Fresh RustSec database commit `7eebec69c352c7191b1f13eb95dd510eeca5d1de` (updated 2026-10-09T08:12:02Z), 1,296 advisories/109 lock dependencies: no reported vulnerabilities or warnings; yanked checks excluded. Historical bindings: 106 recorded file hashes intact; four unresolved specification commit fields remain.", "",
              "The table retains every command attempt, including setup and errors. Exact complete argv, UTC start/end, environment, exit, process-group RSS and log SHA-256 appear in the JSON companion. Long embedded scripts are represented by their retained command records, not shortened runnable replacements.", "", "| Command label / actual command | Exit / interpretation | Duration (s) | Retained local evidence / SHA-256 |", "| --- | --- | --- | --- |"]
    for command in report["commands"]:
        argv = shlex.join(command["argv"])
        display = argv if len(argv) <= 220 and "\n" not in argv else shlex.join(command["argv"][:2]) + " (complete script/argv in paired JSON)"
        lines.append(f"| `{command['label']}`: `{cell(display)}` | {command['exitCode']} / {command['classification']}: {cell(command['interpretation'])} | {command['seconds']} | [log](AUD-016-evidence/{command['label']}.log), [record](AUD-016-evidence/{command['label']}.command.json); `{command['logSha256']}` |")
    lines += ["", "### Findings", ""]
    for finding in report["findings"]:
        lines += [f"#### {finding['id']} — {finding['severity'].capitalize()} — {finding['title']}", "",
                  f"- **Category:** {finding['category']}.", f"- **Severity:** {finding['severity']}.", "- **Status:** open.",
                  f"- **Release blocking:** {str(finding['releaseBlocking']).lower()}; {finding['releaseBlockingReason']}",
                  "- **Affected files and builds:** " + "; ".join(source_link(value) for value in finding.get("affectedFiles", [])) + "; " + describe(finding.get("affectedBuilds", "native/browser scopes described in reproduction")) + ".",
                  f"- **Reproduction:** {describe(finding['reproduction'])}",
                  f"- **Expected behavior:** {finding['expected']}", f"- **Observed behavior:** {finding['observed']}",
                  f"- **Impact:** {finding['impact']}",
                  "- **Evidence:** " + "; ".join(local_ref(value) for value in finding["evidence"]) + ".",
                  f"- **Recommended fix:** {finding['recommendedFix']}",
                  f"- **Required verification:** {finding['requiredVerification']}", ""]
    lines += ["### Remediation and follow-up", "", "Baseline audit only: no fixes or fix commits. Proposed fixes require their own regression/acceptance evidence and source binding. Original finding IDs remain intact.", "", "| Finding ID | Status | Fix commit | Verification commit | Evidence |", "| --- | --- | --- | --- | --- |"]
    for item in report["remediation"]:
        lines.append(f"| {item['id']} | {item['status']} | Not recorded | Not run | {cell(item['evidence'])} |")
    lines += ["", "The changed specification and current guards address the historical length-detection contract differently; AUD-015-FUN001 is not reissued here. Passing aggregate tests is not a claim that every original AUD-015 trigger has independently been replayed or that uncommitted source fixes have signed fix/verification commits.", "", "### Concurrent AUD-017 reconciliation", "",
              "[AUD-017](audit-17-2026-10-09.md) finished separately on identical non-audit source bytes. Its commands are external evidence, not commands rerun here. The shared copy-gate root is independently named AUD-016-BLD001 and AUD-017-BLD001; repair it once and retain the independently assigned IDs and stated severity rationale. The current cryptographic length guard satisfies the changed specification. The separate reported rekey issue is CLI/library-browser confirmation policy parity; it is not demonstrated acceptance of a 16-bit wallet check as owner confirmation or a built-in-check bypass after `LENGTH_DIFFERS`. Its hypothetical wallet-loss scenario remains a source inference rather than an executed result.", ""]
    if report.get("concurrentAudit"):
        lines += ["| External finding ID | External severity / status | External title |", "| --- | --- | --- |"]
        lines += [f"| {item['id']} | {item['severity']} / {item['status']} | {item['title']} |" for item in report["concurrentAudit"]["findings"]]
    lines += ["", "Selected rekey/secret/API/documentation claims were independently source-challenged after that report completed; local cross-review records and hashes are listed in the JSON companion. External root causes keep their original IDs. Source support for unwiped diagnostic Strings does not measure residual heap bytes. Documentation claims require qualification: BROWSER-PACKAGE already describes decrypt(passphrase)/candidate walletCheck at lines 782–787, and API already describes some Rust fields/owner-24 refusal; missing JavaScript usage/result-shape guidance does not mean complete absence throughout both documents. The public browser client/CLI and hypothetical 24-to-21 rekey were not executed by that report's cited reduced-cost library recovery probe.", "", "### Informational observations and recommendations", ""]
    lines += [f"- {observation}" for observation in report["untrackedObservations"]]
    lines += ["", "### Assessment and limitations", "",
              "Release acceptance is blocked by the two recorded mandatory-gate failures. The scoped known answers and independent oracles did not establish a new algorithm/output mismatch, while reproducible API/secret-boundary/status/display defects remain open. Severity is bounded by actual triggers; no High/Critical direct-compromise finding was established by this review.", ""]
    lines += [f"- {limitation}" for limitation in report["limitations"]]
    (AUDITS / (STEM + ".md")).write_text(redact("\n".join(lines) + "\n"))
    print(f"Assembled {STEM}.md/.json: {len(findings)} findings, {len(ledger)} checks, {len(commands)} command attempts.")


if __name__ == "__main__":
    main()
