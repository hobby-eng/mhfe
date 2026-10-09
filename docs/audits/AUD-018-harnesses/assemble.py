#!/usr/bin/env python3
"""Assemble source-bound AUD-018 release evidence without rerunning product checks."""

import copy
import datetime
import hashlib
import json
import re
from pathlib import Path


class ReportAssembler:
    def __init__(self):
        self._root = Path(__file__).resolve().parents[3]
        self._audits = self._root / "docs/audits"
        self._evidence = self._audits / "AUD-018-evidence"
        self._stem = "audit-18-2026-10-09"

    @staticmethod
    def _sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def _public(value):
        if isinstance(value, str):
            return re.sub(r"/home/[^/\s]+", "/home/user", value)
        if isinstance(value, list):
            return [ReportAssembler._public(item) for item in value]
        if isinstance(value, dict):
            return {key: ReportAssembler._public(item) for key, item in value.items()}
        return value

    def _load(self, name):
        return json.loads((self._evidence / name).read_text())

    def _findings(self):
        previous = {}
        for number in [15, 16, 17]:
            path = self._audits / f"audit-{number:02d}-2026-10-09.json"
            for item in json.loads(path.read_text())["findings"]:
                previous[item["id"]] = item
        host = {
            "id": "AUD-018-BLD001", "category": "BLD", "kind": "finding",
            "title": "The browser host still carries the older MHFE package and recovery schema",
            "severity": "medium", "status": "open", "releaseBlocking": True,
            "releaseBlockingReason": "Workspace policy requires current library/browser behavior and completed handover to multi-chain before release.",
            "affectedFiles": [
                "../multi-chain-wallet-tools/packages/recovery-mhfe-wasm/generated/modules.json",
                "../multi-chain-wallet-tools/packages/recovery-mhfe-wasm/generated/core/client.d.ts",
                "../multi-chain-wallet-tools/packages/recovery-mhfe-wasm/generated/runtime/runtime.js",
                "../multi-chain-wallet-tools/apps/key-derivation/src/ui/recovery-mhfe-decode.ts",
                "../multi-chain-wallet-tools/apps/key-derivation/src/ui/recovery-mhfe-owner-check.ts"],
            "evidence": ["local-only: browser-review.json hostHandover", "local-only: skeptic-review.json decisions", "local-only: metadata-final.json and artifacts.json"],
            "reproduction": "Compare generated/modules.json and current dist/modules.json; trace host decode and owner callbacks against current web/client.d.ts and runtime helpers. No host rebuild is needed to observe these source differences.",
            "expected": "The host consumes the current package/result schema, passes the recovery source-check passphrase, reports walletCheck, and explains the stated-versus-recovered word count to the owner.",
            "observed": "Both packages are unreleased 0.5.1, but the host pins build 6a91d106c1b87634 (base abb16671b641378c0fc3c4d855f8d126498e754b; manifest SHA-256 304993d69a983d232545185fc0e43f447db24403d9c030cc473f07188dbf0913). Fresh host and canonical upstream build is cc38bfadd2bfe9b2. Host decode still reads passesWalletCheckWithoutPassphrase and omits the new recovery passphrase; the owner page has no statedWords handling. Its generated runtime lacks current malformed-envelope/null remediation helpers.",
            "impact": "The workspace release handover is incomplete. The host README declares its package unreleased and its provenance gate refuses that state. A different build ID alone is not a versioning defect. Host rekey auto-selects BuiltInCheck only for builtInCheck, so the old detected kind does not establish exposure of the AUD-017-FUN001 bypass in this HTML. No published vulnerable host, wrong cryptographic output, or failed host build is demonstrated.",
            "recommendedFix": "Hand over the current verified package with its provenance, update the host fields and source-check passphrase forwarding, and show statedWords where a recovered length differs.",
            "requiredVerification": "Run the host provenance/schema checks and MHFE browser regressions in both editions and both engines where present, including owner refusal, contradictory lengths, passphrase-aware source-check outcomes and malformed input cleanup.",
            "relatedFindings": ["AUD-017-API001", "AUD-017-DOC002", "AUD-016-API002", "AUD-016-API003"],
            "newInThisAudit": True}
        doc = copy.deepcopy(previous["AUD-015-DOC001"])
        doc.update({"status": "open", "releaseBlocking": True, "newInThisAudit": False,
                    "affectedFiles": ["docs/audits/audit-02-2026-09-22.json", "docs/audits/audit-08-2026-10-06.json"],
                    "releaseBlockingReason": "Publishing the rewritten historical audit records with unresolved ordinary source bindings, per the original finding; not a current cryptographic-output failure.",
                    "evidence": ["local-only: core-record-fields.log", "local-only: core-record-prose.log", "local-only: skeptic-review.json"],
                    "reproduction": "Run the retained record_commit_fields.py and resolve the reported historical specification commits in both authoritative repositories. Classify foreign database/compiler commits separately.",
                    "observed": "Exactly four historical specification fields remain unresolved: AUD-002 /snapshot/companionSpecification/commit is e87eb5cdbd02b41c15aa512cd32055d56d3bd760; AUD-008 /snapshot/specificationCommit, /researchOpportunities/snapshot/specificationCommit and /remediationVerification/snapshot/specification/commit are 28e50e049d48cf1d5a8a529380192b6371458a57. Existing privacy maps do not explain these specification identities. The fifth raw structured failure is an external RustSec database identity, not another source-binding defect.",
                    "impact": "These four companion-specification source bindings in AUD-002/AUD-008 cannot be resolved in the authoritative checkouts or explained by their retained privacy mappings. This limits reproducibility of those historical reviewed-source identities; it does not invalidate every audit or demonstrate a current encryption-output defect.",
                    "recommendedFix": "Recover a trustworthy old-to-new specification mapping or explicitly annotate unavailable historical source identities and their evidence limits. Update their structured and prose bindings consistently; do not invent replacement commits.",
                    "requiredVerification": "Resolve or explicitly classify all repository source-commit fields, validate the Markdown/JSON pairs and retained hash bindings, and retain external/history explanations without pretending checks were rerun."})
        ui = copy.deepcopy(previous["AUD-016-UI001"])
        ui.update({"status": "open", "releaseBlocking": False, "newInThisAudit": False,
                   "affectedFiles": ["src/bin/mhfe/typed_line.rs:78", "src/bin/mhfe/typed_line.rs:210"],
                   "evidence": ["local-only: native-unicode-original.log", "local-only: native-unicode-rocket.log", "src/bin/mhfe/typed_line.rs:210"],
                   "reproduction": "Run the retained native verify-boundaries.py unicode-original and unicode-rocket probes against the fresh binary in a bounded Linux PTY. Both cancel without completing a KDF.",
                   "expected": "Visible password editing places the cursor at column 23 after the wide character in the tested line.",
                   "observed": "Original U+754C passes. U+1F680 is absent from the manual wide-character table: expected column 23, observed 22; host wcwidth is 2. Terminal settings are restored on cancellation.",
                   "impact": "Incorrect display/cursor editing for omitted wide characters. No changed password/KDF bytes, truncation, ciphertext defect or secret disclosure was observed.",
                   "recommendedFix": "Use a complete maintained width policy for supported terminal conventions and cover omitted wide characters, combining marks and wrapping.",
                   "requiredVerification": "Retain the original CJK case and add the rocket and broader wide/combining/wrap regressions on the supported terminal platforms."})
        findings = [host, doc, ui]
        fallback_path = self._evidence / "native-python-controls.json"
        if fallback_path.exists():
            fallback = self._load(fallback_path.name)
            if fallback.get("currentTriggerPresent"):
                item = copy.deepcopy(previous["AUD-015-SEC002"])
                item.update({"status": "open", "releaseBlocking": False, "newInThisAudit": False,
                             "affectedFiles": ["packaging/mhfe-fast-mode.py:208", "packaging/mhfe-fast-mode.py:247", "packaging/mhfe-fast-mode.py:293", "dist/core/mhfe-fast-mode.py", "scripts/build-wasm.sh:99"],
                             "releaseBlockingReason": "Low public-metadata diagnostic defect. Tested refusals occur before listener creation; no secret was handled or disclosure observed. The repaired Rust variant is recorded separately.",
                             "evidence": ["local-only: native-python-controls.json", "local-only: native-path-controls.log", "packaging/mhfe-fast-mode.py"],
                             "reproduction": fallback.get("reproduction", "Run the retained bounded Python fallback control-path probe; capture diagnostics as bytes."),
                             "observed": fallback.get("observed", "The Rust server now escapes path controls, but the shipped Python fast-mode helper still writes raw path controls in a refusal diagnostic."),
                             "impact": "Terminal-control injection from attacker-controlled public path/checksum metadata in the fallback helper. This is incomplete remediation of the existing finding, not evidence of intentionally malicious code.",
                             "recommendedFix": "Apply the same control escaping and checksum-name validation to the Python fallback, with one source of each rule and a targeted negative regression.",
                             "requiredVerification": "Test public parent-path and checksum-name control sequences in both Rust and Python serving helpers, capture raw diagnostics safely, and ensure invalid paths are refused before serving."})
                findings.insert(2, item)
        return findings, previous

    def _checks(self, findings):
        # The initial imported plan is retained. This final ledger binds the actual AUD-018 bytes.
        rows = self._load("coverage-plan.json")
        evidence = {
            "SEC-001": ("passed", "native-fingerprint; native-low-memlock-final; native malicious review", "Public wrong-field redaction, representative input locks and secret ownership; no forensic erasure claim."),
            "SEC-002": ("passed", "release-check; real-browsers; native-path-controls", "Actual process isolation/PTY protections and package CSP checks; OS/platform limits remain."),
            "SEC-003": ("passed", "native-malicious-review.json; browser-malicious-review.json; supply-chain review", "Trace all scoped network/command sinks; expected local serving and build downloads classified."),
            "SEC-004": ("passed", "release-check; core-source-identity; core-review.json", "Engine KATs and reduced-cost checks passed; 12 core crypto/dependency files unchanged; full-cost replay owner-excluded."),
            "SEC-005": ("passed", "browser-worker-cleanup-bounded; native-cli-static; native review", "Cleanup and exceptional ownership paths covered; JavaScript GC and physical allocator/swap erasure not certified."),
            "SEC-006": ("passed", "browser-page-protocol-bounded; release-check; browser malicious review", "Malformed replies and explicit-null refusal/cleanup passed; no confirmed hidden persistence or exfiltration found in reviewed source."),
            "SEC-007": ("passed", "core-native-cancel; release-check; cgroup witness", "Huge-scope native cancellation returns within 2s; kernel heavy-work limits enforced, no cryptographic parameter reductions."),
            "FUN-001": ("passed", "release-check; core-source-identity", "Current BIP39/packing known-answer, metadata and negative tests; full-cost suite replay excluded by owner."),
            "FUN-002": ("passed", "release-check; core-review.json", "Current wallet known answers and CLI/browser parity pass; earlier independent oracle retained, not rerun or claimed fresh."),
            "FUN-003": ("not-applicable", "Source/API inventory", "MHFE has no BIP85, BIP38, message-signing or Silent Payments feature."),
            "FUN-004": ("not-applicable", "Source/API inventory", "MHFE has no descriptor/Miniscript/multisig feature; supported address encodings belong to FUN002."),
            "FUN-005": ("not-applicable", "Source/API inventory", "MHFE has no transaction/PSBT parsing or signing feature."),
            "FUN-006": ("passed", "release-check; real-browsers; core/browser/native reviews", "Rekey recovery-state reuse, length/refusal rules, repair/search and browser owner schema covered in current MHFE package; host handover tracked separately."),
            "FUN-007": ("not-applicable", "Source/API inventory", "MHFE has no network provider/discovery/balance/history feature; offline address search is covered separately."),
            "API-001": ("passed", "release-check; real-browsers; browser-page-protocol-bounded", "Actual rebuilt WASM/Argon2 bindings and strict optional-secret contracts; synthetic transport probe complements real browsers."),
            "API-002": ("passed", "core-native-cancel; browser-page-protocol-bounded; browser-worker-cleanup-bounded", "Cancellation, callbacks, malformed envelopes, late-message and operation-slot cleanup; no single-derivation preemption claim."),
            "API-003": ("passed", "release-check; real-browsers; browser-review.json", "Current walletCheck/statedWords/otherLengths declarations and serialization agree with tested upstream contracts; host gap has its own finding."),
            "API-004": ("passed", "release-check; real-browsers", "Caller byte ownership, UTF-8 refusals, repair and wallet output known answers/interop; full-size vectors excluded."),
            "BLD-001": ("passed", "release-check; format-check; core source review", "Exact pins, native/WASM/four-module clippy and actual copy gate pass; checker was not weakened."),
            "BLD-002": ("failed", "real-browsers; canonical-build; browser/skeptic source traces", "Upstream both-engine/both-mode matrix passes; required HTML handover remains stale (AUD-018-BLD001). Cross-target compilation is not target runtime acceptance."),
            "BLD-003": ("passed", "provenance; rustsec-current; supply-chain; shim-review.json", "22 vendored files, 25 pins, 108 Cargo archives/4075 unpacked files match; current RustSec clean; npm archive bytes match with generated shims separately reviewed."),
            "BLD-004": ("passed", "canonical-build; canonical-artifacts; metadata-final", "One canonical build and four archive checksum/license/source bindings pass. Host/canonical WASM and manifest match; native differs. No second uncached reproducibility proof."),
            "BLD-005": ("passed", "canonical-artifacts; core-review.json; closure-matrix.json", "CI release dependency now covers all tagged checks; local map/annotated-tag identities match. Dirty fixes lack signed release commit; historical external assets/signature trust unexecuted."),
            "UI-001": ("failed", "native-unicode-original; native-unicode-rocket; real-browsers", "Original CJK cursor passes; rocket cursor remains one column short (AUD-016-UI001). Browser fixture is functional, not full host visual acceptance."),
            "UI-002": ("passed", "release-check; native-cli-options; native-cli-static; browser protocol", "CLI options/refusals and recovery-state reuse covered; no complete host navigation sweep."),
            "UI-003": ("passed", "native-fingerprint; native-low-memlock-final; release-check", "Actual lock warnings/redaction/help verified in available PTY; full screen-reader/terminal matrix not run."),
            "ARC-001": ("passed", "release-check; native-cli-static; core/browser source reviews", "Independent library modules and narrow interfaces build; CLI policy delegates to library. Host artifact handover separately failed."),
            "ARC-002": ("passed", "release-check; native-cli-static; native-scan-gap-static", "Actual copy gate/clippy and shared message/scan-gap definitions pass; no assertion removal to obtain green."),
            "ARC-003": ("passed", "real-browsers; core-native-cancel; skeptic-review.json", "Negative assertions retained/expanded; original probes reviewed and false positives classified; round trips alone not treated as independent proof."),
            "DOC-001": ("passed", "core-review.json; closure-matrix.json; browser/native reviews", "Current MHFE source-check, rekey, lock and browser result wording trace agrees; host corrected-length presentation remains BLD001."),
            "DOC-002": ("passed", "core-doc-links; core-doc-symbols; release-check; canonical-artifacts", "15 Markdown files/0 link-list failures, 0 unknown documented symbols; Rustdoc/license/help and archive legal bytes pass."),
            "DOC-003": ("failed", "core-record-fields; core-record-prose; skeptic-review.json; report validation", "Four historical specification source bindings still unresolved (AUD-015-DOC001); external/hash scan false positives classified; new report pair validated separately.")}
        fallback = any(item["id"] == "AUD-015-SEC002" for item in findings)
        if fallback:
            evidence["SEC-002"] = ("failed", "native-path-controls; native-python-controls.json; release-check", "Rust process/server boundaries pass, but Python fallback retains original terminal-control diagnostic injection (AUD-015-SEC002).")
        for row in rows:
            key = row["id"].removeprefix("CHECK-")
            outcome, names, explanation = evidence[key]
            row.update({"scope": "Current MHFE 0.5.1 source and specification; MHFE-specific HTML host handover",
                        "outcome": outcome, "method": explanation, "expectedEvidence": names.split("; "),
                        "evidenceOrGap": explanation, "sourceFingerprint": self._load("snapshot.json")["mhfe"]["codeFingerprint"]})
        return rows

    def _remediation(self, previous, findings):
        evidence_by_id = {}
        native = self._load("native-review.json")
        for identifier, item in native["originalFindingAssessments"].items():
            evidence_by_id[identifier] = {"currentTriggerStatus": item.get("partialFix", "absent in assigned source/runtime scope"),
                                          "evidence": item.get("evidence", []), "workingTreeVerification": item.get("verification", "")}
        for item in self._load("browser-review.json")["originalFindings"]:
            evidence_by_id[item["id"]] = {"currentTriggerStatus": "absent in fresh upstream package and completed native browser matrix",
                                          "evidence": ["local-only: release-check.log", "local-only: real-browsers.log", "local-only: browser-review.json"],
                                          "workingTreeVerification": item["basis"]}
        for item in self._load("core-review.json")["originalFindings"]:
            evidence_by_id.setdefault(item["id"], {"currentTriggerStatus": item["currentTriggerStatus"],
                                                   "evidence": ["local-only: core-review.json"], "workingTreeVerification": item["reason"]})
        evidence_by_id["AUD-016-BLD001"] = {"currentTriggerStatus": "absent", "evidence": ["local-only: release-check.log"], "workingTreeVerification": "Actual 50-token copy gate passes; all three diagnosed duplicate test blocks are refactored; no checker relaxation."}
        evidence_by_id["AUD-017-BLD001"] = dict(evidence_by_id["AUD-016-BLD001"])
        evidence_by_id["AUD-017-BLD002"] = {"currentTriggerStatus": "absent in the documented claim", "evidence": ["local-only: closure-matrix.json", "packaging/Dockerfile.reproducible:91"], "workingTreeVerification": "The comment now accurately says some checks; this does not claim that the container gained all omitted gates. Release publishing depends on the full called CI workflow."}
        for item in findings:
            if item["id"] != "AUD-018-BLD001":
                evidence_by_id[item["id"]] = {"currentTriggerStatus": "present; incomplete remediation", "evidence": item["evidence"], "workingTreeVerification": item["observed"]}
        ids = [key for key in previous if key.startswith(("AUD-016-", "AUD-017-"))]
        ids += ["AUD-015-SEC002", "AUD-015-DOC001", "AUD-015-BLD001"]
        rows = []
        for identifier in ids:
            detail = evidence_by_id[identifier]
            rows.append({"id": identifier, "status": "open", "fixCommit": None, "verificationCommit": None,
                         **detail, "formalCommitClosure": "Not closed at a recorded signed fix/verification commit; dirty-tree source/runtime evidence is recorded separately."})
        return rows

    def assemble(self):
        snapshot = self._load("snapshot.json")
        final = self._load("closeout-final.json")
        for name in ["mhfe", "mhfe_spec"]:
            assert snapshot[name]["codeFingerprint"] == final[name]["codeFingerprint"]
        required = ["native-malicious-review.json", "browser-malicious-review.json", "shim-review.json", "supply-chain-review.json"]
        for name in required:
            assert (self._evidence / name).is_file(), name
        findings, previous = self._findings()
        commands = []
        classifications = {
            "browser-page-protocol": "environment-refusal-no-product-probe",
            "docker-cgroup-probe": "harness-environment-cgroup-files-hidden",
            "native-low-memlock": "harness-input-option-error-corrected-retained",
            "native-low-memlock-rerun": "harness-summary-timing-expectation-error-corrected-retained",
            "native-unicode-rocket": "confirmed-original-AUD-016-UI001-residual",
            "core-record-fields": "confirmed-original-AUD-015-DOC001-plus-one-external-false-positive",
            "core-record-prose": "historical-and-external-hash-candidates-classified",
            "supply-chain": "strict-inventory-extra-generated-shims-classified-by-independent-review",
            "canonical-uncached": "harness-output-name-refused-before-Docker",
            "canonical-uncached-final": "required-uncached-build-failed-or-resource-stopped",
            "canonical-compare": "canonical-byte-comparison-failed"}
        for path in sorted(self._evidence.glob("*.command.json")):
            item = json.loads(path.read_text())
            item["recordSha256"] = self._sha(path)
            item["classification"] = "passed" if item["exitCode"] == 0 else classifications.get(item["label"], "failed-unclassified")
            assert item["classification"] != "failed-unclassified", item["label"]
            commands.append(item)
        metadata = self._load("metadata-final.json")
        artifact = self._load("artifacts.json")
        comparison_path = self._evidence / "canonical-comparison.json"
        comparison = self._load(comparison_path.name) if comparison_path.exists() else None
        reproducibility_passed = bool(comparison and comparison["passed"])
        uncached_log = (self._evidence / "canonical-uncached-final.log").read_text()
        uncached_peak = re.findall(r"^MemoryPeak=(\d+)$", uncached_log, re.M)
        limits = [
            "Full-cost suite 3/4 and independent Argon2 vector replays excluded explicitly by the owner, who states they were just checked; no fresh replay result or independence claim.",
            "The documented cached/uncached archive comparison is recorded separately. Host/container WASM and manifest are equal, native binaries differ; the precise host-versus-container native byte difference was not localized. Successful canonical equality does not require a host native compiler to produce canonical bytes.",
            "Windows/aarch64 cross-target builds and clippy passed in the container, but Windows/macOS/aarch64 native runtime and macOS archive builds were not executed locally. No paid CI dispatched.",
            "The current fixes are dirty source, not a clean signed/tagged release commit. HEAD alone does not identify checked bytes. No commit, push, tag, release, signature or publication created.",
            "Host integration inspected read-only; no host build, browser regression matrix, accessibility or full visual terminal acceptance performed.",
            "Security source review and package byte comparisons found no confirmed malicious insertion in their recorded scope; they cannot certify the existing OS, firmware, browser/toolchain executables, account state or absence of a physical/local compromise.",
            "No pre-incident independent trusted backup was supplied. Local Git/lock/test baselines can share a compromised origin. Upstream pinned packages are not each fully audited for deliberate upstream malice.",
            "No physical heap/swap/allocator erasure or timing-side-channel proof; JavaScript garbage collection prevents deterministic complete secret erasure.",
            "Old external v0.3.0-v0.5.0 release asset attestations, trusted signature identity, publication of the history map and original-to-rewritten byte equivalence not independently reverified.",
            "Bounded native cancellation does not promise interruption inside PBKDF2 or a single key/address derivation. Memory locking remains best effort, warning after actual accepted input; no swap write measured."]
        own = self._audits / "AUD-018-harnesses"
        harnesses = {str(path.relative_to(self._root)): self._sha(path) for path in sorted(own.rglob("*")) if path.is_file() and "__pycache__" not in path.parts}
        reused = ["docs/audits/AUD-016-harnesses/run.py", "docs/audits/AUD-016-harnesses/provenance.py",
                  "docs/audits/AUD-016-harnesses/core/public_probe.rs", "docs/audits/AUD-016-harnesses/core/cancel_watchdog.py",
                  "docs/audits/AUD-016-harnesses/browser/page-protocol.mjs", "docs/audits/AUD-016-harnesses/browser/worker-cleanup.mjs",
                  "docs/audits/AUD-015-harnesses/r5-build-docs/record_commit_fields.py",
                  "docs/audits/AUD-015-harnesses/r5-build-docs/documented_symbols.py",
                  "docs/audits/AUD-015-harnesses/r5-build-docs/markdown_links_lists.py",
                  "docs/audits/AUD-017-harnesses/r4-build-docs/record_commit_prose.py"]
        reused = {name: self._sha(self._root / name) for name in reused}
        evidence_names = required + ["snapshot.json", "final.json", "closeout.json", "closeout-final.json", "owner-scope.json", "procedure-hashes.json", "coverage-plan.json", "metadata.json", "metadata-final.json", "artifacts.json", "core-review.json", "browser-review.json", "native-review.json", "native-review-before-malicious.json", "skeptic-review.json", "closure-matrix.json", "supply-chain.json", "build-environment-boundary.json"]
        if (self._evidence / "native-python-controls.json").exists():
            evidence_names.append("native-python-controls.json")
        evidence_names.append("canonical-wrapper-cached.txt")
        if comparison:
            evidence_names.append("canonical-comparison.json")
        if (self._evidence / "final-skeptic.json").exists():
            evidence_names.append("final-skeptic.json")
        checks = self._checks(findings)
        canonical_check = next(row for row in checks if row["id"] == "CHECK-BLD-004")
        canonical_check.update({"outcome": "passed" if reproducibility_passed else "blocked",
                                "method": "Prescribed cached and REPRODUCIBLE_NO_CACHE=1 canonical builds, per-file checksum/license/source checks and exact archive byte comparison.",
                                "expectedEvidence": ["canonical-build", "canonical-uncached-final", "canonical-artifacts", "canonical-compare"],
                                "evidenceOrGap": "All four canonical archives and checksum files match between the two builds." if reproducibility_passed else "Required uncached comparison did not complete/pass; no complete reproducibility claim."})
        artifact_hashes = {name: value["sha256"] for name, value in metadata["artifacts"].items()}
        if comparison:
            artifact_hashes.update({"canonical-output-aud018_uncached/release/" + row["name"]: row["uncached"]["sha256"] for row in comparison["archives"]})
        report = {
            "schemaVersion": 1, "auditId": "AUD-018", "auditNumber": 18, "date": "2026-10-09",
            "title": "MHFE 0.5.1 pre-release verification and remediation follow-up",
            "completedUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "reviewer": {"name": "Codex coordinator and three scoped reviewers", "model": None, "reasoningEffort": None},
            "reviewerPhases": [
                {"name": "coordinator", "model": None, "reasoningEffort": None, "scope": "Build/release evidence, dependency provenance, final ledger and source binding"},
                {"name": "core", "model": None, "reasoningEffort": None, "scope": "Core correctness/spec/docs, independent skeptic, closure matrix and tooling shims"},
                {"name": "native", "model": None, "reasoningEffort": None, "scope": "Native/CLI source, fresh public PTY boundaries and malicious native-code trace"},
                {"name": "browser", "model": None, "reasoningEffort": None, "scope": "WASM/JS API protocols, package/host handover and malicious browser-code trace"}],
            "metadataNote": "Exact service model and actual reasoning setting are unavailable; prior user request for ultra is not substituted for measured phase metadata.",
            "snapshot": {"commit": snapshot["mhfe"]["head"], "commitComplete": False,
                         "workingTree": snapshot["mhfe"]["status"], "sourceFingerprint": snapshot["mhfe"]["sourceFingerprint"],
                         "nonAuditSourceFingerprint": snapshot["mhfe"]["codeFingerprint"],
                         "companionSpecification": snapshot["mhfe_spec"], "finalSnapshotLabel": "closeout-final",
                         "initialUtc": snapshot["mhfe"]["capturedUtc"], "finalUtc": final["mhfe"]["capturedUtc"],
                         "nonAuditSourceUnchanged": True,
                         "finalFullFingerprint": final["mhfe"]["sourceFingerprint"],
                         "fullManifestChangeReason": "Only the audit index changed outside the excluded own AUD-018 paths; non-audit code bytes are identical."},
            "scope": {"request": "Explicit pre-release verification after remediation, plus requested parallel malicious-code/tampering review.",
                      "tools": "MHFE library, CLI, WASM and browser package; companion MHFE specification; MHFE-specific multi-chain host handover read-only.",
                      "ownerExclusions": self._load("owner-scope.json"),
                      "verificationLevel": "Release-level checks except explicitly owner-excluded full-cost replays; compact scoped review, no expanded major-release claim."},
            "planningNote": "Initial coverage-plan imported the prior ledger and retained its old fingerprint/proposed evidence labels. Its original bytes are preserved; this final checks array records current AUD-018 identities, actual methods, evidence and outcomes.",
            "checks": checks, "findings": findings, "observations": [],
            "remediation": self._remediation(previous, findings), "limitations": limits,
            "releaseAssessment": {"verdict": "FAIL", "currentProductHandoverBlockers": ["AUD-018-BLD001"],
                                  "historicalRecordPublicationBlockers": ["AUD-015-DOC001"],
                                  "nonblockingResiduals": [item["id"] for item in findings if not item["releaseBlocking"]],
                                  "mandatoryMhfeChecksPassed": True, "canonicalArchivesVerified": 4,
                                  "documentedLocalReproducibilityComparisonPassed": reproducibility_passed,
                                  "signedCandidateCommitPresent": False},
            "resources": {"heavyConcurrency": 1, "kernelMemoryMaxBytes": 4294967296, "kernelMemorySwapMaxBytes": 0,
                          "canonicalRuntimeLimitSeconds": 1080, "browserRuntimeLimitSeconds": 1080,
                          "browserCgroupMemoryPeakBytes": 816226304, "canonicalCgroupMemoryPeakBytes": 3910725632,
                          "uncachedCanonicalCgroupMemoryPeakBytes": int(uncached_peak[-1]) if uncached_peak else None,
                          "processGroupRssInterpretation": "systemd-run sampled client process group only; not the workload peak. Kernel cgroup readback and unit stop hooks identify actual enforced limits/peaks."},
            "tools": metadata["tools"], "buildEnvironment": metadata["environment"],
            "advisoryDatabase": {"tool": "cargo-audit 0.22.2", "commit": "7eebec69c352c7191b1f13eb95dd510eeca5d1de", "lastUpdatedUtc": "2026-10-09T08:12:02Z", "advisories": 1296, "lockDependencies": 109, "vulnerabilities": 0, "warnings": 0, "yankedStatusChecked": False},
            "commands": commands, "procedureHashes": self._load("procedure-hashes.json"),
            "harnessBindings": harnesses, "reusedHarnessBindings": reused,
            "reviewEvidenceBindings": {name: self._sha(self._evidence / name) for name in evidence_names},
            "artifacts": {"hostBuildId": metadata["hostBrowserBuildId"], "canonical": artifact,
                          "artifactHashes": artifact_hashes, "cachedUncachedComparison": comparison,
                          "nativeComparisonLimit": "Native host/canonical byte difference not localized; compiler/build environment differences are possible, not proven cause."},
            "maliciousCodeReview": {"result": "No confirmed malicious insertion or secret-exfiltration path found in the scoped reviewed source and package comparisons.",
                                    "evidence": required, "supplyChain": self._load("supply-chain-review.json"),
                                    "systemForensicsPerformed": False, "preIncidentTrustedBaselineProvided": False},
            "normalization": {"homePaths": "/home/user", "times": "UTC", "localOriginalEvidencePreserved": True}}
        report = self._public(report)
        (self._audits / (self._stem + ".json")).write_text(json.dumps(report, indent=2) + "\n")
        (self._audits / (self._stem + ".md")).write_text(self._markdown(report))
        print(json.dumps({"auditId": report["auditId"], "verdict": "FAIL", "findings": len(findings), "commands": len(commands), "checks": len(report["checks"])}))

    @staticmethod
    def _text(value):
        if isinstance(value, list):
            return "; ".join(str(item) for item in value)
        return str(value)

    def _markdown(self, r):
        lines = [f"# AUD-018 — {r['title']}", "", "## Record metadata", "",
                 "- **Audit number:** 18.", f"- **Completed (UTC):** {r['completedUtc']}.",
                 "- **Reviewer:** Codex coordinator and three scoped reviewers; source review, execution and independent challenge have distinct owners.",
                 "- **Model / actual reasoning effort:** Unknown per phase. The user's earlier ultra request is not measured service metadata.",
                 f"- **Reviewed commit:** `{r['snapshot']['commit']}` plus extensive pre-existing uncommitted 0.5.1 changes.",
                 f"- **MHFE source fingerprint:** `{r['snapshot']['sourceFingerprint']}`; non-audit source `{r['snapshot']['nonAuditSourceFingerprint']}`.",
                 f"- **Specification:** `{r['snapshot']['companionSpecification']['head']}` plus dirty files; non-audit source `{r['snapshot']['companionSpecification']['codeFingerprint']}`.",
                 "- **Source stability:** Initial and final non-audit manifests match. HEAD alone does not identify the checked working bytes.",
                 "- **Artifacts:** Fresh host native/JS/WASM and four canonical archives; browser build `cc38bfadd2bfe9b2`. Archive checksums below; complete per-file bindings are in the JSON companion.",
                 f"- **Companion:** [{self._stem}.json]({self._stem}.json). Rerun harnesses: [AUD-018-harnesses](AUD-018-harnesses/README.md). Original command logs are local-only in ignored `AUD-018-evidence/`.",
                 "", "## Finding register", "",
                 "| Finding / record ID | Category | Kind | Severity | Recorded status | Release blocking | Title |",
                 "| --- | --- | --- | --- | --- | --- | --- |"]
        for item in r["findings"]:
            lines.append(f"| {item['id']} | {item['category']} | finding | {item['severity'].capitalize()} | {item['status']} | {str(item['releaseBlocking']).lower()} | {item['title']} |")
        lines += ["", "## Review evidence", "", "### Scope and methodology", "",
                  "**Release verdict: FAIL.** Mandatory MHFE checks and the current canonical package pass. Release readiness still lacks current browser-host handover (AUD-018-BLD001). Publishing the rewritten historical reports still lacks four specification bindings (original AUD-015-DOC001). Low residuals are separated from these blockers. Only the host handover finding is newly numbered here.",
                  "", "This is an explicit pre-release verification and remediation follow-up using the shared audit guide, standard, template and JSON schema. The coordinator owns heavy execution, artifacts and dependency provenance; native/browser reviewers own their distinct boundaries; core owns specification/documentation and independently challenges conclusions. Production sources, tests, fixtures, dependencies and workflows were reviewed without edits. No commit, push, tag or publication was performed.",
                  "", "The owner expressly excluded repeated full-size MHFE/Argon2 and independent vector replays, stating they had just been checked. That statement is owner attestation, not newly executed evidence. Fast known-answer/negative tests, vector metadata, reduced-cost native/browser cases and the documented build checks were executed. Forty-two non-audit MHFE files changed from AUD-016, 205 were unchanged; all 64 compared specification files were unchanged. Twelve crypto/parameter/engine/dependency file identities match the prior snapshot. Changed confirmation, cancellation and front-end paths were reviewed and tested separately.",
                  "", "The initial imported coverage plan retained earlier proposed labels/fingerprint; the final ledger below replaces them with actual AUD-018 evidence and the current byte identity. Original planning evidence remains unaltered.",
                  "", "#### Procedure byte bindings", "",
                  "| Procedure | SHA-256 |", "| --- | --- |"]
        lines += [f"| `{name}` | `{value}` |" for name, value in r["procedureHashes"].items()]
        lines += ["", "### Coverage ledger", "", "Every CHECK item has an owner, method and evidence/gap. Passed means the stated applicable checks passed within their recorded limits, not exhaustive certification.", "",
                  "| Check ID | Category / logical group | Tool / build scope | Primary owner / method | Outcome | Evidence / gap reason |",
                  "| --- | --- | --- | --- | --- | --- |"]
        for row in r["checks"]:
            lines.append(f"| {row['id']} | {row['category']} / {row['logicalGroup']} | {row['scope']} | {row['primaryOwner']}: {row['method']} | {row['outcome']} | {'; '.join(row['expectedEvidence'])} |")
        lines += ["", "### Checks", "",
                  "| Check / command | Outcome | Counts / environment | Evidence |", "| --- | --- | --- | --- |",
                  "| `scripts/check.sh` | Passed | 379.10 s; library 343 passed / 2 ignored, CLI 118 passed / 2 ignored, suite-3 metadata 3 passed / 1 ignored, suite-4 metadata 2 passed / 1 ignored, doctests 4 passed; copy/vendored/license/fmt/clippy/native/WASM/module/Rustdoc/PTY/Node package/CLI parity/artifact gates | `release-check.log` |",
                  "| `node scripts/verify-browsers.mjs` | Passed | 421.24 s; Chromium 153.0.8010.12 and Firefox 155.0, standard and fast modes, all four pages | `real-browsers.log` |",
                  "| `scripts/build-reproducible.sh canonical-output-aud018` | Passed | 892.57 s; native/ARM64/Windows cross clippy/builds, offline tests, browser/Argon2/package checks, four archives | `canonical-build.log` |",
                  f"| Required `REPRODUCIBLE_NO_CACHE=1` build and exact comparison | {'Passed' if r['releaseAssessment']['documentedLocalReproducibilityComparisonPassed'] else 'Incomplete/failed; no reproducibility claim'} | Separate bounded unit and `canonical-output-aud018_uncached`; all four archives compared as bytes, with each SHA-256 list verified | `canonical-uncached-final.log`, `canonical-comparison.json` |",
                  "| Canonical archive inspection | Passed | Four SHA-256/BUILD-INFO/license bindings and 15 browser internal checksums; WASM and browser manifest equal host bytes; native differs | `canonical-artifacts.log`, `artifacts.json` |",
                  "| `npm run format:check` | Passed | 4.79 s, Prettier 3.9.9 | `format-check.log` |",
                  "| Cargo/vendor provenance and RustSec | Passed | 25 exact pins, 22 vendored files, 108 crate archives, 4075 unpacked files; 109 dependencies, 1296 advisories, no vulnerability/warning; yanked status excluded | `provenance.log`, `rustsec-current.log` |",
                  "| Native cancellation/public-input/low-lock/parent-control probes | Passed in their scope | No full KDF; fresh release/debug bytes; cancel 16384 candidates within 2 s after callback error; actual locks/redaction/escaped Rust diagnostics checked | `core-native-cancel.log`, native logs |",
                  "| Browser transport and cleanup probes | Passed | 26/26 page protocol, 7/7 worker cleanup; actual unit peaks 26,300,416 and 17,711,104 bytes | bounded browser logs |",
                  "| Historical structured/prose scans | Classified failures | Exactly four real specification fields; external RustSec/compiler/upstream and historical references classified separately | `core-record-fields.log`, `core-record-prose.log`, skeptic |",
                  "| Original CJK / rocket cursor | Partial fix | CJK passes; rocket expects 23, observes 22; no KDF or input-byte defect | native Unicode logs |",
                  "| npm installed tooling vs pinned official archives | Archive files match; strict extra-file inventory classified | 232 archive files match; generated shell wrappers inspected separately; no packages installed or executed for comparison | `supply-chain.log`, `supply-chain-review.json`, `shim-review.json` |",
                  "| Full-cost vector replays | Owner-excluded | Just-checked owner attestation; no fresh execution/result claimed | `owner-scope.json` |",
                  "| macOS builds / other-platform native execution | Not run | Cross-compilation does not establish target execution | Explicit limitations |",
                  "", f"Heavy checks ran sequentially in kernel-limited user units: `MemoryMax=4294967296`, `MemorySwapMax=0`. Docker RUN inheritance was demonstrated through host `/proc` and the bounded parent. Browser/canonical runtime caps were 18 minutes; actual browser/first-canonical cgroup peaks were 816,226,304 / 3,910,725,632 bytes. Uncached peak: {r['resources']['uncachedCanonicalCgroupMemoryPeakBytes']} bytes. The imported runner's ~7 MB sampled systemd client RSS is not the workload peak. The first inside-container cgroup read failed because BuildKit hides those files; the host witness passed. The initial uncached output name was refused before Docker; the corrected allowed suffix preserves both builds. Retained low-lock harness setup/expectation failures and the first denied user-bus protocol attempt were corrected in new attempts, without changing product assertions.",
                  "", "RustSec DB `7eebec69c352c7191b1f13eb95dd510eeca5d1de` was fetched for this run, last updated at `2026-10-09T08:12:02Z`. Exact anonymized argv, environments, UTC timing, exits and log hashes for every executed recorded command are in the companion JSON. Original local evidence is unredacted and retained.",
                  "", "#### Canonical archives", "", "| Archive | Bytes | SHA-256 |", "| --- | --- | --- |"]
        for item in r["artifacts"]["canonical"]["archives"]:
            lines.append(f"| [{item['name']}](../../canonical-output-aud018/release/{item['name']}) | {item['bytes']} | `{item['sha256']}` |")
        comparison_text = ("The prescribed cached/uncached comparison passes: all four archives and both SHA256SUMS files are byte-identical. This is local reproducibility evidence for the recorded recipe/source, not independent machine or upstream authenticity certification."
                           if r["releaseAssessment"]["documentedLocalReproducibilityComparisonPassed"]
                           else "The required cached/uncached comparison has not completed/passed; complete local reproducibility remains an explicit gap.")
        lines += ["", "All BUILD-INFO records say source HEAD `(modified)`. These are verified candidate archives from dirty bytes, not signed/published release assets. Host native SHA-256 is `3db809ef6e2c0972ef323079bea1aa7fea9b1969edfdf22d26927d3e8110a316`; canonical native is `73cd06bc3527b4c2b2b12f70fec83f7b6346a947fe35e6ff1d4ad232ef5b38a6`. The host-versus-container native difference was not localized. WASM matches at `68659291712d48c62cf0571fd1921f82d8f2acf34b1c9a7cbd00f75eecae68a5`. " + comparison_text,
                  "", "### Findings", ""]
        for item in r["findings"]:
            lines += [f"#### {item['id']} — {item['severity'].capitalize()} — {item['title']}", "",
                      f"- **Category / status:** {item['category']} / {item['status']}; {'new finding' if item.get('newInThisAudit') else 'original ID retained in follow-up'}.",
                      f"- **Release blocking:** {str(item['releaseBlocking']).lower()}. {item.get('releaseBlockingReason', 'Low nonblocking residual in the tested scope.')}"]
            for key, label in [("affectedFiles", "Affected files and builds"), ("reproduction", "Reproduction"), ("expected", "Expected behavior"), ("observed", "Observed behavior"), ("impact", "Impact"), ("evidence", "Evidence"), ("recommendedFix", "Recommended fix"), ("requiredVerification", "Required verification")]:
                if key in item:
                    lines.append(f"- **{label}:** {self._text(item[key])}")
            lines.append("")
        lines += ["### Remediation and follow-up", "",
                  "Formal statuses remain open where the recorded fix/verification commits are null. This does not mean every old runtime defect remains present. The separate current-trigger column records what this follow-up actually verified; no historical snapshot is silently replaced.", "",
                  "| Finding ID | Status | Fix commit | Verification commit | Current trigger / evidence |",
                  "| --- | --- | --- | --- | --- |"]
        for item in r["remediation"]:
            lines.append(f"| {item['id']} | {item['status']} | Not recorded | Not recorded | {item['currentTriggerStatus']}; {self._text(item['evidence'])} |")
        lines += ["", "All twelve AUD-017 source triggers are addressed in the current MHFE tree, including an accurate Docker comment rather than a claim of additional unexecuted container gates. AUD-016 cancellation, redaction, lock reporting, malformed/null handling, copy and native-browser triggers are addressed in the recorded scope. The Unicode width correction is incomplete. If Python fallback controls are listed above, Rust-only success does not close that original variant.",
                  "", "The prescribed alternative for original AUD-015-BLD001 is locally present: the old-to-new release map is in HEAD, whose object has a signature header, and all three local annotated tags match the map. Absence of the old objects alone is not a fresh local defect once that alternative is present. Trusted signature verification, publication and old external asset attestations/source equivalence remain unexecuted. Do not infer a current artifact failure from that historical gap.",
                  "", "### Informational observations and recommendations", "",
                  "#### Requested malicious-code/tampering review", "",
                  r["maliciousCodeReview"]["result"],
                  "", "Reviewers inventoried/hashed and lexically scanned the scoped native and browser executable source, including unchanged files. Manual tracing concentrated on candidate paths and critical network/command, persistence, entropy, crypto, OS and build-time boundaries. Expected operations include loopback-only serving, opening its local URL, local OS protection/resource probes, build-stage toolchain/registry downloads, test fixtures and offline artifact publishing gates. Candidates were classified by reachable data flow rather than treating every `fetch`, `eval` or hash string as a malicious finding.",
                  "", "Cargo archive/unpacked provenance and pinned npm archive comparisons complement source review. The strict npm inventory's three extra generated `.bin` wrappers were retained as candidates and independently inspected before classification; no archive-content mismatch is hidden. No active Git hooks/replacement refs, Cargo override configuration, or selected compiler/loader injection variables were found. Git object integrity passes. These observations apply to the captured build environment and do not attest the entire operating system.",
                  "", "The owner's unattended-laptop concern cannot be resolved by a code review alone. No pre-incident independent trusted baseline was provided, and the current machine supplies both the code and review tools. OS/firmware/account/browser/compiler compromise or a deliberately malicious upstream package beyond the recorded source scope is not excluded by these results.",
                  "", "### Assessment and limitations", ""]
        lines += [f"- {item}" for item in r["limitations"]]
        lines += ["", "Before a release tag, the current source fixes and browser handover need a recorded signed commit; a tag on current HEAD alone would omit the dirty changes. Complete the specifically scoped blockers and rerun their affected regressions. Successful checks already bound to unchanged bytes should be reused; this report does not request another full vector replay.", ""]
        return "\n".join(lines)


if __name__ == "__main__":
    ReportAssembler().assemble()
