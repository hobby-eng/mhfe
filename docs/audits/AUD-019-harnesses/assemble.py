#!/usr/bin/env python3
"""Generate the standard AUD-019 report from completed, retained evidence."""

import copy
import datetime
import hashlib
import json
import re
import shlex
from pathlib import Path


class AuditReport:
    COMMIT = "66f142566464255e331763966b00ea1681c2dabd"
    FIX = "3a705db6945b35f8c248c44893e71ddc36902af4"

    def __init__(self):
        self.root = Path(__file__).resolve().parents[3]
        self.audits = self.root / "docs/audits"
        self.evidence = self.audits / "AUD-019-evidence"
        self.stem = "audit-19-2026-10-10"

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @classmethod
    def public(cls, value):
        if isinstance(value, str):
            return re.sub(r"/home/[^/\s]+", "/home/user", value)
        if isinstance(value, list):
            return [cls.public(item) for item in value]
        if isinstance(value, dict):
            return {key: cls.public(item) for key, item in value.items()}
        return value

    def load(self, name):
        return json.loads((self.evidence / name).read_text())

    def checks(self, core, native, browser):
        rows = {item["id"]: copy.deepcopy(item) for item in core["checks"] + native["checks"]}
        for item in browser["checks"]:
            key = item["checkId"]
            if key not in rows:
                rows[key] = {"id": key, "status": "passed", "method": item["evidence"],
                             "evidence": ["local-only: browser-review.json"],
                             "limits": "Assigned browser/package scope; synthetic and real-WASM execution are distinguished below."}
        updates = {
            "CHECK-BLD-001": ("passed", "Four independently selectable browser modules; feature-gated Rust checks and generated bindings; version/build/source identity checked in all six release archives.", "release-check.log; artifacts.json"),
            "CHECK-BLD-002": ("passed", "Current native/WASM feature combinations, package/parity, actual WASM retry, Chromium and Firefox in standard/fast modes; exact tag Linux/macOS/Windows CI inspected. Current host package/source handover hashes match; complete host application acceptance was not repeated.", "release-check.log; remote-release-checks.log; browser-shared-retry-evidence.json; browser-review.json"),
            "CHECK-BLD-003": ("passed", "25 exact Cargo pins, 108 archives, 4075 unpacked Cargo files, 22 vendored files, three official npm archives and 231 installed npm files verified; six archives carry exact licenses/notices. Current tag RustSec action reports zero entries, without denying warnings.", "dependency-provenance.log; supply-chain.json; artifacts.json; remote-release-canonical.log"),
            "CHECK-BLD-004": ("passed", "Fresh uncached Docker recipe under a 4 GiB/no-swap kernel unit; all four archives and canonical SHA256SUMS are byte-identical to the retained clean-commit export. Each archive also equals the candidate/CI checksum. No local macOS reproduction.", "canonical-uncached-unit.log; canonical-comparison.json"),
            "CHECK-BLD-005": ("passed", "Read exact tag/branch workflows and successful jobs. All six candidate archives and SHA256SUMS cryptographically verified with exact workflow, signer/source digest, tag ref and hosted-runner constraints. OpenPGP owner signing/current private draft inspection remain pending.", "remote-release-run.json; remote-vector-run.json; remote-release-publish.log; attestations-all.log"),
            "CHECK-UI-001": ("partial", "Actual MHFE package is loaded in all four real-browser engine/mode pages; functional scenarios pass. MHFE ships a library package without its own visual application. Complete foreign host real-file/representative viewport acceptance was not repeated.", "remote-release-checks.log; browser-review.json"),
        }
        for key, (status, method, evidence) in updates.items():
            rows[key] = {"id": key, "status": status, "method": method,
                         "evidence": ["local-only: " + name for name in evidence.split("; ")],
                         "limits": "See execution matrix, publication prerequisites and scope limitations."}
        for key, value in rows.items():
            value.setdefault("method", value.get("reason", "Assigned scoped review"))
            value.setdefault("evidence", [])
            value.setdefault("limits", value.get("reason", "See explicit scope limits."))
            value["primaryOwner"] = ("core reviewer" if key in {x["id"] for x in core["checks"]}
                                     else "native reviewer" if key in {x["id"] for x in native["checks"]}
                                     else "browser reviewer")
            if key in updates:
                value["primaryOwner"] = "coordinator with browser reviewer" if key.startswith("CHECK-BLD") else "browser reviewer"
        guide = (self.root.parent / "multi-chain-wallet-tools/docs/FULL_AUDIT_GUIDE.md").read_text()
        titles = dict(re.findall(r"^### (CHECK-[A-Z]+-\d{3}) — (.+)$", guide, re.M))
        if set(rows) != set(titles) or len(rows) != 32:
            raise SystemExit("The full 32-check coverage ledger is incomplete")
        return [{**rows[key], "title": title} for key, title in titles.items()]

    def remediation(self, core, native, browser):
        rows = {}
        for item in core["remediation"]:
            status = item.get("status", "fixed")
            rows[item["id"]] = {
                "id": item["id"], "title": item["originalTitle"], "status": status,
                "fixCommit": item.get("fixCommit") or self.FIX,
                "verificationCommit": item.get("verificationCommit"),
                "evidence": [item.get("evidence", "Committed remediation and retained AUD-015/016/017 follow-up; no separate current trigger execution attributed in this row.")],
                "assessment": item.get("coreAdjudication", "source follow-up"),
            }
        for item in native["remediation"]:
            rows[item["id"]].update(item)
        for item in browser["originalFindings"]:
            key = item["originalFindingId"]
            if key == "AUD-018-BLD001":
                rows[key].update({"status": "fixed", "fixCommit": item["remediationIntroducingCommit"],
                                  "verificationCommit": None, "evidence": [item["evidence"]],
                                  "assessment": item["formalClosure"],
                                  "limits": "Foreign host fixes are uncommitted; the MHFE fix commit does not identify them. Hashed host bytes resolve the old stale trigger, but no signed host closure or complete host UI acceptance is claimed."})
            else:
                rows[key].update({"status": "verified", "fixCommit": item["remediationIntroducingCommit"],
                                  "verificationCommit": self.COMMIT, "evidence": [item["evidence"]],
                                  "assessment": "Assigned source/contract evidence plus shared exact-commit regression execution; see current scope limits."})
        for item in self.load("native-remediation-supplement.json")["rows"]:
            key = item["originalFindingId"]
            evidence = [f"{entry['path']}" + (f":{entry['line']}" if "line" in entry else "") + f" ({entry['sha256']})"
                        for entry in item["sourceEvidence"] + item["regressionEvidence"]]
            rows[key].update({"status": item["status"], "fixCommit": item["fixCommit"],
                              "verificationCommit": item["verificationCommit"],
                              "evidence": evidence, "assessment": item["currentTriggerDisposition"],
                              "limits": "; ".join(item["limits"])})
        for item in self.load("browser-remediation-supplement.json")["originalFindings"]:
            rows[item["id"]].update({"status": item["status"],
                "fixCommit": item["remediationIntroducingCommit"],
                "verificationCommit": self.COMMIT if item["status"] == "verified" else None,
                "evidence": item["source"] + [item.get("exactTriggerEvidence", item.get("retainedAdjacentEvidence"))],
                "assessment": item.get("observed", item["expected"]),
                "limits": item.get("limits", item.get("verificationGap"))})
        for key in ["AUD-016-BLD001", "AUD-017-BLD001", "AUD-017-BLD002", "AUD-015-BLD002"]:
            rows[key].update({"status": "verified", "fixCommit": self.FIX,
                              "verificationCommit": self.COMMIT,
                              "evidence": ["scripts/check.sh current complete copy gate passed; tag Release invokes full reusable CI and its complete canonical verification stage; fresh local uncached recipe passed."]})
        rows["AUD-017-UI002"]["evidence"].append("Actual WASM/RekeySession scripts/verify-browser-package.mjs:765-891, then scripts/verify-browsers.mjs:1963-1993 on four real pages; comparison-only retry without a second recovery is checked. Eight synthetic probes supplement exception cleanup only.")
        rows["AUD-015-BLD001"].update({"status": "open", "verificationCommit": None,
            "assessment": "The signed local history mapping is present, but old v0.3.0-v0.5.0 asset/provenance reconstruction was not freshly verified. Current v0.6.0 has its own independently verified source/artifact chain.",
            "releaseBlocking": False, "releaseBlockingReason": "Residual concerns the historical published releases, not the newly verified v0.6.0 candidate; no historical certification is granted."})
        return [rows[key] for key in sorted(rows)]

    def finding(self, core):
        item = copy.deepcopy(core["findings"][0])
        item.update({
            "title": "Published rehearsal prose retains the superseded stated-length condition",
            "affectedFiles": ["../mhfe_spec/README.md:447", "src/rehearsal.rs:373", "scripts/verify-browsers.mjs:1441"],
            "releaseBlockingReason": "Low interoperability/documentation inconsistency; no cipher change or rekey-confirmation bypass. A detected short-source verifier establishes consistency, not wallet identity. The reproduced 12-word short-source verifier is 128 bits; the separate 24-word walletCheck is 16 bits.",
            "reproduction": "For the public zero-12 container and correct test password, fullCheck({ words: 15 }) deliberately returns matches: true, path: null, evidence: { builtInCheck: 12, walletCheck: null }. The actual real-browser assertion at scripts/verify-browsers.mjs:1441-1447 passed in Chromium and Firefox, both standard and fast modes, in the exact tag CI log. The words field specifies the built-in reference count; the result has no sourceLength field.",
            "expected": "The companion specification's rehearsal paragraph agrees with its recovery precedence rule for an owner-stated short length contradicted by another detected verifier.",
            "observed": "Published specification v0.6.0 and the current companion specification README retain the stated-length condition for Matches in rehearsal, while the revised recovery rule and MHFE implementation accept another matching short layout and report its detected length. MHFE's own current README documents the intended precedence. Rekey separately refuses LENGTH_DIFFERS or ambiguity before sealing and requires eligible owner or external wallet confirmation.",
            "impact": "A caller implementing the obsolete rehearsal sentence can disagree on check status for stated 15/detected 12 words. No unsafe rekey, wrong wallet identity or change to encrypted format was demonstrated.",
            "recommendedFix": "Reconcile the companion specification rehearsal sentence with its detected-verifier precedence; retain detected-length evidence and the separate rekey confirmation requirement.",
            "requiredVerification": "Compare no stated length and stated short lengths with zero, one and multiple verifier matches across recovery/rehearsal prose; retain the actual stated-15/detected-12 browser regression and wrong-password negative.",
            "evidence": ["mhfe_spec v0.6.0 tag d954dc9f8df8c8d1fda075fb2be348d1f4877d41 and current specification have the same normative text.",
                         "../mhfe_spec/README.md:378 and :447; src/rehearsal.rs:373; docs/API.md:96; README.md:387.",
                         "local-only: core-review.json; native-skeptic-review.json; remote-release-checks.log."],
        })
        return item

    def build(self):
        for label in ["release-check", "canonical-uncached-unit", "canonical-comparison", "attestations-all"]:
            if self.load(label + ".command.json")["exitCode"] != 0:
                raise SystemExit("Required current evidence is not successful: " + label)
        core, native, browser = [self.load(name + "-review.json") for name in ["core", "native", "browser"]]
        initial, final = self.load("initial.json"), self.load("final-formatted.json")
        resume = self.load("resume.json")
        for project in ["mhfe", "mhfe_spec"]:
            if resume[project]["head"] != initial[project]["head"] or resume[project]["codeFingerprint"] != initial[project]["codeFingerprint"]:
                raise SystemExit("Reviewed source identity changed during the pause: " + project)
        if resume["mhfe_spec"]["sourceFingerprint"] != initial["mhfe_spec"]["sourceFingerprint"]:
            raise SystemExit("Companion specification changed during the pause")
        core_challenge = self.load("report-core-challenge.json")
        browser_challenge = self.load("report-browser-challenge.json")
        if core_challenge["result"] != "supported within recorded scope; no unresolved substantive core correction" or browser_challenge["concreteErrors"]:
            raise SystemExit("An independent final report challenge is unresolved")
        if initial["mhfe"]["codeFingerprint"] != final["mhfe"]["codeFingerprint"]:
            raise SystemExit("Product source changed during the audit")
        if initial["mhfe_spec"]["sourceFingerprint"] != final["mhfe_spec"]["sourceFingerprint"]:
            raise SystemExit("Companion specification changed during the audit")
        commands = [self.load(path.name) for path in sorted(self.evidence.glob("*.command.json"))
                    if not path.name.startswith("validation-")]
        bindings = [{"path": str(path.relative_to(self.audits)), "sha256": self.sha(path)}
                    for path in sorted((self.audits / "AUD-019-harnesses").rglob("*"))
                    if path.is_file() and "__pycache__" not in path.parts]
        bindings += [{"path": str(path.relative_to(self.audits)), "sha256": self.sha(path)}
                     for path in sorted(self.evidence.iterdir())
                     if path.is_file() and path.suffix in {".json", ".log", ".txt", ".md"}
                     and (not path.name.startswith(("report-", "validation-", "report-validation"))
                          or path.name.startswith(("report-core-challenge", "report-browser-challenge")))]
        remote = []
        for name in ["branch", "release", "vector"]:
            record = self.load("remote-" + name + "-run.json")
            run = json.loads(record["result"]["structuredContent"]["content"])
            if run["head_sha"] != self.COMMIT or run["conclusion"] != "success":
                raise SystemExit("Current workflow identity/result differs")
            remote.append({"name": run["name"], "id": run["id"], "source": run["head_sha"],
                           "url": run["html_url"], "conclusion": run["conclusion"],
                           "startedUtc": run["run_started_at"], "updatedUtc": run["updated_at"]})
        attestation = self.load("attestation-SHA256SUMS.json")[0]["verificationResult"]
        report = {
            "schemaVersion": 1, "auditId": "AUD-019", "auditNumber": 19, "date": "2026-10-10",
            "title": "Final full-scope MHFE v0.6.0 audit before publication",
            "reviewer": {"name": "Codex coordinator and three scoped independent reviewers", "model": None, "reasoningEffort": None},
            "completedUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "snapshot": {"commit": self.COMMIT, "commitComplete": True,
                         "workingTree": "Clean product tree before audit; only current audit records/harnesses and their index added. Product inputs stayed unchanged.",
                         "sourceFingerprint": initial["mhfe"]["sourceFingerprint"],
                         "nonAuditFingerprint": initial["mhfe"]["codeFingerprint"],
                         "initial": initial, "final": final, "resumed": resume,
                         "tag": {"name": "v0.6.0", "object": "3f1b83fb9986b2584da058ad5896f1ceb18bc772", "target": self.COMMIT,
                                 "signatureVerified": True, "keyFingerprint": "SHA256:lDODtP3Ip3KLwvWPChsX3XL4jKpw1sp6WhcmQuLBeko"}},
            "scope": {"project": "mhfe", "version": "0.6.0", "team": ["coordinator: snapshot, release evidence, independent adjudication", "core: cryptography, correctness, architecture, specification and claims", "native: CLI, OS isolation, private input, terminal and independent skeptic", "browser: WASM/module contracts, worker ownership, integration and malicious candidates"],
                      "features": "Encryption/decryption, suites 3/4, PIM/memory metadata, rekey, decoy and missing-word recovery, repair cards, password/chosen-word tools, wallet checks and four browser modules.",
                      "verificationLevel": "Explicit release-level request with owner exclusion of repeated local full-cost vectors; successful exact-tag full vector CI retained instead.",
                      "maliciousCode": "Scoped repository, dependency, build and generated-artifact integrity review; no whole-machine or account investigation."},
            "procedureHashes": self.load("procedure-hashes.json"), "environment": self.load("environment.json"),
            "checks": self.checks(core, native, browser), "findings": [self.finding(core)], "observations": [],
            "remediation": self.remediation(core, native, browser), "commands": commands, "remoteRuns": remote,
            "artifacts": self.load("artifacts.json"), "canonicalComparison": self.load("canonical-comparison.json"),
            "attestation": {"verifiedSubjectCount": 7, "repository": "hobby-eng/mhfe", "workflow": ".github/workflows/release.yml", "ref": "refs/tags/v0.6.0", "sourceDigest": self.COMMIT,
                            "signerDigest": self.COMMIT, "runnerEnvironment": "github-hosted", "predicateType": attestation["statement"]["predicateType"],
                            "subjects": attestation["statement"]["subject"], "verifierVersion": "2.101.0",
                            "verifierArchiveSha256": "9bca2d1c16825f109907a23307628a2f0698fbf99662b73a5cf0b020293072b8",
                            "verifierBinarySha256": "ea857a3f0f7d4276cf5848b236542c5048e2eaa7bdd1b6ddec238f8793e74bff"},
            "evidenceBindings": bindings,
            "finalReportReview": {
                "core": {"record": "local-only: report-core-challenge.json", "sha256": self.sha(self.evidence / "report-core-challenge.json"), "result": core_challenge["result"]},
                "browser": {"record": "local-only: report-browser-challenge.json", "sha256": self.sha(self.evidence / "report-browser-challenge.json"), "result": browser_challenge["adjudication"]},
                "limits": "Independent challenges bind the report pair as read before the final resume/evidence closeout. The retained pre-closeout pair and original challenge errors remain local evidence; final closeout updates metadata/bindings, not product conclusions."},
            "resumeInspection": {
                "capturedUtc": resume["mhfe"]["capturedUtc"],
                "productAndSpecificationUnchanged": True,
                "browserHost": self.load("resume-browser-integrity.json"),
                "remoteTagObject": json.loads(self.load("resume-remote-tag.json")["result"]["structuredContent"]["content"])["object"]["sha"],
                "privateDraft": "Read-only release lookup remains inaccessible/404; no absence inferred.",
                "execution": "Owner paused and later resumed this audit. Only source/artifact/evidence consistency was rechecked after resume; heavy checks, vectors and cryptographic signature verification were not repeated."},
            "informationalObservations": [
                "Repair output strings hold encrypted container/card text, not passwords or recovered spending seeds. Consider qualifying the broad phrase-wiping claim in SECURITY.md; no private-key lifetime defect or transmission was demonstrated.",
                "An unreadable /proc/swaps currently maps to an empty warning list. Reporting an unknown swap state would improve diagnostics; actual inaccessible-proc secret exposure was not reproduced.",
                "The foreign host README retains an older Emscripten version string, while its actual 0.6.0 generated manifest/WASM match current 6.0.12 artifacts.",
                "Build-tool installation warns about a yanked yoke-derive 0.8.3 in the wasm-bindgen CLI lock and future-incompatible buf_redux/multipart tooling. Product dependency integrity passes; these warnings are not hidden or counted as a product test failure."],
            "assessment": {"technicalCandidate": "PASS WITH CAVEATS", "fullScopeExecution": "INCOMPLETE", "publicationVerification": "INCOMPLETE",
                           "newReleaseBlockingFindings": 0, "newFindings": {"low": 1},
                           "reason": "All required executed MHFE source/package/current-tag/canonical integrity checks pass. One Low companion-specification wording inconsistency is open. OpenPGP owner signature/public key, current private draft inventory and broader foreign-host acceptance are not verified; historical assets retain their original unverified remediation limit."},
            "limitations": [
                "This is a full-scope audit with incomplete broader execution, not an independent security certification or proof of absence of malicious code.",
                "Repeated local full-cost Argon2/vector replay was explicitly excluded by the owner. Current exact-tag CI successfully ran both native full-vector groups and independent published-vector/password validation; those are remote observations, not new local replays.",
                "The local check.sh and tiny public preflight used current Cargo-cached compiled artifacts where accepted by Cargo. Fresh uncached canonical Docker compilation and exact-tag CI independently cover the recipe; never interpret the tiny preflight as a full fresh rebuild.",
                "Linux/native/package tests ran locally. macOS ARM and Windows acceptance are exact-tag CI observations; Linux ARM and macOS x86-64 archives were cross-compiled, not executed locally. macOS canonical reproduction was not performed.",
                "The kernel heavy-check budget was 4 GiB with zero swap and one heavy job at a time. Fresh Docker cgroup MemoryPeak was 2537144320 bytes. The earlier collected check.sh unit has no retained MemoryPeak; runner process-group RSS measures the client and does not establish workload peak.",
                "Local Unicode generator verification refused the installed Unicode 16 module; exact-tag CI used pinned unicodedata2 17.0.1/Unicode 17.0.0 and passed the full width-table check. No local data downgrade was made.",
                "The current private draft Release API returned inaccessible/404 in this environment. Successful creation logs and matching retained candidate bytes do not prove its current private inventory. No absent draft or invalid authentication token is inferred.",
                "The retained candidate has no SHA256SUMS.asc or RELEASE-SIGNING-KEY.asc. Owner signing, verification against the intended OpenPGP key, upload and final download verification are pending publication steps; no release was published by this audit.",
                "The foreign host has current matching package/source handover at inventoried dirty bytes; its signed published-package admission and complete host UI/viewport regressions were not verified. AUD-018-BLD001 is fixed in this current working-tree trigger scope, with no signed host closure claimed.",
                "Historical unavailable specification commits are explicitly disclosed, not reconstructed. AUD-015-BLD001 old v0.3.0-v0.5.0 release asset/provenance verification remains open; current v0.6.0 attestations do not certify old assets.",
                "Secret wiping and isolation were checked through source ownership and bounded observable refusals/readbacks. Physical allocator remnants, browser GC, encrypted swap, firmware, laptop access, malware outside the repository and key/account custody were not independently certified.",
                "Verifier bootstrap used official GitHub HTTPS and matching official checksum, without an independently authenticated signature on the verifier download. Attestation verification therefore trusts that bootstrap and the verifier's Sigstore/GitHub roots.",
                "Exact model and actual reasoning-effort metadata were not available in retained execution metadata; both are recorded as unknown despite the requested audit depth.",
            ],
        }
        report = self.public(report)
        (self.audits / (self.stem + ".json")).write_text(json.dumps(report, indent=2) + "\n")
        (self.audits / (self.stem + ".md")).write_text(self.markdown(report))
        print("Generated AUD-019 Markdown/JSON; source preserved and successful uncached comparison required.")

    def markdown(self, report):
        out = ["# AUD-019 — Final full-scope MHFE v0.6.0 audit before publication", "",
               "Technical candidate: **PASS WITH CAVEATS**. No new release-blocking MHFE defect was confirmed. One new Low documentation inconsistency remains in the companion specification. Full-scope execution and final publication verification are **INCOMPLETE** in the explicitly listed broader scopes and pending owner-signing steps.", "",
               "## Record metadata", "",
               "- **Audit number:** 19.", "- **Completed (UTC):** " + report["completedUtc"] + ".",
               "- **Started (UTC):** " + report["snapshot"]["initial"]["mhfe"]["capturedUtc"] + "; retained audit date/filename identify this starting snapshot. Owner pause and later resume belong to the same AUD-019 record.",
               "- **Reviewer:** Coordinator and three scoped reviewers; an independent native skeptic challenged the combined core/browser conclusions.",
               "- **Model / actual reasoning effort:** Unknown; no exact retained client metadata was available.",
               "- **Reviewed commit:** `" + self.COMMIT + "`.",
               "- **Signed tag:** `v0.6.0`, object `3f1b83fb9986b2584da058ad5896f1ceb18bc772`, targeting the reviewed commit; signature and all 11 commits since v0.5.0 verified against the retained expected SSH public key.",
               "- **Working tree:** Product tree was clean before audit. Only this audit's documents/harnesses and index are added. No product source, test, dependency or workflow was changed.",
               "- **Initial MHFE full / non-audit SHA-256:** `" + report["snapshot"]["sourceFingerprint"] + "` / `" + report["snapshot"]["nonAuditFingerprint"] + "` (600 files; own audit excluded).",
               "- **Companion specification:** HEAD `c16c7bd4cda9479861579b1b958c6052658c3e66`, published v0.6.0 tag `d954dc9f8df8c8d1fda075fb2be348d1f4877d41`; unchanged normative bytes. Pre-existing untracked AGENTS.md/drafts preserved.",
               "- **Artifacts:** Six candidate archives plus SHA256SUMS; four canonical targets independently reproduced without cache. Full hashes and source/build relationship appear below.",
               "- **Records:** [JSON companion](" + self.stem + ".json); [rerunnable harnesses](AUD-019-harnesses/README.md). Raw logs/command records in `AUD-019-evidence/` are local-only and git-ignored.", "",
               "## Finding register", "", "| Finding ID | Category | Kind | Severity | Status | Release blocking | Title |", "| --- | --- | --- | --- | --- | --- | --- |"]
        for item in report["findings"]:
            out.append(f"| {item['id']} | {item['category']} | finding | {item['severity']} | {item['status']} | false | {item['title']} |")
        out += ["", "Independent final report challenges passed in their stated scopes. The core reviewer corrected the draft's verifier-width and README identity wording; the browser review preserved its own initial literal-CSP harness false positive and corrected the assertion to the actual wasm-unsafe-eval trigger. Neither required a product change. On resume, current MHFE/specification manifests, all 60 inventoried host files, candidate bytes and the remote tag identity were checked again. Original heavy-check/vector evidence remains valid; no such execution was repeated.", "",
                "## Review evidence", "", "### Scope and methodology", "",
                "The standard workspace procedure was applied to all 32 checklist items, with inapplicable wallet subsystems identified individually. Core/security/correctness, native/terminal, browser/module/integration and documentation claims had distinct owners. The coordinator challenged findings and reconciled shared execution; the native reviewer independently challenged the new specification discrepancy, repair-string hypothesis and real-WASM retry evidence. Only public vectors and synthetic data were used.", "",
                "The audit covers encryption/decryption, suites 3/4, packing and length precedence, PIM/memory metadata, rekey confirmation, decoy and missing-word recovery, repair cards, chosen/excluded words, password tools, wallet-reference checks, CLI protection and the four browser modules. The malicious-code scope covers current source candidates, Git hooks/configuration, exact dependency/vendor archives, build scripts and generated/release bindings. No confirmed malicious insertion or exfiltration was identified; this is a scoped finding, not a whole-laptop verdict.", "",
                "Procedure files come from the authoritative multi-chain-wallet-tools checkout. SHA-256 bindings:", "", "| Procedure | SHA-256 |", "| --- | --- |"]
        out += [f"| `{path}` | `{digest}` |" for path, digest in report["procedureHashes"].items()]
        out += ["", "Environment: Linux x86-64, Rust/Cargo 1.99.0, wasm-bindgen 0.2.129, Emscripten 6.0.12, Node 26.10.0, Python 3.14.4, Docker 29.8.2 and Playwright 1.64.0. Heavy checks ran serially under 4 GiB/no-swap kernel units, with one Cargo build job. Uncached Docker runtime was 561.71 seconds and cgroup peak was 2,537,144,320 bytes; the earlier collected check.sh unit has no retained workload peak.", "",
                "### Coverage ledger", "", "| Check ID | Primary owner / logical group | Outcome |", "| --- | --- | --- |"]
        for item in report["checks"]:
            out.append(f"| {item['id']} | {item['primaryOwner']}: {item['title']} | {item['status']} |")
        out += ["", "Methods, evidence and individual inapplicable reasons:", ""]
        for item in report["checks"]:
            out.append(f"- **{item['id']}:** {item['method']} Evidence: {'; '.join(item['evidence']) or 'feature absent; source inventory'}. Limits: {item['limits']}")
        out += ["", "### Checks", "",
                "Current local `scripts/check.sh` passed: **344 library tests / 2 ignored; 122 CLI tests / 2 ignored; suite-3 metadata 3 / 1 ignored; suite-4 metadata 2 / 1 ignored; 4 doctests**. Ignored full-cost groups are covered by the separately observed exact-tag vector workflow. Formatter, full copy gate, native/WASM Clippy and module combinations, terminal suite, Rust/C Argon2 known answers, generated package assertions including actual-WASM retry, CLI/browser parity, 14 Python-fallback tests and release integrity gates passed. Cargo reused accepted local compilation artifacts where present; this is not called a fresh native rebuild.", "",
                "Scoped additional probes: 128 public core assertions without constructing an Argon2 engine; 26 page protocol assertions; 7 worker cleanup assertions; 8 synthetic retry/exception-control assertions; original CJK and rocket cursor probes (column 23, cancel 130, terminal restored); invalid-fingerprint redaction; 4096-byte low-memlock truthful-warning probe; 10 bounded Python-control refusal cases. Synthetic retry probes do not establish cryptographic correctness. Existing actual-WASM/reduced-C-engine retry checks and four real-browser pages do: fingerprint/owner re-confirmation is performed on the retained recovery without repeating KDF recovery.", "",
                "Exact-tag browser CI used **Chromium 156.0.8078.4 and Firefox 157.0**, each in standard and fast mode. Linux, Windows and macOS checks are green. macOS library/CLI totals were 336/117 with 2/1 ignored; Windows 333/114 with 2/1 ignored. The corrected macOS unavailable-isolation status is gray, distinct from a successful protection check. No platform protection is inferred where the tool reports it unavailable.", "",
                "Full-cost vectors were **not rerun locally**, per owner instruction. The exact-tag successful vector workflow independently ran native suite 3 (one vector-group test, 2536.30 s) and suite 4 (one group, 1488.77 s), Unicode 17 password/width checks (33 password cases), independent suite-3 16 positive transcript files plus 7 negatives, and suite-4 validation at four entropy widths plus 63 refusals, 10 positive files plus 4 negatives. These overlapping groups are not added into one misleading total.", "",
                "Observed remote runs (read-only inspection; no new Actions dispatch):", "", "| Run | Result / source | Link |", "| --- | --- | --- |"]
        for run in report["remoteRuns"]:
            out.append(f"| {run['name']} {run['id']} | {run['conclusion']}; `{run['source']}` | [GitHub run]({run['url']}) |")
        out += ["", "The tag Release invokes the required reusable CI jobs before draft publication. Its canonical job and publish job succeeded; the vector workflow is separate and also finished successfully. The branch-only canonical job was intentionally skipped; the actual tag Release canonical job ran. RustSec's current tag action reports zero entries with cargo-audit 0.22.0 and denyWarnings=false; no exact advisory-database commit was retained here.", "",
                "Dependency integrity: **25 exact pins, 108 Cargo archives, 4075 unpacked source files, 22 vendor files, three official npm archive SHA-512 matches and 231 installed npm files**, with no missing/mismatched files in checked scope. Git fsck passes; no active repository hooks, Cargo override configuration, selected loader-injection variables or replace refs were found. These inventory checks are complemented by targeted source review; they are not exhaustive behavioral proof for every dependency.", "",
                "#### Release bytes and authenticated provenance", "", "| Candidate archive | SHA-256 | Local canonical byte match |", "| --- | --- | --- |"]
        for item in report["artifacts"]["archives"]:
            match = "yes, retained and fresh uncached" if item["localCanonicalByteMatch"] else "not locally reproduced; tag CI and attestation verified"
            out.append(f"| `{item['file']}` | `{item['sha256']}` | {match} |")
        out += ["", "Candidate SHA256SUMS SHA-256: `" + report["artifacts"]["checksumFileSha256"] + "`. All archive sums match the tag publish log. Every archive records version 0.6.0 and clean source `" + self.COMMIT + "`; licenses/notices match the reviewed source. Browser build `4f5000f4290fa5eb` has 15 verified internal checksum subjects. Current host package manifest and WASM equal the upstream candidate, while the host's remaining application changes are dirty.", "",
                "All four fresh uncached canonical archives and the four-target checksum file equal the retained canonical export byte for byte. Each canonical archive also equals the six-target candidate. The candidate checksum file has two additional macOS targets; its different inventory is expected. Only this audit's new unused documents were ignored in process-local Git status during the recipe after strict tracked/untracked input checks; product inputs were not ignored or changed, and no Git configuration was changed on disk.", "",
                "Cryptographic provenance was verified for **all seven subjects**, not only inspected through the API: audit-local GitHub CLI 2.101.0 used `--repo hobby-eng/mhfe --signer-workflow hobby-eng/mhfe/.github/workflows/release.yml --source-ref refs/tags/v0.6.0 --source-digest " + self.COMMIT + " --signer-digest " + self.COMMIT + " --deny-self-hosted-runners`. It verified Sigstore/GitHub hosted-runner signatures, transparency material and the SLSA v1 subject digests. [GitHub attestation](https://github.com/hobby-eng/mhfe/attestations/54619731). The verifier download matched its official SHA-256; its bootstrap trust limit is stated below. This closes the earlier gh 2.46 command-availability gap.", "",
                "#### Exact command ledger", "",
                "All commands below have original local-only logs and records in `AUD-019-evidence/`. Published paths are anonymized; raw local evidence is unchanged. Exit failures include retained harness/environment attempts and are not silently replaced by corrected successes. UTC execution times, environment and RSS attribution are in the JSON companion.", "", "| Label | Exit / seconds | Log SHA-256 |", "| --- | --- | --- |"]
        for item in report["commands"]:
            out.append(f"| {item['label']} | {item['exitCode']} / {item['seconds']} | `{item['logSha256']}` |")
        out += ["", "Exact commands, in the same ledger order:", ""]
        for item in report["commands"]:
            out += [f"**{item['label']}**", "", "```sh", shlex.join(item["argv"]), "```", ""]
        out += ["", "Initial failures retained: stale/missing harness path and browser-probe setup/assertion mistakes were corrected within audit-owned harnesses; core first compared whole specification READMEs instead of normative protocol text and corrected the comparison; native source scan first failed its audit-only inventory handling; the local Unicode check refused Unicode 16; one initial systemd property argument was malformed before any build ran; draft API/network attempts were inaccessible. Their corrected outcomes remain separate. No product assertion, vector, protection or cryptographic parameter was weakened to obtain a pass.", "",
                "### Findings", ""]
        for item in report["findings"]:
            out += [f"#### {item['id']} — Low — {item['title']}", ""]
            for key, label in [("category", "Category"), ("status", "Status"), ("releaseBlockingReason", "Release blocking: false"), ("reproduction", "Reproduction"), ("expected", "Expected behavior"), ("observed", "Observed behavior"), ("impact", "Impact"), ("recommendedFix", "Recommended fix"), ("requiredVerification", "Required verification")]:
                out.append(f"- **{label}:** {item[key]}")
            out += ["- **Affected files:** " + "; ".join(item["affectedFiles"]) + ".", "- **Evidence:** " + "; ".join(item["evidence"]), ""]
        out += ["### Remediation and follow-up", "",
                "All 49 distinct original IDs from AUD-015 through AUD-018 are retained below. `verified` means the original trigger is absent in the stated current source/runtime scope at the verification commit; it does not certify every possible variant. `fixed` without a verification commit preserves a source-only or foreign-tree acceptance limit. Historical original reports/evidence are unchanged.", "", "| Original finding ID | Status | Fix commit | Verification commit |", "| --- | --- | --- | --- |"]
        for item in report["remediation"]:
            out.append(f"| {item['id']} | {item['status']} | `{item['fixCommit']}` | {('`' + item['verificationCommit'] + '`') if item['verificationCommit'] else 'not claimed'} |")
        out += ["", "Per-finding evidence and limits:", ""]
        for item in report["remediation"]:
            limits = item.get("limits", "")
            if isinstance(limits, list):
                limits = "; ".join(limits)
            out.append(f"- **{item['id']}:** {'; '.join(item['evidence'])}. {item.get('assessment', '')}. {limits}")
        out += ["", "Historical AUD-015-DOC001 closure verifies the explicit disclosure of four unavailable companion-specification fields and their retained original IDs; it does not reconstruct the pruned trees. AUD-015-BLD001 remains open for historical v0.3.0-v0.5.0 asset provenance. AUD-018-BLD001's old stale package/schema trigger is resolved at hashed current foreign-host bytes, but signed host closure/full application acceptance is pending. Neither is misrepresented as a newly reproduced v0.6.0 cryptographic defect.", "",
                "### Informational observations and recommendations", ""]
        out += ["- " + item for item in report["informationalObservations"]]
        out += ["", "### Assessment and limitations", "",
                "**No new MHFE release-blocking code defect was confirmed.** The current technical candidate passes with the Low companion-specification caveat. This audit does not certify the final published release: the retained candidate still needs the owner's OpenPGP signature/public key, verification of that signature and current draft inventory, and a final download/check after publication. Signed published-package admission and complete foreign-host application acceptance are separate integration steps.", ""]
        out += ["- " + item for item in report["limitations"]]
        out += ["", "The JSON companion binds the procedure, manifests, scoped reviewer records, commands/logs and audit harness SHA-256 values. Product and specification fingerprints were preserved. Reports/harnesses are reviewable uncommitted additions; the audit performed no commit, push, tag change, release publication, message to another chat or deletion of build folders.", ""]
        return "\n".join(out)


if __name__ == "__main__":
    AuditReport().build()
