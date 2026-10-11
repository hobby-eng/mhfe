#!/usr/bin/env python3
"""Bind the browser review conclusions to retained AUD-019 evidence and current file bytes."""

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
HOST = ROOT.parent / "multi-chain-wallet-tools"
EVIDENCE = ROOT / "docs/audits/AUD-019-evidence"
HEAD = "66f142566464255e331763966b00ea1681c2dabd"
FIX = "3a705db6945b35f8c248c44893e71ddc36902af4"
RETRY_FIX = "22a1e369bc411e5612c733f672aeaaa87f5aa5c6"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def private_paths(value):
    if isinstance(value, str):
        return value.replace(str(Path.home()), "/home/user")
    if isinstance(value, list):
        return [private_paths(item) for item in value]
    if isinstance(value, dict):
        return {key: private_paths(item) for key, item in value.items()}
    return value


def main():
    outputs = [EVIDENCE / "browser-review.json", EVIDENCE / "browser-malicious-review.json"]
    if any(path.exists() for path in outputs):
        raise SystemExit("Preserving existing browser review evidence")
    inventory = json.loads((EVIDENCE / "browser-inventory.json").read_text())
    bindings = json.loads((EVIDENCE / "browser-loader-source-bindings.json").read_text())
    # Do not silently carry a stale inventory into the conclusions after a concurrent rebuild.
    changed = []
    for record in inventory["files"]:
        base = ROOT if record["repository"] == "mhfe" else HOST
        if digest(base / record["path"]) != record["sha256"]:
            changed.append(f'{record["repository"]}:{record["path"]}')
    if changed:
        raise SystemExit("Inventoried bytes changed: " + json.dumps(changed))
    if git(ROOT, "rev-parse", "HEAD") != HEAD:
        raise SystemExit("The reviewed commit changed")
    commands = []
    for path in sorted(EVIDENCE.glob("browser-*.command.json")):
        item = json.loads(path.read_text())
        item["recordSha256"] = digest(path)
        commands.append(private_paths(item))
    artifacts = [
        {"path": str(path.relative_to(ROOT)), "sha256": digest(path)}
        for path in sorted(EVIDENCE.glob("browser-*"))
        if path.is_file() and path.suffix in {".json", ".log"}
    ]
    procedures = [
        "AGENTS.md", "docs/FULL_AUDIT_GUIDE.md", "docs/audits/AUDIT_STANDARD.md",
        "docs/audits/AUDIT_TEMPLATE.md", "docs/audit-report.schema.json",
    ]
    procedure_hashes = [{"path": path, "repository": "multi-chain-wallet-tools",
                         "sha256": digest(HOST / path)} for path in procedures]
    procedure_hashes.extend([
        {"path": "AGENTS.md", "repository": "mhfe", "sha256": digest(ROOT / "AGENTS.md")},
        {"path": "AGENTS.md", "repository": "workspace", "sha256": digest(ROOT.parent / "AGENTS.md")},
    ])
    reused = [
        "docs/audits/AUD-016-harnesses/browser/page-protocol.mjs",
        "docs/audits/AUD-016-harnesses/browser/worker-cleanup.mjs",
        "docs/audits/AUD-018-harnesses/browser/bounded.sh",
        "docs/audits/AUD-018-harnesses/browser/static-malicious-scan.py",
        "docs/audits/AUD-018-harnesses/browser/loader-source-bindings.py",
    ]
    reviewer = {"task": "browser", "model": None, "actualReasoningEffort": None,
                "availability": "Exact runtime model and actual reasoning effort are not supplied."}
    snapshot = {
        "mhfeHead": HEAD, "nonAuditSourceSha256": "14c21f4c71addda0bb625cb36f5125276628412bdb7ab662ccb1953cf22ba22b",
        "mhfeTrackedWorkingTree": git(ROOT, "status", "--short", "--untracked-files=no"),
        "hostHead": git(HOST, "rev-parse", "HEAD"), "hostWorkingTree": "dirty",
        "hostStatusSha256": hashlib.sha256(git(HOST, "status", "--porcelain=v1", "--untracked-files=all").encode()).hexdigest(),
        "buildId": inventory["packages"]["upstream"]["buildId"],
        "upstreamManifestSha256": digest(ROOT / "dist/modules.json"),
        "hostManifestSha256": digest(HOST / "packages/recovery-mhfe-wasm/generated/modules.json"),
        "inventoryCurrent": not changed,
    }
    prior = [
        {"originalFindingId": "AUD-016-API002", "remediationIntroducingCommit": FIX,
         "runtimeTriggerStatus": "not reproduced", "evidence": "browser-page-protocol-final: null reply, missing error payload and non-text error message reject PACKAGE_MISMATCH, terminate and throw no page handler exception."},
        {"originalFindingId": "AUD-016-API003", "remediationIntroducingCommit": FIX,
         "runtimeTriggerStatus": "not reproduced", "evidence": "browser-page-protocol-final: explicit null repetition/passphrase reject TypeError; undefined-only empty secret helper."},
        {"originalFindingId": "AUD-015-SEC007", "remediationIntroducingCommit": FIX,
         "runtimeTriggerStatus": "not reproduced", "evidence": "browser-page-protocol-final and worker-cleanup: own-property dispatch rejects inherited names."},
        {"originalFindingId": "AUD-017-API001", "remediationIntroducingCommit": FIX,
         "runtimeTriggerStatus": "source remediation present; runtime binding acceptance delegated to coordinator", "evidence": "PhraseJson omits None statedWords; owner callback declaration makes it optional; worker/API/host preserve and render a present conflicting length."},
        {"originalFindingId": "AUD-017-FUN001", "remediationIntroducingCommit": FIX,
         "runtimeTriggerStatus": "source remediation present; runtime cryptographic cases delegated to coordinator", "evidence": "RecoveredForRekey retains detection; 16-bit source wallet check remains evidence, never rekey confirmation; reference/owner comparison required on contradictory reading."},
        {"originalFindingId": "AUD-017-DOC002", "remediationIntroducingCommit": FIX,
         "runtimeTriggerStatus": "documentation corrected in assigned browser scope", "evidence": "API.md and BROWSER-PACKAGE.md describe every 24-word walletCheck with the given passphrase, statedWords precedence, passphrase and walletHasPassphrase rules; 8b256d7d67e38d6c4debe76fc135e874ee9a9f31 further clarifies rekey passphrase disclosure."},
        {"originalFindingId": "AUD-017-UI002", "remediationIntroducingCommit": RETRY_FIX,
         "runtimeTriggerStatus": "not reproduced in synthetic control flow", "evidence": "browser-rekey-retry-current: 1 recover, 2 confirmAgain, 1 ownerAnswer, 1 seal, 1 free; retry on the retained recovery. Actual KDF acceptance belongs to coordinator."},
        {"originalFindingId": "AUD-016-BLD002", "remediationIntroducingCommit": FIX,
         "runtimeTriggerStatus": "stale assertions corrected by source review; real-browser acceptance delegated to coordinator", "evidence": "Current acceptance tests expect walletCheck:null, optional owner statedWords, detection precedence, callback retry/owner refusal and TypeError semantics while retaining negative coverage."},
        {"originalFindingId": "AUD-018-BLD001", "remediationIntroducingCommit": FIX,
         "runtimeTriggerStatus": "old stale package/field trigger no longer evident in current host bytes", "evidence": "Host package 0.6.0, build and full manifest match upstream. Host consumes walletCheck/statedWords, offers passphrase source check, owner comparison and retry confirmation. Host fixes are dirty and cannot be attributed to MHFE commit 66f142.",
         "formalClosure": "MHFE remediation committed; foreign host source fixed at inventoried hashes, signed-release admission and full host browser acceptance not verified here."},
    ]
    limitations = [
        "No real browser, full host suite, full Argon2 operation, build or vector replay was launched by this reviewer; coordinator evidence is shared separately.",
        "Synthetic bindings prove orchestration and observable cleanup, not cryptographic values, native allocation behavior or browser-engine behavior.",
        "No deterministic wipe guarantee exists for JavaScript strings, terminated-worker memory, OS swap or engine copies; documents describe these limits.",
        "Host is a foreign dirty checkout. Its manifest equality and source review do not establish a signed-release admission, clean host commit or passing full host acceptance gate.",
        "WASM review decodes imports/build sections and traces generated glue, not every compiled instruction or toolchain authenticity.",
    ]
    review = {
        "auditId": "AUD-019", "reviewer": reviewer,
        "reviewedUtc": datetime.now(timezone.utc).isoformat(), "snapshot": snapshot,
        "state": "No confirmed new browser product defect in assigned scope; host admission and acceptance are separate gaps.",
        "scope": ["All public core, repair, password and wallet classes and declarations; private runtime, worker dispatch and local WASM binding contracts.",
                  "Recovery, source wallet check, rekey retained recovery and owner confirmation, cancellation and exceptional byte cleanup.",
                  "Current browser docs, generated class/worker bytes and read-only MHFE host handover."],
        "procedureSha256": procedure_hashes, "commands": commands, "artifacts": artifacts,
        "reusedHarnesses": [{"path": path, "sha256": digest(ROOT / path)} for path in reused],
        "checks": [
            {"checkId": "CHECK-API-001", "status": "passed assigned source and synthetic triggers", "evidence": "26 page protocol, 7 worker cleanup, 8 new retry assertions; documented misuse rejects without leaving jobs pending."},
            {"checkId": "CHECK-API-002", "status": "passed assigned source/contracts", "evidence": "Typed inputs, optional/null fields, async rejection, BUSY/cancel/closed lifetimes, bytes owned per job and narrow module APIs traced."},
            {"checkId": "CHECK-BLD-001", "status": "passed local source/artifact identity", "evidence": "All 10 class/declaration files, ordered 8 worker pieces, package hashes and host manifest match. Cross-platform/release identity belongs to coordinator."},
            {"checkId": "CHECK-BLD-002", "status": "passed MHFE source/package handover; host acceptance gap", "evidence": "Current host fields and retry prompt use 0.6.0 APIs. Dirty host admission/full acceptance not independently run."},
            {"checkId": "CHECK-UI-001", "status": "passed browser source review; real-browser matrix delegated", "evidence": "Owner reveal is opt-in, refusal blocks seal, stated length warning precedes comparison, retry offers eligible owner lengths without a default, disposal ends open questions."},
            {"checkId": "CHECK-SEC-002", "status": "passed assigned capability trace", "evidence": "Local Worker/WASM data flow; remote package loaders stubbed; expected loopback launcher/build-test network classified separately."},
            {"checkId": "CHECK-SEC-005", "status": "passed observable owned-byte cleanup", "evidence": "Caller Buffer remains intact; request/answer copies wipe on refusal, cancellation, failed transfer and worker exceptions; sessions free."},
            {"checkId": "CHECK-SEC-006", "status": "passed assigned production sink trace", "evidence": "No browser storage or unintended log sink identified on secret paths; user-requested clipboard/download/reveal are explicit sinks."},
        ],
        "confirmedFindings": [], "originalFindings": prior,
        "hostHandover": {
            "sourceCommitClaim": HEAD, "provenanceSource": "tooling/verify-dependency-provenance.mjs:67",
            "admissionStatus": "Host locally classifies the package as an unreleased pushed-commit build; signed-release replacement is required by its own release gate.",
            "decode": "Initial decrypt uses empty-passphrase default; renders walletCheck/statedWords, then explicitly offers a passphrase check through MhfeWallet.walletCheck with the same recovered 24-word phrase. This avoids another recovery and retains the check explanation.",
            "rekey": "Passphrase/walletHasPassphrase, optional owner statedWords, replacement owner callback and onConfirmAgain are wired. ConfirmAgainPrompt only offers owner for eligible lengths and clears questions on disposal.",
            "locations": ["apps/key-derivation/src/ui/recovery-mhfe-decode.ts:155", "apps/key-derivation/src/ui/recovery-mhfe-decode.ts:183", "apps/key-derivation/src/ui/recovery-mhfe-decode.ts:232", "apps/key-derivation/src/ui/recovery-mhfe-rekey.ts:252", "apps/key-derivation/src/ui/recovery-mhfe-owner-check.ts:103", "apps/key-derivation/src/ui/recovery-mhfe-confirm-again.ts:38"],
            "observation": "Host package README:30 still names Emscripten 6.0.10; current MHFE build uses 6.0.12. This scoped documentation staleness is not evidence of a stale package because all manifest bytes match.",
        },
        "rejectedHypotheses": [
            {"hypothesis": "Retry re-runs the 12 recovery rounds", "resolution": "recoverConfirmed invokes recover once, then confirmAgain; source retains RecoveredForRekey. Synthetic probe observes 1/2 calls."},
            {"hypothesis": "Late asynchronous retry answers survive cancellation/send failure unwiped", "resolution": "wipeSecrets handles both message and nested value; probe observes owned copy zeroed and caller intact."},
            {"hypothesis": "16-bit wallet check or contradictory stated length silently authorizes a rekey", "resolution": "Core confirmation is library-owned; retry must compare a qualifying owner reading or external reference. Source check is only output evidence. Full cryptographic fixtures delegated."},
            {"hypothesis": "A builtInCheck retry answer can bypass ambiguous/contradictory detection", "resolution": "The callback type/docs exclude it; generic runtime confirmation helper may forward it, but core applies the same refusal and authorizes no seal. No supported caller trigger or safety bypass demonstrated."},
            {"hypothesis": "Null optional owner words selects an unauthorized reading", "resolution": "Nullish fallback is restricted to the sole worker-supplied eligible reading; explicit out-of-list length rejects before transfer. No wrong-reading confirmation demonstrated."},
            {"hypothesis": "Generated prototype/encoded payload matches are hidden host hooks", "resolution": "Symbol.dispose aliases own generated session free methods; null-prototype records and embedded standard WASM payloads are expected. Production glue callback capabilities traced separately from test-only overrides."},
        ],
        "limitations": limitations,
        "formalClosureStatement": "Committed MHFE fixes and local trigger verification are distinguished from foreign dirty host closure; no duplicate original finding IDs allocated.",
    }
    malicious = {
        "auditId": "AUD-019", "reviewKind": "Browser source and generated package malicious-code/tampering review",
        "reviewer": reviewer, "reviewedUtc": review["reviewedUtc"], "snapshot": snapshot,
        "state": "No confirmed malicious-code or tampering indicator in examined bytes; this does not establish that a machine or toolchain is uncompromised.",
        "sourceOnly": True, "reviewedTargetExecutedForThisScan": False,
        "inventorySha256": digest(EVIDENCE / "browser-inventory.json"),
        "files": inventory["files"], "lexicalMatches": len(inventory["hits"]), "wasmSurfaces": inventory["wasm"],
        "commands": commands, "confirmedFindings": [],
        "dataFlowEvidence": [
            {"topic": "Secret sources and sinks", "observed": "Class-owned UTF-8 bytes travel by transfer to local disposable workers/WASM and return only to the initiating page. New retry passphrase bytes follow the same nested answer cleanup. Host reveal, clipboard and downloads require a person action; no browser persistence or unintended secret log/network sink identified.", "locations": ["web/runtime.js:132", "web/runtime.js:462", "web/client.js:855", "web/client.js:1149", "web/worker-runtime.js:129", "web/core-worker.js:188", "web/argon2-engine.js:46"]},
            {"topic": "Randomness and hidden triggers", "observed": "Production random sources are self.crypto.getRandomValues; no Math.random fallback identified. hardwareConcurrency sets a bounded draw worker count, crossOriginIsolated selects threading, and timeouts/deadlines constrain resources. Emscripten userAgent/performance references support threading/environment checks. No secret-value/date/machine branch that changes wallet outputs was identified in reviewed JS.", "locations": ["web/worker-runtime.js:62", "web/runtime.js:895", "web/wallet.js:336", "packaging/mhfe-fast-mode.py:164"]},
            {"topic": "Generated loaders and hooks", "observed": "Ten class/declaration files and the 8-piece worker join equal current sources after build stamps. Async URL loaders throw; generated package JS contains no network loader calls. Embedded Argon2 base64 is the compiled module, not opaque executedJS. Symbol.dispose aliases free on the generated session classes and does not modify Object.prototype. Node require/vm/data-URL imports, crypto/slice overrides and fixtures reside in build/verification code, not shipped browser execution.", "locations": ["scripts/remove-network-code.mjs:17", "scripts/remove-network-code.mjs:57", "dist/runtime/worker.js:124", "dist/runtime/worker.js:212", "dist/runtime/worker.js:476", "dist/runtime/worker.js:1996", "scripts/verify-browser-package.mjs:4271"], "bindingEvidenceSha256": digest(EVIDENCE / "browser-loader-source-bindings.json")},
            {"topic": "WASM imports", "observed": "Both mhfe modules expose 19 local callback/object bridge imports. ST Argon2 imports one heap-growth function; MT has shared memory and 13 thread/timing/heap/exit functions. Glue supplies derive/reserve/fill locally. No network/storage capability identified in this import surface; compiled bodies were not disassembled."},
            {"topic": "Expected non-secret network and output", "observed": "Fast-mode launcher binds 127.0.0.1 and serves one checksum-verified HTML snapshot for exact Host GET/HEAD only, without request logging or secret input parsing. Browser-suite loopback servers and public-data local fixtures are verification-only. Host provenance API requests fetch a public GitHub commit, never wallet input. Build/generator file writes produce package/tests/tables and do not consume a person secret.", "locations": ["packaging/mhfe-fast-mode.py:124", "packaging/mhfe-fast-mode.py:277", "packaging/mhfe-fast-mode.py:341", "scripts/verify-browsers.mjs", "tooling/verify-dependency-provenance.mjs:257"]},
        ],
        "limits": limitations + ["The whole foreign host application, browser extensions, OS persistence and dependency provenance are outside this reviewer scope; coordinator/native reviewers own their assigned areas."],
    }
    for path, value in zip(outputs, [review, malicious]):
        path.write_text(json.dumps(private_paths(value), indent=2) + "\n")
    print(json.dumps({"outputs": [{"path": str(path.relative_to(ROOT)), "sha256": digest(path)} for path in outputs], "files": len(inventory["files"]), "confirmedNewFindings": 0}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
