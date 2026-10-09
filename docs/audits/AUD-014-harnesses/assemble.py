"""Assemble and validate the source-bound AUD-014 record from retained commands."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

import jsonschema

ROOT = Path.cwd()
BASE = ROOT / "docs/audits"
EVIDENCE = BASE / "AUD-014-evidence"
STEM = "audit-14-2026-10-08"
PRIVACY_NOTE = (
    "Privacy-only metadata redaction: home paths use /home/user, location-specific "
    "annotations are omitted, and timestamps use UTC. Recorded findings, outcomes "
    "and reviewed-source hashes are unchanged; this is not a new audit."
)


def report_text(text):
    # Deliberate copy: each historical audit emitter must remain independently runnable.
    parts = ROOT.resolve().parts
    owner = parts[2] if len(parts) > 2 and parts[1] == "home" else Path.home().name
    return re.sub(re.escape(owner), "user", text, flags=re.IGNORECASE)


def unique(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, f"duplicate JSON key: {key}"
        result[key] = value
    return result


def read(path):
    return json.loads(path.read_text(), object_pairs_hook=unique)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(record):
    jsonschema.Draft202012Validator(read(ROOT.parent / "multi-chain-wallet-tools/docs/audit-report.schema.json")).validate(record)
    markdown = (BASE / (STEM + ".md")).read_text()
    assert {item["id"] for item in record["findings"]} == set(re.findall(r"AUD-014-(?:SEC|FUN|API|BLD|DOC|UI|ARC)\d{3,}", markdown))
    assert len(record["checks"]) == len({item["id"] for item in record["checks"]}) == 32
    for path, expected in record["authorizedAdditions"]["sourceManifest"]:
        assert (not (ROOT / path).exists()) if expected == "deleted" else digest(ROOT / path) == expected
    for path, expected in record["procedureHashes"].items():
        assert digest(ROOT.parent / path) == expected, path
    for path, expected in record["harnessHashes"].items():
        assert digest(ROOT / path) == expected, path
    for item in record["commands"]:
        assert digest(EVIDENCE / (item["label"] + ".log")) == item["logSha256"]
    for target in re.findall(r"\]\(([^)]+)\)", markdown):
        if not target.startswith(("http:", "https:", "#")):
            assert (BASE / target.split("#")[0]).exists(), target
    assert subprocess.run(["git", "check-ignore", str(EVIDENCE / "initial.json")], capture_output=True).returncode == 0
    assert "AUD-014-evidence/" not in subprocess.check_output(["git", "diff", "--cached", "--name-only"], text=True)
    result = {"schema": "passed", "uniqueKeys": True, "pairedFindingIds": True, "checkCount": 32,
              "authorizedChangedFiles": record["authorizedAdditions"]["changedFiles"], "links": "passed",
              "sourceAndProcedureAndHarnessAndLogHashes": "passed", "evidenceIgnoredAndNotStaged": True}
    (EVIDENCE / "report-validation.json").write_text(json.dumps(result, indent=2) + "\n")
    files = sorted(path for path in EVIDENCE.iterdir() if path.is_file() and path.name != "SHA256SUMS")
    (EVIDENCE / "SHA256SUMS").write_text("".join(f"{digest(path)}  {path.name}\n" for path in files))
    print(json.dumps(result, indent=2))


if sys.argv[1:] == ["--validate-only"]:
    validate(read(BASE / (STEM + ".json")))
    raise SystemExit(0)
assert not sys.argv[1:], "Only --validate-only is accepted."


initial = read(EVIDENCE / "initial.json")
final = read(EVIDENCE / "final.json")
before = dict(initial["records"])
after = dict(final["records"])
changed = sorted(path for path in before.keys() | after.keys() if before.get(path) != after.get(path))
assert changed == ["src/word_wishes.rs", "src/word_wishes/known_answers.rs", "src/word_wishes/statistics.rs"]
for path, expected in after.items():
    assert (not (ROOT / path).exists()) if expected == "deleted" else digest(ROOT / path) == expected
for path, expected in initial["procedureHashes"].items():
    assert digest(ROOT.parent / path) == expected, path

findings = [
    {
        "id": "AUD-014-SEC001", "category": "SEC", "kind": "finding",
        "title": "An operation awaiting startup escapes a concurrent full-check failure",
        "severity": "medium", "status": "open", "releaseBlocking": True,
        "releaseBlockingReason": "The documented sticky self-check failure must refuse pending operations before secret encoding and dispatch.",
        "affected": ["web/runtime.js:737-741", "web/runtime.js:784", "web/wallet.js:188", "web/wallet.js:259"],
        "reproduction": "Call drawPhrase with a public chosen word on a fresh MhfeWallet. Hold its passing startup report; call fullCheck and deliver its failed report first. Deliver startup success afterwards. Run integration/gate-race.mjs --controlled and --wasm.",
        "expected": "PackageCheck.require and the public fullCheck contract promise SELF_CHECK_FAILED after any failed part, permanently; fullCheck is explicitly permitted alongside an operation.",
        "observed": "Both probes observe one drawPhrase worker request after the failure. The controlled report fails word-wishes; the actual baseline selfCheckWallet full report fails random-source. The harness refuses the dispatched draw, then exits 1 with 'a failed full check must prevent a waiting draw from being dispatched'.",
        "impact": "A public pending-operation path violates fail-closed policy. The runtime checks #failed only before awaiting startup, not after. Correct host UI gating may avoid overlap. No actual defective phrase, direct key compromise or real-browser race frequency was demonstrated; this shared gate behavior is not a bit-insertion defect.",
        "evidence": ["integration-gate-controlled", "integration-gate-wasm-corrected", "integration-lifecycle-final", "independent bit reviewer challenge of actual dispatch path"],
        "recommendedFix": "Recheck the sticky failure after await in PackageCheck.require; retain a public-class concurrent startup/full failure regression. Consider the narrow dispatch boundary without adding duplicate gate policy.",
        "requiredVerification": "Both gate-race modes must exit 0 with no dispatched draws and SELF_CHECK_FAILED; passing startup and transient worker errors must retain their documented behavior. Recheck all classes sharing the gate and real browsers."
    },
    {
        "id": "AUD-014-SEC002", "category": "SEC", "kind": "finding",
        "title": "Chosen-word filtering retains unguarded first-party secret copies",
        "severity": "low", "status": "open", "releaseBlocking": False,
        "affected": ["src/word_wishes.rs:83-88", "src/word_wishes.rs:220-223", "src/word_wishes.rs:232", "SECURITY.md:34-35", "SECURITY.md:62-65"],
        "reproduction": "Trace WordWishes::met_by for any nonempty wish through packing::with_checksum and collection of all 24 word indices; inspect the concrete buffer owners and their drop behavior. Inspect normalization and WordWishes storage as related copies.",
        "expected": "SECURITY.md promises wiping every first-party owned entropy/phrase buffer, explicitly including the word numbers from which a phrase is drawn. Dependency-internal and uncontrollable compiler copies are separately excepted.",
        "observed": "met_by owns a plain 33-byte entropy/checksum array and a plain Vec<u16> containing the complete 24-word phrase, without a wiping guard. Normalization owns an ordinary lowercase String; WordWishes holds chosen indices in ordinary vectors and derives Clone/Debug. No production logging via Debug was found.",
        "impact": "A bounded best-effort lifecycle contract violation: full phrase indices and entropy have no explicit wipe on release. Inspection proves missing guards, not forensic persistence or disclosure. Exploitation requires memory visibility; worker termination and native anti-dump defenses reduce exposure. Low severity is calibrated to this evidence and earlier owned-copy findings, despite a reviewer's medium recommendation.",
        "evidence": ["first-party source ownership trace", "SECURITY.md owned-buffer contract", "independent bit reviewer confirmation"],
        "recommendedFix": "Use existing wiping owners for packed entropy, phrase indices, normalization and retained chosen-word material. Avoid secret-bearing Debug output. Preserve validated encapsulation and ensure clones follow the same ownership policy.",
        "requiredVerification": "Target native and WASM success, rejection and constructor-error paths; confirm first-party owned copies are guarded and add meaningful regression evidence. Do not imply immutable host strings or compiler copies can be erased."
    }
]

checked = {
    "CHECK-SEC-001": ("failed", "Chosen words are secret; owned-buffer contract violation SEC002; no exfiltration demonstrated."),
    "CHECK-SEC-004": ("passed", "Scoped constrained sampling and bit invariants; no Argon2 or RNG certification."),
    "CHECK-SEC-005": ("failed", "SEC002 first-party copies; lifecycle cancellation cases pass."),
    "CHECK-SEC-007": ("passed", "Bounded, serialized, public-data probes; memory reserve monitoring."),
    "CHECK-FUN-001": ("passed", "All 24 positions, all indices, neighboring bits, final 3+8, predicate and multiplicity controls."),
    "CHECK-API-001": ("passed", "Actual PhraseDraw public API, actual wallet WASM self-check and package methods."),
    "CHECK-API-002": ("failed", "SEC001 concurrent failure gate; 12 healthy worker lifecycle cases pass."),
    "CHECK-API-004": ("passed", "Scoped word index, prefix, case, position, checksum, range and error-redaction boundaries."),
    "CHECK-BLD-001": ("passed", "WordWishes checks belong to the wallet feature; canonical local browser package build, not a canonical Docker rebuild."),
    "CHECK-BLD-002": ("passed", "Targeted native, actual WASM and bounded real-browser wallet smoke; not the full feature matrix."),
    "CHECK-ARC-001": ("passed", "Wish rules owned by library type; frontend calls reviewed in this feature only."),
    "CHECK-ARC-002": ("passed", "New independent oracle duplication is deliberate, commented and confined to verification; no repository-wide no-copy claim."),
    "CHECK-ARC-003": ("passed", "Baseline test blind spots recorded; independently structured oracles and poison controls added and challenged."),
    "CHECK-DOC-001": ("failed", "Wiping and sticky-failure guarantees compared with implementation; odds use an ideal checksum model, not a rigorous finite-sample entropy proof."),
    "CHECK-DOC-003": ("passed", "Paired schema, 32-check ledger, source/procedure/harness/log hashes and ignored evidence validated.")
}
inapplicable = {
    "CHECK-SEC-003": "MHFE has no connected provider/network lookup feature; no egress was introduced.",
    "CHECK-FUN-003": "MHFE has no BIP85/BIP38/message/Silent Payments subsystem.",
    "CHECK-FUN-004": "MHFE has no script/descriptor/Miniscript/multisig subsystem.",
    "CHECK-FUN-005": "MHFE does not construct/sign transactions or PSBTs.",
    "CHECK-FUN-007": "MHFE does not provide connected discovery/provider/accounting services."
}
guide = (ROOT.parent / "multi-chain-wallet-tools/docs/FULL_AUDIT_GUIDE.md").read_text()
checks = []
for check_id, title in re.findall(r"^### (CHECK-[A-Z]+-\d{3}) [^\n]*? (.+)$", guide, re.M):
    outcome, detail = checked.get(check_id, ("not-run", "Outside this targeted chosen/excluded-word audit; no whole-project acceptance inferred."))
    if check_id in inapplicable:
        outcome, detail = "not-applicable", inapplicable[check_id]
    checks.append({"id": check_id, "title": title, "scope": "MHFE chosen/excluded words", "outcome": outcome, "evidenceOrGap": detail})
assert len(checks) == len({item["id"] for item in checks}) == 32
commands = []
for path in sorted(EVIDENCE.glob("*.command.json")):
    item = read(path)
    label = path.name.removesuffix(".command.json")
    assert digest(EVIDENCE / (label + ".log")) == item["logSha256"]
    commands.append({"label": label, **item})
harnesses = sorted((BASE / "AUD-014-harnesses").rglob("*"))
record = {
    "schemaVersion": 1, "auditId": "AUD-014", "auditNumber": 14, "date": "2026-10-08",
    "title": "MHFE chosen-word bit boundaries, sampling and self-check audit",
    "reviewer": {"name": "Codex coordinator with three independently scoped reviewers", "model": None, "reasoningEffort": None,
                 "requestedModelFamily": "gpt-6.1", "requestedReasoningEffort": "ultra", "settingSource": "Coordinator client telemetry unavailable; user-requested label is not fabricated metadata."},
    "reviewerPhases": [{"name": name, "model": "gpt-6.1-sol", "reasoningEffort": "ultra", "source": "Explicit spawn assignment"}
                       for name in ["wishes_bits", "wishes_tests", "wishes_selftests"]],
    "snapshot": {"commit": initial["head"], "commitComplete": True,
                 "workingTree": {"description": "Pre-existing dirty source preserved; explicitly authorized test/self-check additions separately bound.", "initialStatus": initial["status"], "finalStatus": final["status"]},
                 "sourceFingerprint": initial["sourceFingerprint"], "sourceManifest": initial["records"], "capturedAt": initial["capturedAt"]},
    "authorizedAdditions": {"sourceFingerprint": final["sourceFingerprint"], "sourceManifest": final["records"], "capturedAt": final["capturedAt"], "changedFiles": changed, "generatorAlgorithmChanged": False},
    "artifacts": {"initial": initial["artifacts"], "final": final["artifacts"], "finalBuildId": read(ROOT / "dist/modules.json")["buildId"],
                  "relationship": "Baseline native library built after snapshot for oracle. Fresh browser WASM compiled after authorized self-check additions. Native CLI was not rebuilt; no released artifact acceptance."},
    "procedureHashes": initial["procedureHashes"],
    "harnessHashes": {str(path.relative_to(ROOT)): digest(path) for path in harnesses if path.is_file() and "__pycache__" not in path.parts},
    "scope": "Targeted MHFE only: chosen/excluded-word slicing, predicates, constrained distribution, test validity, startup/full feature checks, WASM/class/worker integration and related documentation. Deriver is deliberately reviewed afterwards in a separate record.",
    "checks": checks, "commands": commands, "findings": findings, "observations": [],
    "remediation": [{"id": item["id"], "status": "open", "fixCommit": None, "verificationCommit": None, "evidence": item["evidence"]} for item in findings],
    "testImprovements": [
        "Exhaustive 24 x 2048 x 8 setter cases and reader cases, each compared with independent binary-text oracles.",
        "Startup/full: 624 independent setter and 624 reader cases, exact prior KATs, negative filters/checksum controls and zero-source refusal even with a chosen nonzero word.",
        "Per-position word marginals, correct excluded-word bit probabilities, within/across-word bit joints, anywhere multiplicity, excluded-only and anywhere+excluded datasets.",
        "Poison data must be rejected: clobbered bits, forbidden words, patterned/repeated sources, balanced correlated bits, opposite position biases and random-position insertion.",
        "Baseline five indices miss a middle-bit exchange affecting 1024 values; analytic witness is not a production mutation run. Old df23 chi-square model tail was about1.054e-4, not claimed1e-6; conservative model-tail threshold replaces it."
    ],
    "limitations": [
        "No full-cost Argon2, vector replay, full card generation, complete browser suite, canonical Docker/release verification or historical AUD013 remediation acceptance.",
        "Public API oracle trusts existing BIP39 wordlist and SHA256 after published zero/all-ff vectors; independent oracle covers MHFE bit/filter logic, not those dependencies.",
        "Statistical fixtures use fixed seeds, finite samples and ideal SHA256/checksum modeling; they cannot prove cryptographic entropy or certify the host RNG. They remain unit tests, not startup statistics.",
        "Concurrency witnesses control delivery order; actual WASM self-check failure and actual dispatch are observed, no unsafe phrase is generated.",
        "Owned-copy finding is source-level guard evidence, not freed-memory forensic proof. JavaScript strings and compiler copies cannot be guaranteed erased.",
        "Original harness compile error, too-short scheduling wait, new test-helper Clippy warning/copy and sandbox EPERM are retained separately; no such failures are counted as baseline application defects or passing gates.",
        "RSS is sampled, shared pages may be counted more than once, and process samples cannot diagnose the user's prior freeze.",
        "The UTC report date is October 8. No commit, push, release or other checkout was created."
    ]
}
record["privacyRedaction"] = {
    "kind": "privacy-only-metadata-redaction", "homePath": "/home/user",
    "locationAnnotations": "omitted", "timestampsUTC": True,
    "reviewedSourceHashesUnchanged": True, "findingsAndOutcomesUnchanged": True,
    "newAudit": False,
}
record = json.loads(report_text(json.dumps(record)))
jsonschema.Draft202012Validator(read(ROOT.parent / "multi-chain-wallet-tools/docs/audit-report.schema.json")).validate(record)
(BASE / (STEM + ".json")).write_text(json.dumps(record, indent=2) + "\n")

lines = ["# AUD-014 - MHFE chosen-word bit boundaries, sampling and self-check audit", "", "## Record metadata", "",
         "- **Completed (UTC):** 2026-10-08.",
         "- **Reviewer:** Codex coordinator and three scoped reviewers.",
         "- **Model / reasoning:** requested GPT6.1 / ultra; actual coordinator telemetry unknown. All three scoped reviewers explicitly configured `gpt-6.1-sol`, `ultra`.",
         f"- **Reviewed commit:** `{initial['head']}` plus the dirty working tree.",
         f"- **Baseline source:** `{initial['sourceFingerprint']}` ({len(initial['records'])} paths).",
         f"- **After authorized additions:** `{final['sourceFingerprint']}`; only three word-wishes test/self-check files changed. Production generator/filter/packing logic unchanged.",
         f"- **Fresh browser build:** `{record['artifacts']['finalBuildId']}`. Exact before/after artifact hashes and manifests are in the [JSON companion](" + STEM + ".json). Native CLI not rebuilt.",
         "", "## Finding register", "", "| ID | Category | Kind | Severity | Status | Title |", "| --- | --- | --- | --- | --- | --- |"]
for item in findings:
    lines.append(f"| {item['id']} | {item['category']} | finding | {item['severity']} | open | {item['title']} |")
lines += ["", "## Review evidence", "", "### Scope and methodology", "", record["scope"], "",
          "Baseline was captured before edits and tests; the unchanged baseline was recaptured after its 11 tests. Separate authorization covered necessary tests and startup checks. Memory-sensitive checks used a 3GiB sampled RSS budget and a 2GiB available-memory reserve. Cargo serialized the final overlapping build requests through its output lock; no full-cost workload ran. Only public fixtures were used.", "",
          "Procedure files and SHA256:", ""]
for path, sha in record["procedureHashes"].items():
    lines.append(f"- `{path}`: `{sha}`.")
lines += ["", "### Coverage ledger", "", "| Check ID | Scope | Outcome | Evidence / gap |", "| --- | --- | --- | --- |"]
for item in checks:
    lines.append(f"| {item['id']} | {item['title']} | {item['outcome']} | {item['evidenceOrGap']} |")
lines += ["", "### Checks", "", "Every command below has retained **local-only** log and command metadata in ignored `AUD-014-evidence/`; the JSON companion records exact UTC times, argv, exit, log SHA256 and memory measurements. Counts from overlapping reruns are not added together.", "",
          "| Label / exact command | Exit | Log SHA256 |", "| --- | --- | --- |"]
for item in commands:
    command = " ".join(item["command"]).replace("|", "\\|")
    lines.append(f"| `{item['label']}`: `{command}` | {item['exitCode']} | `{item['logSha256']}` |")
lines += ["", "The baseline bit probe passed **643,072** exact/multiplicity/predicate cases. The strengthened native scoped suite passed **22 tests**; each exhaustive setter/reader test covers **393,216** cases. Statistical draw datasets contain **20,000 accepted phrases** each. The lifecycle probe passes **12** bounded controlled-worker cases. Detailed final real-browser/timing output remains in the corresponding local command log, with its hash above; it is not a full browser-suite acceptance.", "",
          "### Findings", ""]
for item in findings:
    lines.append(f"#### {item['id']} - {item['severity'].title()} - {item['title']}")
    for key, label in [("category", "Category"), ("status", "Status"), ("releaseBlocking", "Release blocking"), ("affected", "Affected files and builds"), ("reproduction", "Reproduction"), ("expected", "Expected behavior"), ("observed", "Observed behavior"), ("impact", "Impact"), ("evidence", "Evidence"), ("recommendedFix", "Recommended fix"), ("requiredVerification", "Required verification")]:
        value = item[key]
        if isinstance(value, list):
            value = "; ".join(value)
        lines.append(f"- **{label}:** {str(value).lower() if isinstance(value, bool) else value}")
    if "releaseBlockingReason" in item:
        lines.append("- **Blocking reason:** " + item["releaseBlockingReason"])
    lines.append("")
lines += ["### Remediation and follow-up", "", "| Finding ID | Status | Fix commit | Verification commit | Evidence |", "| --- | --- | --- | --- | --- |"]
for item in findings:
    lines.append(f"| {item['id']} | open | Not fixed | Not run | Original source/probe evidence above |")
lines += ["", "### Informational observations and recommendations", "", "Authorized improvements, independently challenged and tested:", ""]
lines += ["- " + text for text in record["testImprovements"]]
lines += ["", "These improvements are separate from the two open production findings. New statistical controls are deliberately not run at startup. Correct BIP39 checksums do not establish randomness: the poison cases retain valid checksums.", "",
          "### Assessment and limitations", "", "No slicing, neighboring-bit, final checksum-boundary or constrained-sampling defect was reproduced. The field geometry now has substantially stronger exact and startup coverage. Two independent lifecycle/gating issues remain open; the report does not authorize release or claim that all defects are absent.", ""]
lines += ["- " + text for text in record["limitations"]]
lines += ["", "### Privacy redaction", "", PRIVACY_NOTE]
(BASE / (STEM + ".md")).write_text(report_text("\n".join(lines) + "\n"))
validate(read(BASE / (STEM + ".json")))
