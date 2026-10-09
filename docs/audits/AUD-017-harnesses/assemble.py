#!/usr/bin/env python3
"""Writes the AUD-017 report pair, docs/audits/audit-17-<date>.md and .json, from the findings
below and the command records in docs/audits/AUD-017-evidence/*.command.json.

    python3 docs/audits/AUD-017-harnesses/assemble.py

Run from the repository root after every probe has run. Home-directory paths are written as
/home/user (workspace rule "Report privacy"); the local evidence keeps the original text.
Exits non-zero when a command record is missing a field or a finding lacks a required field.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path.cwd()
EVIDENCE = ROOT / "docs/audits/AUD-017-evidence"
DATE = "2026-10-09"
OUT = ROOT / "docs/audits" / f"audit-17-{DATE}"
HOME = re.compile(r"/home/[a-z_][a-z0-9_-]*")
# The upper-case report labels of the standard's lower-case severities.
LABEL = {"medium": "Medium", "low": "Low"}


def private(value):
    """Anonymizes home paths in every string of `value`."""
    if isinstance(value, str):
        return HOME.sub("/home/user", value)
    if isinstance(value, list):
        return [private(item) for item in value]
    if isinstance(value, dict):
        return {key: private(item) for key, item in value.items()}
    return value


def load_commands():
    rows = []
    for path in sorted(EVIDENCE.glob("*.command.json")):
        record = json.loads(path.read_text())
        for field in ("label", "argv", "startUtc", "endUtc", "exitCode", "seconds", "logSha256"):
            if field not in record:
                sys.exit(f"{path.name} has no {field}")
        rows.append(record)
    rows.sort(key=lambda record: record["startUtc"])
    return rows


PROCEDURE = json.loads((EVIDENCE / "procedure-hashes.json").read_text())
SNAPSHOT = json.loads((EVIDENCE / "snapshot.json").read_text())

REVIEWERS = [
    ("Coordinator", "Snapshot and its comparison with AUD-016's, the challenge of every reviewer "
     "finding against the code, merging of duplicates, the copy gate rerun, report."),
    ("R1 crypto core", "CHECK-SEC-004, CHECK-FUN-001, CHECK-FUN-006: the length rule, the 16-bit "
     "source check, the new negative vector and its independent oracle, rekey and rehearsal."),
    ("R2 native CLI", "CHECK-SEC-001/003/005/006/007, CHECK-UI-001..003: secret handling of the "
     "new passphrase prompt, the rekey loop, the new CLI modules, terminal and signal paths."),
    ("R3 browser package", "CHECK-SEC-001/002/005/006/007, CHECK-API-001/002/004, CHECK-BLD-001: "
     "the built dist/ package in Node at reduced cost, worker protocol, CLI/browser parity."),
    ("R4 build, docs, architecture", "CHECK-BLD-003..005, CHECK-ARC-001..003, "
     "CHECK-DOC-001..003, CHECK-FUN-002 (light): workflows, copy gate, documents, records."),
]

COVERAGE = [
    ("CHECK-SEC-001", "SEC / Secret ownership", "R2, R3", "failed",
     "Container-search words in unwiped strings (SEC001); the decrypt passphrase is hidden, locked "
     "and wiped in the CLI and transferred and wiped in the browser (r3-api-probes P7)."),
    ("CHECK-SEC-002", "SEC / Worker transport", "R3", "passed",
     "Allowlists, Object.prototype names, duplicate and late replies, build checks (P3, P6, P8); "
     "CSP not run in a browser."),
    ("CHECK-SEC-003", "SEC / Egress", "R2", "passed",
     "Per-command isolation unchanged; no new network path."),
    ("CHECK-SEC-004", "SEC / Randomness and encryption", "R1", "passed",
     "Packing, verifiers, length detection and the wallet-check digest recomputed by the probe; "
     "no Argon2 or cipher replay in this audit (the full vector replay of the same tree passed "
     "before the audit)."),
    ("CHECK-SEC-005", "SEC / Lifecycle", "R2, R3", "passed",
     "Signal exit paths, wipes in loops and on errors, cancel while loading."),
    ("CHECK-SEC-006", "SEC / Injection", "R2, R3", "passed",
     "Quoted refusals, serve names, hidden-line filter; no DOM, storage or dynamic code in dist/."),
    ("CHECK-SEC-007", "SEC / Bounds", "R2, R3", "passed",
     "Line capacity, scan-gap range, word positions, worker counts."),
    ("CHECK-FUN-001", "FUN / BIP39", "R1", "passed",
     "Readings by entropy_to_phrase and the NFKD salt of the seed check agree with the probe."),
    ("CHECK-FUN-002", "FUN / HD derivation", "R4", "passed",
     "Light static review; known answers present and able to fail. No new derivation code."),
    ("CHECK-FUN-003", "FUN / BIP85, BIP38, messages", "-", "not-applicable",
     "mhfe has no BIP85, BIP38, message signing or Silent Payments."),
    ("CHECK-FUN-004", "FUN / Scripts and descriptors", "-", "not-applicable",
     "mhfe only decodes addresses to compare them; it builds no scripts or descriptors."),
    ("CHECK-FUN-005", "FUN / Transactions", "-", "not-applicable", "mhfe handles no transactions."),
    ("CHECK-FUN-006", "FUN / Recovery formats", "R1, R3", "failed",
     "Every length-rule branch agrees with the specification (54 cases); rekey with a detected "
     "length still takes the built-in check alone in the library and browser (FUN001)."),
    ("CHECK-FUN-007", "FUN / Discovery and providers", "-", "not-applicable",
     "mhfe contacts no provider; its searches are local."),
    ("CHECK-API-001", "API / Runtime contracts", "R3", "failed",
     "The owner callback lacks the stated length (API001); d.ts and runtime JSON agree."),
    ("CHECK-API-002", "API / Async state", "R3", "passed",
     "Self-check gate, BUSY, cancel, late results."),
    ("CHECK-API-003", "API / Outputs", "R3", "passed",
     "Candidate fields walletCheck, statedWords, otherLengths at runtime (rekey-parity D)."),
    ("CHECK-API-004", "API / Encoding and parity", "R3", "passed",
     "Passphrase UTF-8 and normalization; parity gaps recorded under FUN001 and API001."),
    ("CHECK-BLD-001", "BLD / Features", "R3", "passed",
     "Static only: feature gates, stamps, modules.json; vectors.rs not referenced in the WASM."),
    ("CHECK-BLD-002", "BLD / Matrix sampling", "-", "blocked",
     "Builds and browser suites belong to the concurrent AUD-016 by the owner's split."),
    ("CHECK-BLD-003", "BLD / Lockfiles and licenses", "R4", "passed",
     "Version 0.5.1, exact pins, release profile, actions pinned by SHA."),
    ("CHECK-BLD-004", "BLD / Canonical bytes", "R4", "blocked",
     "Needs Docker; static review found BLD002."),
    ("CHECK-BLD-005", "BLD / Artifacts and CI", "R4, coordinator", "failed",
     "The copy gate of scripts/check.sh fails, and release now requires CI (BLD001)."),
    ("CHECK-ARC-001", "ARC / Ownership", "R2, R4", "failed",
     "The rekey front end decides owner eligibility itself (ARC002)."),
    ("CHECK-ARC-002", "ARC / Duplication", "R2, R4", "failed",
     "One message in five places (ARC001), a typed default (ARC003), copies in BLD001."),
    ("CHECK-ARC-003", "ARC / Comments and fidelity", "R4", "passed",
     "rustfmt and Prettier pass; the earlier stale comment is fixed."),
    ("CHECK-UI-001", "UI / Real viewports", "R2", "passed", "Hint rows fit; explanations tested."),
    ("CHECK-UI-002", "UI / Navigation and inputs", "R2", "failed",
     "Answers without options (UI001); the rekey loop repeats the recovery (UI002)."),
    ("CHECK-UI-003", "UI / Secret visibility", "R2", "passed",
     "The passphrase screen, made passwords, found words on the private screen."),
    ("CHECK-DOC-001", "DOC / Capability descriptions", "R2, R3, R4", "failed",
     "decrypt --help omits the passphrase step (DOC001); the browser documents omit the 0.5.1 "
     "fields (DOC002)."),
    ("CHECK-DOC-002", "DOC / Commands and links", "R4", "passed",
     "Documented options and symbols, links and list layout: 0 problems."),
    ("CHECK-DOC-003", "DOC / Records", "R4", "passed",
     "AUD-009..015 records agree with their JSON; every harness folder has a README; the "
     "procedure reverse edit reproduces the pinned hash. Two historical specification commit "
     "names stay as recorded (see AUD-015 dispositions)."),
]

FINDINGS = [
    {
        "id": "AUD-017-FUN001", "category": "FUN", "severity": "medium",
        "title": "A rekey with the length detected is confirmed by the built-in check alone in "
                 "the library and the browser, while the command-line tool never offers it",
        "affectedFiles": ["src/rehearsal.rs:429", "src/wasm_api/core.rs:918",
                          "src/bin/mhfe/rekey.rs:145-150", "docs/BROWSER-PACKAGE.md:175-178",
                          "docs/API.md:276-278", "scripts/verify-browser-package.mjs:729-735"],
        "reproduction": "rekey({ words: 0, confirmation: { builtInCheck: true } }) on a container "
                        "whose packed state passes one short verifier (r3-rekey-parity part A); "
                        "`mhfe rekey` with the length detected asks only for an address, a "
                        "fingerprint or the owner.",
        "expected": "One rule for both front ends, decided by the library (AGENTS.md: the command "
                    "line and the page offer the same operations).",
        "observed": "refuse_for accepts BuiltInCheck under ConfirmationNeeded::Detected; the "
                    "browser seals the reading; the CLI routes Detected to ask_how_to_confirm.",
        "impact": "A 24-word original that creation flagged (otherLengths [21]) can be sealed "
                  "again as its 21-word reading, another wallet, by the browser without a word-"
                  "count note; its later rehearsal by the built-in check passes. A wrong old "
                  "password reaches the same path through the 21-word layout about once in 2^32. "
                  "Residue of AUD-015-FUN001, whose first recommended fix was not taken.",
        "evidence": ["r3-rekey-parity (exit 1, part A)", "r1-length-rule (exit 0)",
                     "src/rehearsal.rs:429 read by the coordinator"],
        "recommendedFix": "The owner chooses one rule; the library enforces it in refuse_for "
                          "(refuse BuiltInCheck under Detected, or where other_detected_lengths "
                          "is non-empty) or the CLI offers the same answer. Add a case to "
                          "scripts/verify-cli-browser-parity.mjs.",
        "reviewer": "R1, R3 (merged)", "releaseBlocking": False,
        "releaseBlockingReason": "Allowed by the current specification draft; the parity "
                                 "difference needs an owner decision before release.",
    },
    {
        "id": "AUD-017-BLD001", "category": "BLD", "severity": "medium",
        "title": "The copy gate of scripts/check.sh fails on this tree, so CI, and with it the "
                 "release workflow, would fail",
        "affectedFiles": ["scripts/check.sh:32-33", "src/rekey.rs:481-488", "src/rekey.rs:505-512",
                          "src/rekey/known_answers.rs:145-176", "src/rehearsal.rs:617-653",
                          ".github/workflows/release.yml:93-101"],
        "reproduction": "node scripts/verify-no-copies.mjs",
        "expected": "Exit 0, as on every earlier commit.",
        "observed": "Three copies of 50 tokens or more, exit 1: src/rekey/known_answers.rs:145-156 "
                    "= :165-176; src/rehearsal.rs:617-626 = :644-653; src/rekey.rs:481-488 = "
                    ":505-512. All three came with the AUD-015 remediation, which did not run "
                    "this gate.",
        "impact": "Any push fails ci.yml, and release.yml now requires ci.yml, so a v0.5.1 tag "
                  "would never reach the draft.",
        "evidence": ["r4-no-copies (exit 1)", "r4-no-copies-selftest (exit 0)",
                     "coordinator rerun (exit 1, same three copies)"],
        "recommendedFix": "Merge the test helpers detected/stated into one that takes a "
                          "PhraseLength, and factor the known-answer and rehearsal blocks into "
                          "helpers with parameters; rerun the gate.",
        "reviewer": "R4", "releaseBlocking": True,
        "releaseBlockingReason": "The release workflow cannot pass while the gate fails.",
    },
    {
        "id": "AUD-017-SEC001", "category": "SEC", "severity": "low",
        "title": "Container words found by a missing-word search are formatted into ordinary, "
                 "unwiped strings",
        "affectedFiles": ["src/bin/mhfe/container_search.rs:493-498"],
        "reproduction": "Read: `places` is a Vec<String> of \"word N: <word>\"; the library keeps "
                        "Found.container in Zeroizing (src/search.rs:65).",
        "expected": "Zeroizing buffers, as in the AUD-015-SEC006 fix.",
        "observed": "Copies of container-phrase words remain in freed heap memory.",
        "impact": "Bounded: the container also needs the password, and the process is not "
                  "dumpable; still against SECURITY.md's statement on phrase text.",
        "evidence": ["src/bin/mhfe/container_search.rs:493-498 read by the coordinator"],
        "recommendedFix": "Build the lines in Zeroizing<String>.",
        "reviewer": "R2", "releaseBlocking": False, "releaseBlockingReason": "Low, bounded.",
    },
    {
        "id": "AUD-017-API001", "category": "API", "severity": "low",
        "title": "The browser's owner check does not carry the stated length that the command-line "
                 "tool warns about",
        "affectedFiles": ["src/wasm_api/core.rs:778-793", "src/wasm_api/core.rs:945",
                          "web/client.d.ts:300", "src/bin/mhfe/rekey.rs:238-245"],
        "reproduction": "Rekey a zero-12 container with words 15 and the owner's check "
                        "(r3-rekey-parity part B).",
        "expected": "The page learns that the built-in check found 12 words, not the 15 given, "
                    "as src/rekey.rs:107-109 tells callers to say.",
        "observed": "The callback receives only { phrase, words, fingerprintWithoutPassphrase }.",
        "impact": "A page must decide the rule itself (principle 10) or omits the warning.",
        "evidence": ["r3-rekey-parity (exit 1, part B)"],
        "recommendedFix": "Add statedWords to PhraseJson, the d.ts and the documents.",
        "reviewer": "R3", "releaseBlocking": False, "releaseBlockingReason": "Low.",
    },
    {
        "id": "AUD-017-UI001", "category": "UI", "severity": "low",
        "title": "New non-secret questions have no command-line option, and a script cannot give "
                 "the passphrase of the 16-bit source check",
        "affectedFiles": ["src/bin/mhfe/decrypt.rs:199-202", "src/bin/mhfe/container_repair.rs:580",
                          "src/bin/mhfe/rekey.rs:368", "src/bin/mhfe/rekey.rs:398"],
        "reproduction": "decrypt --help, rekey --help (r2-static-cli-rules S3, S4).",
        "expected": "Every non-secret menu answer is also an option of its command (owner rule, "
                    "2026-10-07).",
        "observed": "Whether a passphrase is used, the repair-word count, and how to confirm a "
                    "rekey have no option; decrypt --stdin always checks with the empty "
                    "passphrase and reports the outcome on standard error only.",
        "impact": "A script user whose wallet was drawn with the check gets a 'does not pass' "
                  "hint on almost every run; the browser's decrypt takes a passphrase.",
        "evidence": ["r2-static-cli-rules (exit 1, S3 and S4)"],
        "recommendedFix": "Options such as --passphrase yes|no, --confirm address|fingerprint|show "
                          "and --repair-words N; an optional script line for the passphrase; "
                          "the check's outcome in the script output.",
        "reviewer": "R2", "releaseBlocking": False, "releaseBlockingReason": "Low.",
    },
    {
        "id": "AUD-017-UI002", "category": "UI", "severity": "low",
        "title": "Each pass of the rekey confirmation loop runs the full recovery again, and one "
                 "answer it offers is always refused",
        "affectedFiles": ["src/bin/mhfe/rekey.rs:160-216", "src/rehearsal.rs:552-557"],
        "reproduction": "Read: rekey.rs:175 calls rekey.recover on every pass.",
        "expected": "The readings, once computed, are confirmed without a second recovery; only "
                    "confirmable lengths are offered.",
        "observed": "A stated 15 for a 12-word phrase costs a second recovery (hours at a high "
                    "PIM or memory level); after AmbiguousLength with the owner, 24 is offered "
                    "and refused each time.",
        "impact": "Time and a confusing loop; no secret is lost.",
        "evidence": ["src/bin/mhfe/rekey.rs:160-216 read by the coordinator"],
        "recommendedFix": "A library value that keeps the readings and is confirmed by a "
                          "reference or the owner without recomputing; offer only lengths the "
                          "library accepts.",
        "reviewer": "R2", "releaseBlocking": False, "releaseBlockingReason": "Low.",
    },
    {
        "id": "AUD-017-ARC001", "category": "ARC", "severity": "low",
        "title": "The message 'The built-in check finds N words, not the M you gave' is written "
                 "in five places",
        "affectedFiles": ["src/bin/mhfe/check.rs:345", "src/bin/mhfe/decrypt.rs:294",
                          "src/bin/mhfe/decrypt.rs:323", "src/bin/mhfe/rekey.rs:206",
                          "src/bin/mhfe/rekey.rs:241"],
        "reproduction": "grep -rn \"words, not the\" src",
        "expected": "One source for each message (AGENTS.md rule 6).",
        "observed": "Five copies; the follow-up sentence about reliability is repeated too.",
        "impact": "A wording or rule change reaches some places only.",
        "evidence": ["r2-static-cli-rules (exit 1, S1)", "coordinator grep"],
        "recommendedFix": "One function next to MhfeError::LengthDiffers or one CLI helper.",
        "reviewer": "R2", "releaseBlocking": False, "releaseBlockingReason": "Low.",
    },
    {
        "id": "AUD-017-ARC002", "category": "ARC", "severity": "low",
        "title": "The rekey front end decides itself whether the owner may confirm after "
                 "LENGTH_DIFFERS",
        "affectedFiles": ["src/bin/mhfe/rekey.rs:210", "src/rehearsal.rs:509-559"],
        "reproduction": "Read: rekey.rs:210 tests container.built_in_check_lengths().contains(&stated).",
        "expected": "The library answers (principle 10, delegation).",
        "observed": "The CLI mirrors the library's private rule in one_reading.",
        "impact": "A library change leaves the CLI offering a refused answer or hiding an "
                  "accepted one.",
        "evidence": ["r2-static-cli-rules (exit 1, S2)"],
        "recommendedFix": "Carry the eligibility in LengthDiffers or a Rekey method.",
        "reviewer": "R2", "releaseBlocking": False, "releaseBlockingReason": "Low.",
    },
    {
        "id": "AUD-017-ARC003", "category": "ARC", "severity": "low",
        "title": "The --scan-gap default 20 is typed in help texts, and the option is declared "
                 "twice",
        "affectedFiles": ["src/bin/mhfe/container_repair.rs:29-35",
                          "src/bin/mhfe/container_repair.rs:160-198", "src/search.rs:38"],
        "reproduction": "python3 docs/audits/AUD-017-harnesses/r4-build-docs/typed_defaults.py",
        "expected": "The help is built from search::DECOY_SCAN_GAP; one option struct.",
        "observed": "'default 20' and '20 is the gap' typed by hand in two option structs.",
        "impact": "A changed constant leaves the help stating the old default.",
        "evidence": ["r4-typed-defaults (exit 1)"],
        "recommendedFix": "format! from the constant; one flattened ScanGapOption.",
        "reviewer": "R4", "releaseBlocking": False, "releaseBlockingReason": "Low.",
    },
    {
        "id": "AUD-017-BLD002", "category": "BLD", "severity": "low",
        "title": "The Dockerfile says its canonical stage runs the checks of scripts/check.sh that "
                 "need no terminal, browser or Node packages, but eight such steps are missing",
        "affectedFiles": ["packaging/Dockerfile.reproducible:90-92"],
        "reproduction": "python3 docs/audits/AUD-017-harnesses/r4-build-docs/docker_vs_check.py",
        "expected": "The comment matches the stage, or the stage runs the cheap offline checks.",
        "observed": "Missing: vendored Argon2 hashes, licenses --check, published rounds, the copy "
                    "gate, WASM clippy (all features and per module), cargo doc -D warnings, "
                    "CLI/browser parity.",
        "impact": "A reader trusts a local canonical build as a full gate; CI on the tag still "
                  "covers these steps.",
        "evidence": ["r4-docker-vs-check (exit 1)"],
        "recommendedFix": "Say 'some of the checks', or run the cheap offline ones in the stage.",
        "reviewer": "R4", "releaseBlocking": False, "releaseBlockingReason": "Low.",
    },
    {
        "id": "AUD-017-DOC001", "category": "DOC", "severity": "low",
        "title": "decrypt --help and the README do not describe the new passphrase step of the "
                 "16-bit source check",
        "affectedFiles": ["src/bin/mhfe/decrypt.rs:56-61", "src/bin/mhfe/decrypt.rs:109-119",
                          "README.md:248", "src/bin/mhfe/decrypt.rs:220-223"],
        "reproduction": "target/release/mhfe decrypt --help (r4-help).",
        "expected": "'What it asks for' names the passphrase question; --stdin says the check "
                    "runs without a passphrase.",
        "observed": "Only Container and Password are listed; README.md:248 says decrypt does not "
                    "know the passphrase; one message says 'its wallet check' where the other "
                    "and the specification say 'the 16-bit check'.",
        "impact": "A user is surprised by the question or misreads a script result.",
        "evidence": ["r4-help (exit 0)", "src/bin/mhfe/decrypt.rs read by the coordinator"],
        "recommendedFix": "Add the step and the script behaviour to the help; reword the README "
                          "sentence and the failure hint.",
        "reviewer": "R2", "releaseBlocking": False, "releaseBlockingReason": "Low.",
    },
    {
        "id": "AUD-017-DOC002", "category": "DOC", "severity": "low",
        "title": "The browser documents omit decrypt's passphrase and the 0.5.1 result fields",
        "affectedFiles": ["docs/API.md:660-661", "docs/API.md:697", "docs/API.md:718-721",
                          "docs/BROWSER-PACKAGE.md:157-168", "docs/BROWSER-PACKAGE.md:182-183",
                          "web/client.d.ts:293-296"],
        "reproduction": "python3 docs/audits/AUD-017-harnesses/r4-build-docs/api_md_decrypt.py; "
                        "grep statedWords docs",
        "expected": "decrypt({ passphrase }) and the candidates' walletCheck, statedWords and "
                    "otherLengths, the rekey result's walletCheck and LENGTH_DIFFERS under the "
                    "owner beside 24 words documented.",
        "observed": "None of them in API.md or BROWSER-PACKAGE.md (statedWords only in client.d.ts "
                    "and client.js); the search methods sit under the repair block of API.md.",
        "impact": "An integrator never passes the passphrase and never shows the stated-length "
                  "warning the release notes promise.",
        "evidence": ["r4-api-md-decrypt (exit 1)"],
        "recommendedFix": "Update both usage blocks and the description of the confirmation type; "
                          "move the search lines under core/client.js.",
        "reviewer": "R3, R4 (merged)", "releaseBlocking": False, "releaseBlockingReason": "Low.",
    },
]

DISPOSITIONS = [
    ("AUD-015-FUN001", "partly fixed",
     "Detection always runs; LENGTH_DIFFERS and AMBIGUOUS_LENGTH refuse a contradicted or "
     "ambiguous length under the built-in check; the residue is AUD-017-FUN001."),
    ("AUD-015-SEC001 to SEC006", "fixed in the tree", "R2, file:line evidence in the R2 notes."),
    ("AUD-015-SEC007, API001", "fixed in the tree", "r3-api-probes P2 and P3."),
    ("AUD-015-UI001, UI002, UI005", "fixed in the tree", "UI005 in source; no browser rerun."),
    ("AUD-015-ARC001 to ARC003", "fixed in the tree", "r4-aud015-typed_again_lists exit 0."),
    ("AUD-015-BLD001", "fixed", "docs/releases/history-rewrite-2026-10-09.md, committed in "
     "3c60594; the table matches the current tags."),
    ("AUD-015-BLD002", "fixed in effect", "release.yml runs ci.yml; the Dockerfile comment residue "
     "is AUD-017-BLD002."),
    ("AUD-015-DOC001", "partly fixed",
     "Every mhfe commit reference resolves; two mhfe_spec commits named by audit-02 and audit-08 "
     "no longer exist there and stay as historical bindings (r4-aud015-record_commit_fields)."),
    ("AUD-015-DOC002 to DOC009", "fixed in the tree", "r4-aud015-harness_bindings (106 hashes)."),
]

# The remediation of 2026-10-09 (the owner asked to fix the findings of AUD-016 and
# AUD-017), uncommitted: every finding stays open until a commit records its fix.
REMEDIATION = {
    "AUD-017-FUN001": "The owner's choice of the stricter rule: with the length detected the "
                      "built-in check alone is refused before any Argon2 work in the library "
                      "(Confirmation::refuse_for; ConfirmationNeeded::Detected removed, "
                      "confirmationFor[\"0\"] is \"walletOrOwner\"), so the CLI and the browser "
                      "agree. Tests: rekey::tests::a_detected_length_needs_the_wallet_or_the_owner, "
                      "the rekey self-check's REFERENCE_REQUIRED row, both browser suites; the "
                      "probe rekey-parity exits 0.",
    "AUD-017-BLD001": "The three test copies are one helper each (rekey_of, Refusal table, "
                      "evidence_for); node scripts/verify-no-copies.mjs exits 0.",
    "AUD-017-SEC001": "The found words are written into one Zeroizing buffer reserved at its "
                      "final size (container_search.rs).",
    "AUD-017-API001": "The owner callback's PhraseJson carries statedWords where the check "
                      "found another length; d.ts, documents and both browser suites updated; "
                      "rekey-parity part B exits 0.",
    "AUD-017-UI001": "--repair-words N (encrypt, new, rekey), --passphrase-used yes|no "
                     "(decrypt, rekey) and --confirm check|address|fingerprint|show (rekey); a "
                     "script gives decrypt the passphrase on a third line with --passphrase-used "
                     "yes. static_cli_rules S3/S4 pass.",
    "AUD-017-UI002": "Rekey::recover_state recovers once into a RecoveredForRekey, and "
                     "Rekey::confirm confirms it as often as a confirmation is refused; "
                     "owner_can_confirm and lengths_the_owner_can_confirm tell the CLI which "
                     "answers to offer. Test: a_refused_confirmation_is_followed_by_another_on_the_"
                     "same_recovery.",
    "AUD-017-ARC001": "phrase_length::check_finds and MORE_RELIABLE are the one wording; "
                      "static_cli_rules S1 passes.",
    "AUD-017-ARC002": "The CLI asks Rekey::owner_can_confirm; static_cli_rules S2 passes.",
    "AUD-017-ARC003": "One ScanGapOption, its help built from DECOY_SCAN_GAP; typed_defaults "
                      "exits 0.",
    "AUD-017-BLD002": "The Dockerfile says \"some of the checks\"; docker_vs_check exits 0.",
    "AUD-017-DOC001": "decrypt --help lists the passphrase step and --stdin's third line; the "
                      "README sentence and the failure hint name the 16-bit check.",
    "AUD-017-DOC002": "API.md and BROWSER-PACKAGE.md describe decrypt's passphrase, the "
                      "candidate fields, the rekey walletCheck and statedWords; api_md_decrypt "
                      "exits 0.",
}

FOLLOW_UP = {
    "dateUtc": "2026-10-09",
    "sourceFingerprint": "a9dd0d88f13b0e66910eb62a085b29c4fce0b10f3e4f9723e47226bb89ed4f54",
    "files": 554,
    "commit": None,
    "summary": "Every AUD-017 finding and every AUD-016 finding has a fix in the uncommitted "
               "tree, made by the owner's instruction; each stays open here until a commit "
               "records it. FUN001 took the stricter of the two rules: a detected length is "
               "confirmed by an address, the fingerprint or the owner in every front end. The "
               "same remediation fixed the AUD-016 findings (cancel inside an address search, "
               "the fingerprint error that repeated a pasted phrase, the memory-locking claim, "
               "wide characters, malformed worker replies, explicit null secrets, the stale "
               "browser suite) and the path-controls remnant of AUD-015-SEC002 that AUD-016's "
               "probe found. The informational observations on the rehearsal's source check, "
               "the 24-word status label, the two exempt-name lists, the signal read-back and "
               "invisible formatting characters are addressed too. Source fingerprint "
               "a9dd0d88...4f54 (554 files, AUD-016's harness files included); release binary "
               "SHA-256 73f17222...7c7d built with remapped paths; browser package build "
               "817e72e40b707f90, on which the checks below ran. A doc comment re-wrapped after "
               "it moved line numbers that the binaries carry; AUD-018 rebuilt both from the same "
               "source, the package as build cc38bfadd2bfe9b2, equal to its canonical build.",
    "checks": [
        "The offline steps of scripts/check.sh, each exit 0: vendored Argon2 hashes, licenses, "
        "published rounds, cargo fmt, the copy gate and its self-test, clippy native, WASM and "
        "each of the four browser modules, cargo test (343 library and 118 CLI tests passed, 2 ignored each; the vector "
        "and doc targets pass), cargo doc -D warnings (after one fix of a private link), self-test, "
        "hidden input, Argon2 WASM, browser package, CLI/browser parity, fast-mode script, "
        "release artifacts (after a rebuild with remapped paths), Prettier.",
        "scripts/verify-browsers.mjs in Chromium 153 and Firefox 155, standard and fast mode: "
        "1934 assertions ok, exit 0, after one stale copy count was corrected (log SHA-256 "
        "6a11b971...2266, local evidence).",
        "Every AUD-017 probe now exits 0: static_cli_rules, typed_defaults, api_md_decrypt, "
        "docker_vs_check, rekey-parity, api-probes, static-scan, length_rule_probe.",
        "AUD-016's native probes fingerprint-redaction, unicode-cursor and path-controls exit 0; "
        "dumb-container still shows the container under TERM=dumb, which AUD-016 records as an "
        "observation (containers are public ciphertext). The low-memlock witness was not "
        "rebuilt; mhfe self-test under RLIMIT_MEMLOCK 4096 now reports that 8192 bytes could "
        "not be locked.",
        "Not run: the full-size vector replays (they ran on this tree's vectors before the "
        "audit, and no vector or cipher code changed), the canonical Docker build.",
    ],
}

OBSERVATIONS = [
    "The rehearsal computes the 16-bit source check only when not exactly one short reading "
    "passes (src/rehearsal.rs:335), although its comparison can match the 24-word reading.",
    "RecoveryStatus::ReadAs24Chosen applies whenever the length was stated (src/mhfe.rs:156), "
    "also when a short length was stated.",
    "STATED_READING_ONLY is kept by hand in src/vectors.rs:620 and scripts/independent-suite3.py "
    "without a test tying them; the oracle cannot fail selected-24-words on the length rule, as "
    "the vector README documents.",
    "The applied specification says a stated short length that matches nothing gives no reading; "
    "an earlier intended wording allowed offering the 24-word reading. The code follows the "
    "applied text.",
    "A 16-bit pass with the empty passphrase is chance only, since draws need a non-empty "
    "passphrase; the specification requires the check with the empty passphrase as well, so "
    "both front ends are consistent with it.",
    "protect.rs:70 does not read back the result of sigaction for the quit and suspend routing, "
    "and no startup check reports it.",
    "hidden_input.rs:494 hides C0/C1 controls but shows Cf characters such as U+202E on visible "
    "lines (the person's own input only).",
    "typed_line.rs:166 slices bytes, safe only because every hint is ASCII.",
    "scripts/verify-cli-browser-parity.mjs covers repair words, early refusals and the "
    "other-lengths warning, but no recovery result, rekey, search, new, password tool or "
    "self-test, so it could not catch FUN001 or API001.",
    "ci.yml's canonical-build job (60-minute timeout) runs on every branch push; its duration was "
    "not measured against the rule on hour-long checks.",
    "AGENTS.md does not list scripts/verify-no-copies.mjs and verify-cli-browser-parity.mjs "
    "among its commands.",
    "src/vectors.rs is newer than the dist/ build, but nothing in the WASM references it; dist/ "
    "is current for every browser feature.",
]

LIMITATIONS = [
    "By the owner's split with the concurrent AUD-016, this audit ran no cargo build or test, no "
    "WASM build, no browser suite, no Docker build and no full-size Argon2; CHECK-BLD-002 and "
    "CHECK-BLD-004 are blocked. AUD-016 reviews the same source bytes (manifest equal but for "
    "its own harness files), so its build results apply to this snapshot.",
    "The independent full replay of every suite 3 vector, including the new negative case, ran "
    "on the same tree just before this audit (scripts/independent-suite3.py, 18 files, all "
    "reproduced); its record is tests/fixtures/suite3-vectors/independent-verification.json.",
    "The browser probes ran the built dist/ in Node at 256 KiB and one pass; the CSP and real "
    "browsers were not exercised.",
    "Repair-word changes in src/repair.rs were only skimmed.",
    "Model and reasoning effort are recorded as reported by the client.",
]


def check(finding):
    for field in ("id", "category", "severity", "title", "affectedFiles", "reproduction",
                  "expected", "observed", "impact", "evidence", "recommendedFix", "reviewer",
                  "releaseBlocking", "releaseBlockingReason"):
        if field not in finding:
            sys.exit(f"{finding.get('id')} has no {field}")


def markdown(commands):
    medium = sum(f["severity"] == "medium" for f in FINDINGS)
    lines = [
        "# AUD-017 - mhfe compact audit of the 0.5.1 working tree, parallel to AUD-016", "",
        "## Record metadata", "",
        f"- Audit: AUD-017, {DATE} (UTC).",
        f"- Reviewed snapshot: `{SNAPSHOT['head']}` on `{SNAPSHOT['branch']}` with the "
        f"uncommitted 0.5.1 changes; source fingerprint `{SNAPSHOT['sourceFingerprint']}` over "
        f"{SNAPSHOT['files']} files, captured {SNAPSHOT['capturedUtc']}.",
        "- Concurrent audit: AUD-016 (another tool) on the same source bytes; the two manifests "
        "differ only in AUD-016's own harness files.",
        "- Reviewer: Claude Code, model claude-opus-5-5; reasoning effort not retained by the "
        "client.",
        "- Procedure SHA-256:",
    ]
    lines += [f"  - `{path}`: `{digest}`" for path, digest in PROCEDURE.items()]
    lines += [
        "- Evidence: `docs/audits/AUD-017-evidence/` (local only, not committed).",
        "- Harnesses: [AUD-017-harnesses](AUD-017-harnesses/README.md).", "",
        "## Finding register", "",
        "| ID | Severity | Release blocking | Status | Title |",
        "| --- | --- | --- | --- | --- |",
    ]
    for f in FINDINGS:
        lines.append(f"| {f['id']} | {LABEL[f['severity']]} | "
                     f"{'yes' if f['releaseBlocking'] else 'no'} | open | {f['title']} |")
    lines += ["", "## Review evidence", "", "### Scope and methodology", "",
              "An ordinary audit with a compact team: a coordinator and four reviewers, at most two "
              "at a time, reading the tree and running small probes only. Every reviewer finding "
              "was checked against the code by the coordinator before it was accepted; two pairs "
              "of duplicates were merged (FUN001 from R1 and R3, DOC002 from R3 and R4).", ""]
    lines += [f"- {name}: {scope}" for name, scope in REVIEWERS]
    lines += ["", "### Coverage ledger", "", "| Check | Area | Owner | Status | Evidence |",
              "| --- | --- | --- | --- | --- |"]
    lines += [f"| {c} | {a} | {o} | {s} | {e} |" for c, a, o, s, e in COVERAGE]
    lines += ["", "### Checks", "",
              "Commands run through `run.py`; logs and records are local evidence.", "",
              "| Label | Command | Exit | Seconds | Log SHA-256 |", "| --- | --- | --- | --- | --- |"]
    for c in commands:
        argv = " ".join(c["argv"]).replace("|", "\\|")
        lines.append(f"| {c['label']} | `{argv}` | {c['exitCode']} | {c['seconds']} | "
                     f"`{c['logSha256'][:16]}…` |")
    lines += ["", "### Findings", ""]
    for f in FINDINGS:
        lines += [
            f"#### {f['id']} - {LABEL[f['severity']]} - {f['title']}", "",
            f"- Status: open. Release blocking: {'yes' if f['releaseBlocking'] else 'no'} "
            f"({f['releaseBlockingReason']})",
            f"- Reviewer: {f['reviewer']}.",
            "- Affected: " + ", ".join(f"`{p}`" for p in f["affectedFiles"]) + ".",
            f"- Reproduction: {f['reproduction']}",
            f"- Expected: {f['expected']}",
            f"- Observed: {f['observed']}",
            f"- Impact: {f['impact']}",
            "- Evidence: " + "; ".join(f["evidence"]) + ".",
            f"- Recommended fix: {f['recommendedFix']}", "",
        ]
    lines += ["### Earlier findings", "", "| Finding | Disposition | Evidence |",
              "| --- | --- | --- |"]
    lines += [f"| {i} | {d} | {e} |" for i, d, e in DISPOSITIONS]
    lines += ["", "### Remediation follow-up, 2026-10-09 (uncommitted)", "",
              FOLLOW_UP["summary"], "",
              "| Finding | Fix |", "| --- | --- |"]
    lines += [f"| {f['id']} | {REMEDIATION[f['id']]} |" for f in FINDINGS]
    lines += ["", "Checks after the fixes:", ""]
    lines += [f"- {item}" for item in FOLLOW_UP["checks"]]
    lines += ["", "### Informational observations and recommendations", ""]
    lines += [f"- {o}" for o in OBSERVATIONS]
    lines += ["", "### Assessment and limitations", "",
              f"{len(FINDINGS)} open findings: {medium} medium and {len(FINDINGS) - medium} low; no "
              "critical or high. One is release blocking (BLD001, the failing copy gate). FUN001 "
              "needs the owner's decision on one rekey rule for both front ends. The length rule "
              "of the specification draft, the 16-bit source check and the new negative vector "
              "agree with the implementation and an independent oracle. No release acceptance: "
              "builds, browsers and canonical bytes were outside this audit.", ""]
    lines += [f"- {item}" for item in LIMITATIONS]
    return "\n".join(lines) + "\n"


def record(commands):
    medium = sum(f["severity"] == "medium" for f in FINDINGS)
    return {
        "schemaVersion": 1, "auditId": "AUD-017", "auditNumber": 17, "date": DATE,
        "title": "mhfe compact audit of the 0.5.1 working tree, parallel to AUD-016",
        "reviewer": {"name": "Claude Code", "model": "claude-opus-5-5", "reasoningEffort": None,
                     "reasoningEffortSource": "not retained by the client"},
        "snapshot": {"commit": SNAPSHOT["head"], "commitComplete": False,
                     "workingTree": {"status": SNAPSHOT["status"], "files": SNAPSHOT["files"]},
                     "sourceFingerprint": SNAPSHOT["sourceFingerprint"],
                     "capturedUtc": SNAPSHOT["capturedUtc"]},
        "procedureHashes": PROCEDURE,
        "scope": "Uncommitted 0.5.1 working tree of mhfe: library, command line, WASM bindings, "
                 "browser package, documents, workflows and audit records; read-only with small "
                 "probes, builds left to the concurrent AUD-016.",
        "checks": {
            "coverage": [{"id": c, "area": a, "owner": o, "status": s, "evidence": e}
                         for c, a, o, s, e in COVERAGE],
            "commands": commands,
            "summary": f"{len(commands)} recorded commands; reviewers: "
                       + ", ".join(name for name, _ in REVIEWERS) + ".",
        },
        "findings": [dict(f, kind="finding", status="open",
                          requiredVerification="The reproduction no longer reproduces; a test "
                                               "covers the case.")
                     for f in FINDINGS],
        "observations": [],
        "informationalObservations": OBSERVATIONS,
        "earlierFindings": [{"id": i, "disposition": d, "evidence": e}
                            for i, d, e in DISPOSITIONS],
        "remediation": [{"id": f["id"], "status": "fixed", "fixCommit": None,
                         "verificationCommit": None, "evidence": REMEDIATION[f["id"]]}
                        for f in FINDINGS],
        "remediationFollowUp": FOLLOW_UP,
        "limitations": LIMITATIONS,
        "assessment": f"{len(FINDINGS)} findings: {medium} medium and "
                      f"{len(FINDINGS) - medium} low; one release blocking (BLD001).",
    }


def main():
    for finding in FINDINGS:
        check(finding)
    commands = load_commands()
    OUT.with_suffix(".md").write_text(private(markdown(commands)))
    OUT.with_suffix(".json").write_text(
        json.dumps(private(record(commands)), indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {OUT.name}.md and .json: {len(FINDINGS)} findings, {len(commands)} commands")


if __name__ == "__main__":
    main()
