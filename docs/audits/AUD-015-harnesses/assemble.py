#!/usr/bin/env python3
"""Writes the AUD-015 report pair, docs/audits/audit-15-<date>.md and .json, from the findings
below and the command records in docs/audits/AUD-015-evidence/*.command.json.

    python3 docs/audits/AUD-015-harnesses/assemble.py

Run from the repository root after every command has run. Home-directory paths are written as
/home/user (workspace rule "Report privacy"); the local evidence keeps the original text.
Exits non-zero when a command record is missing a field or a finding lacks a required field.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path.cwd()
EVIDENCE = ROOT / "docs/audits/AUD-015-evidence"
DATE = "2026-10-09"
OUT = ROOT / "docs/audits" / f"audit-15-{DATE}"
HOME = re.compile(r"/home/[a-z_][a-z0-9_-]*")


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
# The commit that the second owner-authorized privacy rewrite of 2026-10-09 made of the reviewed
# commit (its old-to-new map is local, with the rewrite's journal).
SECOND_REWRITE_HEAD = "abb16671b641378c0fc3c4d855f8d126498e754b"
BASELINE = json.loads((EVIDENCE / "snapshot-baseline.json").read_text())
AFTER = json.loads((EVIDENCE / "snapshot-after-rewrite.json").read_text())

REVIEWERS = [
    ("Coordinator", "Snapshot, baseline commands (scripts/check.sh steps under the owner's hold), "
     "dispositions of earlier findings, challenge of every reviewer finding, report."),
    ("R1 crypto core", "CHECK-SEC-004, CHECK-FUN-001, CHECK-FUN-006: MHFE cipher, Argon2 engines, "
     "password rule, suites 3 and 4, repair words, check word, wallet check, rekey, hidden wallets, "
     "search; conformance with mhfe_spec."),
    ("R2 native CLI", "CHECK-SEC-001/003/005/006/007 and CHECK-UI-001..003 for the terminal: "
     "secret ownership, isolation, mhfe serve, exceptional paths, terminal injection, bounds, "
     "word hints."),
    ("R3 browser package", "CHECK-SEC-001/002/005/006/007, CHECK-API-001/002, "
     "CHECK-BLD-001/002: WASM bindings, worker protocol, self-check gate, CSP, manifest."),
    ("R4 wallet features", "CHECK-FUN-002, CHECK-SEC-004 for draws, CHECK-API-003/004, word "
     "wishes and word hints, addresses of 12 coins against independent oracles."),
    ("R5 build, docs, architecture", "CHECK-BLD-003/004/005, CHECK-ARC-001..003, "
     "CHECK-DOC-001..003, including the privacy history rewrite made during the audit."),
]

COVERAGE = [
    ("CHECK-SEC-001", "SEC / Secret ownership", "R2, R3", "failed",
     "CLI: check-word repair labels unwiped (SEC006), stdout buffer undocumented (DOC007); browser "
     "transfer and wipe paths passed (r3-api-probes P1)."),
    ("CHECK-SEC-002", "SEC / Worker transport", "R3", "failed",
     "Inherited Object.prototype names dispatched as page callbacks (SEC007); late replies, "
     "unknown operations and build checks pass."),
    ("CHECK-SEC-003", "SEC / Egress", "R2", "passed",
     "seccomp, Landlock, network namespace read back; mhfe serve loopback-only with request "
     "limits (r2-serve-live-2, r2-menu-isolation-3)."),
    ("CHECK-SEC-004", "SEC / Randomness and encryption", "R1, R4", "passed",
     "27 published transcripts replayed by an independent oracle; reduced-cost containers "
     "recomputed; Unicode 17 password rule over every scalar value; draw rates and bit figures "
     "measured."),
    ("CHECK-SEC-005", "SEC / Lifecycle", "R2, R3", "failed",
     "SIGQUIT/SIGTERM/Ctrl+Z leave the private screen (SEC004); browser failure paths pass."),
    ("CHECK-SEC-006", "SEC / Injection", "R2, R3", "failed",
     "Control sequences from typed answers and a checksum file reach the terminal (SEC002); the "
     "browser package has no DOM, network or dynamic code beyond Blob workers."),
    ("CHECK-SEC-007", "SEC / Bounds", "R2, R3", "passed",
     "Line capacity, numeric limits, serve limits, worker counts and whole-number checks."),
    ("CHECK-FUN-001", "FUN / BIP39", "R1, R4", "passed",
     "22,143 typed phrases against the spec's reading rule; NFKD seed and wallet check."),
    ("CHECK-FUN-002", "FUN / HD derivation", "R4", "passed",
     "43 table rows and 679 further cases of 12 coins against independent derivation; 9 "
     "fingerprints."),
    ("CHECK-FUN-003", "FUN / BIP85, BIP38, messages", "-", "not-applicable",
     "mhfe has no BIP85, BIP38, message signing or Silent Payments."),
    ("CHECK-FUN-004", "FUN / Scripts and descriptors", "-", "not-applicable",
     "mhfe only decodes addresses to compare them; it builds no scripts or descriptors."),
    ("CHECK-FUN-005", "FUN / Transactions", "-", "not-applicable", "mhfe handles no transactions."),
    ("CHECK-FUN-006", "FUN / Recovery formats", "R1", "failed",
     "Suites 3/4, repair words, check word and wallet check conform; rekey with detected length "
     "confirmed by the built-in check alone (FUN001)."),
    ("CHECK-FUN-007", "FUN / Discovery and providers", "-", "not-applicable",
     "mhfe contacts no provider; the address search is local."),
    ("CHECK-API-001", "API / Runtime contracts", "R3, R4", "failed",
     "drawPhrase accepts a non-boolean walletCheck and any workers when unchecked (API001); "
     "library and other class methods pass."),
    ("CHECK-API-002", "API / Async state", "R3", "passed",
     "Self-check gate on both paths, AUD-014-SEC001 race regression in both modes, cancel, BUSY, "
     "late results."),
    ("CHECK-API-003", "API / Outputs", "R4", "passed",
     "JSON results of the wallet module against independent expectations (208,874 checks)."),
    ("CHECK-API-004", "API / Encoding and parity", "R4", "passed",
     "Native and WASM agree on every wallet case; the parity script covers no wallet, password "
     "or hint operation (observation)."),
    ("CHECK-BLD-001", "BLD / Features", "R3, coordinator", "passed",
     "Each browser feature passes clippy alone; stamps and manifest consistent; dist rebuilt "
     "byte for byte."),
    ("CHECK-BLD-002", "BLD / Matrix sampling", "R3", "blocked",
     "Single-feature WASM builds were not sampled at runtime: Rust builds were stopped after the "
     "host froze under memory pressure."),
    ("CHECK-BLD-003", "BLD / Lockfiles and provenance", "R5", "passed",
     "Exact pins, lockfile checksums, vendored Argon2 hashes, EFF list hash, notices check."),
    ("CHECK-BLD-004", "BLD / Canonical builds", "R5", "not-run",
     "Owner hold: no Docker. Static review only."),
    ("CHECK-BLD-005", "BLD / CI and releases", "R5", "failed",
     "Release path skips several check.sh steps (BLD002); rewritten tags break release "
     "provenance (BLD001)."),
    ("CHECK-UI-001", "UI / Terminal widths", "R2", "failed",
     "Word hints wrap below 42 columns (UI001); HTML viewports not applicable (no HTML tool)."),
    ("CHECK-UI-002", "UI / Navigation and input", "R2, R4", "failed",
     "A refused --never-use value loops (UI002); menus, steps and word keys pass."),
    ("CHECK-UI-003", "UI / Secret visibility", "R2, R4", "failed",
     "A made password is shown on the main screen without a private screen (SEC003)."),
    ("CHECK-ARC-001", "ARC / Boundaries", "R5", "passed",
     "Logic in library modules; front ends translate; each browser module alone."),
    ("CHECK-ARC-002", "ARC / Duplication", "R4, R5", "failed",
     "Typed-again word-count lists (ARC001); duplicated address table (ARC002)."),
    ("CHECK-ARC-003", "ARC / Comments and tests", "R5", "failed", "Stale exit-code comment (ARC003)."),
    ("CHECK-DOC-001", "DOC / Capabilities", "R2..R5", "failed",
     "Conformance claim, review list, API.md, SECURITY.md and lifecycle wording (DOC003..DOC009)."),
    ("CHECK-DOC-002", "DOC / Commands and links", "R5", "passed",
     "Links, anchors, options, symbols, Prettier and list layout pass."),
    ("CHECK-DOC-003", "DOC / Audit records", "R5", "failed",
     "Privacy rewrite left old commit references and broken harness bindings (DOC001, DOC002)."),
]


def finding(fid, severity, title, blocking, reason, files, reproduction, expected, observed,
            impact, evidence, fix, verification, source):
    return {
        "id": f"AUD-015-{fid}", "category": re.sub(r"\d+$", "", fid), "kind": "finding",
        "title": title, "severity": severity, "status": "open", "releaseBlocking": blocking,
        "releaseBlockingReason": reason, "affectedFiles": files, "reproduction": reproduction,
        "expected": expected, "observed": observed, "impact": impact, "evidence": evidence,
        "recommendedFix": fix, "requiredVerification": verification, "reviewer": source,
    }


FINDINGS = [
    finding("SEC001", "medium",
            "The reference of a missing-word search records any typed text, a mistyped seed "
            "phrase included, in the main-screen summary",
            True, "A secret typed into a public field by mistake reaches the scrollback; the fix "
            "is small.",
            ["src/bin/mhfe/check.rs:546", "src/bin/mhfe/check.rs:779", "SECURITY.md:13"],
            "mhfe check --fingerprint --pim 0 with the public zero-12 container, word 24 as ?, "
            "repair words skipped, search by the container's own wallet; at 'Address or master "
            "key fingerprint:' type the public zero-12 seed phrase; Ctrl+C at the coin question "
            "(r2-cli/search_reference_record.py).",
            "Nothing is recorded until the text has been read as a fingerprint or as an address "
            "of the chosen coin; a secret typed into a public field never reaches the main screen.",
            "The parse closure accepts any text that is not eight hex digits as an address, so "
            "read_public records 'Reference <text>' at once; the summary on the main screen holds "
            "the whole phrase (and raw escape sequences when typed).",
            "A pasted seed phrase or password stays in the terminal's scrollback and any log. "
            "Needs a user error; no Argon2 run.",
            ["local-only: r2-search-reference-record-2.log (exit 1)",
             "docs/audits/AUD-015-harnesses/r2-cli/search_reference_record.py"],
            "Record the reference only after it is parsed (fingerprint, or Address::parse for the "
            "chosen coin), in its validated form; refuse text that reads as a BIP39 phrase.",
            "search_reference_record.py exits 0; a unit test that an invalid address records "
            "nothing; the terminal suite's search cases pass.", "R2"),
    finding("SEC002", "low",
            "Control sequences from typed answers and from the fast-mode checksum file are "
            "written raw to the terminal",
            False, "No secret is exposed.",
            ["src/wallet.rs:187", "src/wallet.rs:687", "src/bin/mhfe/serve.rs:171",
             "src/bin/mhfe/menu.rs:148", "src/bin/mhfe/style.rs:406"],
            "A checksum file naming 'x<ESC>]0;TITLE<BEL><ESC>[2Jy.html' next to a page served by "
            "mhfe serve; a fingerprint answer holding ESC sequences, at a terminal and with "
            "--stdin (r2-cli/serve_checksum_name.py, public_answer_echo.py).",
            "Untrusted text is shown with control characters neutralised, as the secret prompts "
            "promise (SECURITY.md:29).",
            "Refusal messages quote the input verbatim and anstream passes the escapes through "
            "on a colour terminal; the checksum file's page name is printed verbatim.",
            "A crafted answer or file can retitle the window or clear and overwrite lines, for "
            "example hide a warning.",
            ["local-only: r2-serve-checksum-name.log (exit 1)",
             "local-only: r2-public-answer-echo-2.log (exit 1)"],
            "Replace C0/C1 control characters and DEL in user- or file-derived text in one "
            "display helper, or stop quoting raw input in library messages.",
            "The two probes exit 0 in colour mode; a unit test of the helper.", "R2"),
    finding("SEC003", "low",
            "A password made by --new-password is shown on the main screen where no private "
            "screen can be opened",
            False, "Needs an explicit made-password option on a terminal without the alternate "
            "screen.",
            ["src/bin/mhfe/encrypt.rs:419", "src/bin/mhfe/made_password.rs:186", "README.md:281"],
            "TERM=dumb mhfe encrypt --pim 0 --new-password words in a pseudo-terminal, stopped "
            "before Argon2 (r2-cli/made_password_dumb.py).",
            "README: a password the tool makes is shown once on a private screen; mhfe new "
            "refuses to start where it cannot show one.",
            "The five words appear on the main screen, again after each empty type-back.",
            "The new container password stays in the scrollback.",
            ["local-only: r2-made-password-dumb.log (exit 1)"],
            "Refuse a made kind where no private screen can be entered, as new and wallets do.",
            "made_password_dumb.py exits 0; the terminal suite's made-password case passes.", "R2"),
    finding("SEC004", "low",
            "Ctrl+\\, Ctrl+Z or SIGTERM leave the private screen showing secrets and lose the "
            "summary",
            False, "Secrets stay on the alternate screen, not in the scrollback.",
            ["src/bin/mhfe/terminal.rs:310", "src/bin/mhfe/hidden_input.rs:624",
             "src/bin/mhfe/chosen_words.rs:135"],
            "mhfe new --pim 0, choose a word, type 'zoo' on the private screen, Ctrl+\\ at the "
            "visible position prompt (r2-cli/quit_key_private_screen.py).",
            "The private screen is cleared and left whenever the tool ends (SECURITY.md).",
            "Only SIGINT has a handler; VQUIT/VSUSP are disabled only inside hidden prompts and "
            "lists. The process dies by SIGQUIT with the chosen word still shown.",
            "Secrets remain displayed after the tool ended; no summary or 'NOT verified' alarm.",
            ["local-only: r2-quit-key-private-screen.log (exit 1)"],
            "Route SIGQUIT/SIGTERM/SIGHUP through the Ctrl+C restore path and disable VQUIT/VSUSP "
            "while a step flow or private screen is active.",
            "quit_key_private_screen.py exits 0; a terminal test for Ctrl+\\ and SIGTERM.", "R2"),
    finding("SEC005", "low",
            "An encryption shows the unverified container before its check when standard output "
            "is another terminal",
            False, "Needs output redirected to a second terminal.",
            ["src/bin/mhfe/encrypt.rs:218", "src/bin/mhfe/terminal.rs:583", "SECURITY.md:76"],
            "Source trace: show_sealing decides from io::stdout().is_terminal(), not from "
            "terminal::output_on_screen(); reaching the callback needs full-cost Argon2.",
            "Output that is not the person's screen gets the container only after its check "
            "(SECURITY.md:76-81; AUD-008-SEC004 treats another terminal as redirected).",
            "The second terminal receives an unmarked container before rounds 13 to 24; the "
            "warning and the outcome go to standard error only.",
            "A container copied there could be relied on although its check later failed.",
            ["source lines cited (coordinator confirmed encrypt.rs:218)"],
            "Use terminal::output_on_screen() (or can_show_privately) for person_reads_output.",
            "A pseudo-terminal test with standard output on a second terminal.", "R2"),
    finding("SEC006", "low",
            "The check-word repair offer keeps password words in ordinary, unwiped strings",
            False, "Bounded to the review at a terminal.",
            ["src/bin/mhfe/check_word.rs:188", "src/bin/mhfe/choice.rs:379", "SECURITY.md:34"],
            "Source trace: the answer labels 'Word N: <word> instead of <typed>' and their drawn "
            "lines are plain Strings, rebuilt on each redraw.",
            "Every buffer the program owns that holds a password is wiped when dropped "
            "(SECURITY.md:34-35).",
            "The labels and drawn lines are freed without wiping and are not locked.",
            "Copies of password words stay in freed heap memory.",
            ["source lines cited"],
            "Build these labels and lines in Zeroizing buffers.",
            "A unit test that the review labels are wiped; check-word terminal cases pass.", "R2"),
    finding("SEC007", "low",
            "The page dispatches worker messages named after Object.prototype members as page "
            "callbacks",
            False, "Only a worker that sends such names reaches it; the package's own worker "
            "never does.",
            ["web/runtime.js:237", "web/runtime.js:259", "web/worker-runtime.js:141"],
            "With a stand-in worker, reply {type:'valueOf'} or ask with question 'toString' "
            "(r3-browser/api-probes.mjs P3).",
            "An inherited name is handled like an unknown one, as the worker side does with "
            "Object.hasOwn.",
            "valueOf/hasOwnProperty/__proto__ end the job with CALLBACK_FAILED; question "
            "'toString' is answered.",
            "Protocol inconsistency and misleading error codes; defense in depth.",
            ["local-only: r3-api-probes.log (exit 1, P3)"],
            "Look up handlers with Object.hasOwn or null-prototype maps; treat a missing handler "
            "as a protocol error.",
            "api-probes.mjs P3 passes; a regression in verify-browser-package.mjs.", "R3"),
    finding("FUN001", "medium",
            "A rekey with an automatically detected length is confirmed by the built-in check "
            "alone, although the specification requires the verifier at the word count the owner "
            "supplies",
            True, "Deviates from a MUST of the specification; the owner decided on 2026-10-09 to "
            "bring the library to the specification.",
            ["src/rehearsal.rs:409", "src/rehearsal.rs:484", "src/rekey.rs:137",
             "src/wasm_api/core.rs:805", "docs/API.md:264", "docs/BROWSER-PACKAGE.md:174",
             "mhfe_spec README.md:428"],
            "Encrypt the spec's public 24-word fixture whose entropy packs a 21-word state, then "
            "RekeySession with words 0 and recover('builtInCheck') in the browser package at "
            "reduced cost (r1-crypto/wasm_probe.mjs part 3).",
            "mhfe_spec Re-encryption: a short source MUST pass its verifier at the word count "
            "supplied by the owner. The CLI conforms: with --words auto it asks for an address, a "
            "fingerprint or the owner.",
            "The detected 21-word reading is accepted as verified and sealed; the new container "
            "drops the word-count advice. The library's Confirmation::refuse_for allows it, and "
            "the self-check, tests and documents state it.",
            "About once in 2^32 a wrong password or a misread 24-word original is sealed as a "
            "verified shorter phrase; discarding the old container would then lose the wallet.",
            ["local-only: r1-wasm-probe.log (exit 0; part 3 asserts the observed behaviour)"],
            "Refuse BuiltInCheck under ConfirmationNeeded::Detected in the library; in addition "
            "(owner, 2026-10-09) check every length's verifier when a length is stated and say "
            "which reading passes.",
            "wasm_probe.mjs part 3 expects REFERENCE_REQUIRED; library unit test; RekeyCheck "
            "self-check case; verify-browser-package rekey section; parity test.", "R1"),
    finding("API001", "low",
            "MhfeWallet.drawPhrase accepts a non-boolean walletCheck and an out-of-range workers "
            "when the phrase is not checked",
            False, "The result reports walletCheck:false; no secret is exposed.",
            ["web/wallet.js:168", "web/wallet.js:182", "web/wallet.d.ts:93"],
            "drawPhrase({walletCheck:'yes'}), ({walletCheck:1}), ({workers:0}), "
            "({workers:'many'}), ({workers:1e9}) with a stand-in worker "
            "(r3-browser/api-probes.mjs P2).",
            "A wrongly typed argument rejects with a TypeError (BROWSER-PACKAGE.md), as "
            "describeDraw does.",
            "All calls resolve with one unchecked draw.",
            "A page bug such as the string 'true' silently gives an unchecked phrase.",
            ["local-only: r3-api-probes.log (exit 1, P2)"],
            "Check walletCheck's type and the workers range whatever the passphrase.",
            "api-probes.mjs P2 passes; cases in verify-browser-package.mjs.", "R3"),
    finding("BLD001", "medium",
            "Rewritten, re-signed release tags break the source binding of the published "
            "v0.3.0 to v0.5.0 releases",
            True, "Blocks publishing the rewritten history until provenance stays checkable.",
            ["scripts/package-release.sh:65", "README.md:845", "docs/RELEASING.md:56"],
            "git for-each-ref refs/tags: v0.5.0 points at 5a37293 (was 52b6b36), v0.4.0 at "
            "f42ed54, v0.3.0 at 00693dd; 52b6b36 and 4c3a690 no longer exist locally; "
            "refs/remotes/origin/main was moved to f4f7b01 although nothing was pushed.",
            "A published archive's provenance and BUILD-INFO 'source:' name a commit a user can "
            "fetch (README:845, RELEASING.md:56).",
            "If the rewritten tags and main are pushed, the commits the releases were built from "
            "leave the repository's refs.",
            "Archive bytes stay verifiable by SHA256SUMS and its signature, but not their source "
            "commit.",
            ["local-only: r5-history-rewrite.log", "coordinator: git for-each-ref, git cat-file"],
            "Before publishing the rewrite, keep the original tag commits reachable (archive "
            "refs) or publish a signed old-to-new map; restore refs/remotes by a fetch.",
            "After publication, attestations and BUILD-INFO commits resolve, or the map explains "
            "each.", "R5"),
    finding("BLD002", "low",
            "The tag release path runs only part of scripts/check.sh, and the Dockerfile's "
            "'same fast checks as CI' comment is no longer true",
            False, "The person who signs the release is the remaining barrier.",
            ["packaging/Dockerfile.reproducible:91", "scripts/check.sh:17",
             ".github/workflows/release.yml:19"],
            "Compare the verified stage's steps with check.sh; release.yml does not require CI "
            "on the tagged commit.",
            "The release path cannot skip the mandatory checks (CHECK-BLD-005).",
            "Missing: vendored Argon2 hashes, notices check, published-rounds check, copy check, "
            "WASM clippy per feature, doc warnings, the terminal suite and the parity script.",
            "A tag on an unchecked commit still produces a draft release.",
            ["static review of the cited lines"],
            "Share one step list between check.sh and the verified stage, or require the CI job "
            "for the tagged commit; correct the comment.",
            "Static diff; one canonical build at release.", "R5"),
    finding("UI001", "low",
            "Word hints wrap in 24- to 41-column terminals and the typed line is then drawn on "
            "the hint row",
            False, "Display only; the typed data is unaffected.",
            ["src/bin/mhfe/typed_line.rs:21", "src/bin/mhfe/typed_line.rs:107"],
            "mhfe check in a 32-column pseudo-terminal, 'a' then 'b' at the container prompt, "
            "replayed on a VT100 model (r2-cli/hint_rows_narrow.py).",
            "Each hint row fits the terminal, so the cursor returns to the typed line.",
            "The 40-column count hint wraps from 24 columns, and the next letter lands on the "
            "hint row.",
            "A garbled private screen in narrow windows.",
            ["local-only: r2-hint-rows-narrow.log (exit 1)"],
            "Count the rows each hint takes, or raise the narrowest width above the longest "
            "fixed hint.",
            "hint_rows_narrow.py exits 0; a LineScreen unit test at 30 columns.", "R2"),
    finding("UI002", "low",
            "mhfe new asks the chosen-word question again and again when its --never-use value "
            "is refused",
            False, "The person can only cancel.",
            ["src/bin/mhfe/chosen_words.rs:64", "src/bin/mhfe/chosen_words.rs:95"],
            "mhfe new --never-use notaword in a pseudo-terminal, 'Every word at random' three "
            "times (r4-wallet/never-use-loop.py).",
            "A refused answer is asked again so that it can be corrected, or the option is "
            "refused at the start.",
            "The option's word is reused on every loop; each answer is refused with the same "
            "message.",
            "The command cannot go on after a typo in the option.",
            ["local-only: r4-never-use-loop.log (exit 1)"],
            "Check --never-use with the library rule at the start, or ask for the word again.",
            "never-use-loop.py exits 0; a terminal test for an invalid --never-use.", "R4"),
    finding("UI003", "low",
            "A word never to use with the wallet check is rated 'Not recommended', with advice "
            "about where to put a chosen word",
            False, "A misleading warning; no security effect.",
            ["src/word_wishes.rs:165", "src/bin/mhfe/chosen_words.rs:182", "README.md:501"],
            "mhfe new --never-use abandon with passphrase TREZOR and the check, no chosen word "
            "(r4-wallet/never-use-check-warning.py); describeDraw('', [], 'abandon', true).",
            "README: a word never to use tells too little to matter, and from 240 bits the "
            "phrase has far more than enough.",
            "239.98 bits are rated 'Not recommended', and the 'anywhere vs fixed position' "
            "advice is shown although no word was chosen.",
            "Users may be pushed away from the check or confused.",
            ["local-only: r4-never-use-check-warning.log (exit 1)",
             "local-only: r4-never-use-odds-wasm.log (exit 0)"],
            "Rate by the chosen word only, or round; show the placement advice only for a word "
            "at a fixed position.",
            "A unit test of odds(16) with a never-use word only; the probe exits 0.", "R4"),
    finding("UI004", "low",
            "Word hints stop saying that no word begins like this once the typed word is longer "
            "than nine letters",
            False, "The phrase reader still refuses the word later.",
            ["src/word_hints.rs:156", "README.md:239"],
            "Every prefix of both lists and word+'xyz' compared with the documented rule "
            "(r4-wallet rust-probe hints; wasm-parity.mjs).",
            "A word of letters that no list word begins with gives 'no word'.",
            "A token longer than nine letters gives no hint at all.",
            "Someone typing past a wrong word loses the warning.",
            ["local-only: r4-probe-hints.log (exit 1)", "local-only: r4-wasm-parity.log (exit 1)"],
            "Treat a longer run of letters as a word with no match.",
            "The probes exit 0; a unit test for 'abandonxyz'.", "R4"),
    finding("UI005", "low",
            "The SELF_CHECK_FAILED message has a double period in Chromium when WebAssembly is "
            "blocked",
            False, "Cosmetic.",
            ["web/runtime.js:840", "web/runtime.js:937"],
            "A page without 'wasm-unsafe-eval' in Chromium calls wallet.fingerprint() "
            "(r3-browser/csp-page.mjs).",
            "One clean sentence a page can show as it is.",
            "'...\".. Do not use this program on this computer'.",
            "A fatal-error screen reads badly.",
            ["local-only: r3-csp-chromium.log"],
            "Strip a trailing period before appending the advice.",
            "csp-page.mjs chromium.", "R3"),
    finding("ARC001", "low",
            "Word-count lists are typed again in refusal messages instead of derived from their "
            "constants",
            False, "Maintenance rule; messages could state an old limit after a change.",
            ["src/repair.rs:266", "web/client.js:967", "web/repair.js:50",
             "src/bin/mhfe/container_repair.rs:65", "src/bin/mhfe/encrypt.rs:120"],
            "r5-build-docs/typed_again_lists.py.",
            "AGENTS.md rule 6: a value that follows from another is derived, never typed again "
            "(phrase::counts_text exists).",
            "Five messages and one help text spell the lists by hand.",
            "A changed limit would leave old numbers in messages.",
            ["local-only: r5-typed-again-lists.log (exit 1)"],
            "Build each message from its constant.",
            "typed_again_lists.py exits 0; message assertions pass.", "R5"),
    finding("ARC002", "low",
            "The 43-row wallet address table is kept twice, with no test keeping the copies in "
            "step",
            False, "Both copies are correct today.",
            ["src/wallet.rs:1258", "src/wallet/known_answers.rs:412"],
            "Compare the two ADDRESSES tables; no test compares them.",
            "AGENTS.md rule 6: one source, or a stated copy with a test.",
            "Two equal tables, maintained separately.",
            "A correction to one copy can miss the other.",
            ["local-only: r4-address-oracle.log (exit 0, the table reproduced)"],
            "Let the unit test use known_answers::ADDRESSES.",
            "cargo test wallet::.", "R4"),
    finding("ARC003", "low",
            "A stale exit-code comment says 'No, stop' at the first question of a rekey exits "
            "130",
            False, "No runtime effect.",
            ["src/bin/mhfe/exit.rs:18", "src/bin/mhfe/rekey.rs:391", "src/bin/mhfe/exit.rs:102"],
            "Read the CANCELLED comment against the current rekey questions and exit mapping.",
            "AGENTS.md: remove a comment when the code it describes changes.",
            "The comment names a question removed in 0.5.1; the remaining 'No, stop' exits 3.",
            "Misleads a maintainer.",
            ["source lines cited"],
            "Drop the clause.", "Read the comment against exit.rs.", "R5"),
    finding("DOC001", "medium",
            "The privacy history rewrite updated audit-record commit references only partly",
            True, "Blocks publishing the rewritten history: published records would cite commits "
            "that exist nowhere.",
            ["docs/audits/audit-03-2026-09-30.json", "docs/audits/audit-07-2026-10-05.json",
             "docs/audits/audit-10-2026-10-07.json", "docs/audits/README.md:13",
             "docs/audits/AUD-005-decisions.md"],
            "r5-build-docs/record_commit_fields.py, before and after the redaction session "
            "pruned the old objects.",
            "AGENTS.md: a commit an audit record names is rewritten only together with that "
            "record, whose hashes are then updated; Markdown and JSON agree.",
            "66 structured fields were moved; 48 fixCommit/verificationCommit fields in "
            "audit-03..07 and 68 prose references still name replaced, now pruned commits; one "
            "record mixes old and new names for the same commit; the AUD-006 index row names "
            "old commits.",
            "The remediation evidence of AUD-003..AUD-007 can no longer be traced to source.",
            ["local-only: r5-history-rewrite.log", "local-only: r5-record-commit-fields.log",
             "local-only: r5-record-commit-fields-after-prune.log"],
            "Map every remaining old hash with the redaction's old-to-new map and record the map "
            "in each privacyRedaction block.",
            "record_commit_fields.py exits 0; a prose scan finds no pre-rewrite commit.", "R5"),
    finding("DOC002", "low",
            "The privacy rewrite changed nine harness READMEs whose SHA-256 the audit records "
            "bind, without a binding",
            False, "The files changed only in commit references.",
            ["docs/audits/audit-08-2026-10-06.json", "docs/audits/audit-10-2026-10-07.json",
             "docs/audits/audit-13-2026-10-08.json", "docs/audits/audit-14-2026-10-08.json"],
            "r5-build-docs/harness_bindings.py.",
            "Each edited bound file gets a privacyRedaction.documentBindings entry.",
            "106 bindings checked, 9 no longer match and carry no binding.",
            "A reader verifying harness integrity sees unexplained changes.",
            ["local-only: r5-harness-bindings.log (exit 1)"],
            "Add the nine documentBindings entries.", "harness_bindings.py exits 0.", "R5"),
    finding("DOC003", "low",
            "The v0.5.1 notes claim conformance with published specification v0.5.0, while rekey "
            "no longer obtains a confirmation that v0.5.0 requires",
            False, "Resolved by publishing the revised specification or stating the deviation.",
            ["docs/releases/v0.5.1.md:1", "docs/releases/v0.5.1.md:113",
             "mhfe_spec README.md:441"],
            "Compare mhfe_spec v0.5.0 README lines 440-447 with the notes and the uncommitted "
            "spec change.",
            "The notes name the specification text the release follows.",
            "The relaxed rule (owner decision, AUD-007-FUN002 addendum) exists only in an "
            "uncommitted mhfe_spec change; the notes still cite v0.5.0.",
            "A conformance claim a reader can check and find false.",
            ["git show v0.5.0:README.md in mhfe_spec (reviewer R5)"],
            "Publish the spec revision and cite it, or state the deviation in the notes.",
            "Notes and README cite a specification whose text matches rekey.", "R5"),
    finding("DOC004", "low",
            "The v0.5.1 notes' Reviews section says AUD-010 audited the whole of this work and "
            "omits AUD-011 to AUD-015",
            False, "Documentation only.",
            ["docs/releases/v0.5.1.md:340"],
            "Read lines 340-349 against the audit index.",
            "The notes describe the reviews of the release accurately.",
            "Only AUD-009 and AUD-010 are named.",
            "Overstates AUD-010 and hides later records.",
            ["source lines cited"],
            "List AUD-011 to AUD-015 and drop 'the whole of this work'.",
            "Read the notes against the index.", "R5"),
    finding("DOC005", "low",
            "docs/API.md omits the browser API of chosen words and word hints, and its "
            "WebAssembly export list is stale",
            False, "BROWSER-PACKAGE.md and the .d.ts files are complete.",
            ["docs/API.md:704", "docs/API.md:820", "docs/API.md:844"],
            "Compare API.md with the js_name exports of src/wasm_api and the glue's exports "
            "(r3-browser/static-scan.mjs S3).",
            "API.md names every class method and export (workspace rule: API.md is part of a "
            "finished browser binding).",
            "describeDraw, wordHints and the new parameters fields are missing; the export list "
            "names 'check' (the export is CheckSession) and omits searchCandidates, searchDecoy, "
            "searchWallet, inspectContainer, describeDraw and wordHints; the secrets sentence "
            "omits chosen words and typed lines.",
            "An integrator gets a stale API description.",
            ["local-only: r3-static-scan.log (exit 1, S3)"],
            "Update the usage block and export list from the actual exports.",
            "static-scan.mjs S3 passes.", "R3, R4"),
    finding("DOC006", "low",
            "SECURITY.md says only Backspace, Ctrl+U, Enter, Ctrl+D and Ctrl+C edit a secret's "
            "line, but Tab and Ctrl+W edit lines of words",
            False, "Documentation only.",
            ["SECURITY.md:26", "src/bin/mhfe/hidden_input.rs:13"],
            "Read SECURITY.md:26-29 against Content::Words handling.",
            "SECURITY.md matches the keys of each kind of line.",
            "Tab completes and Ctrl+W deletes a word in seed-phrase, container and chosen-word "
            "lines.",
            "The security contract is stale.",
            ["source lines cited; local-only: hidden-input.log"],
            "State the word-line keys in SECURITY.md.", "Documentation review.", "R2"),
    finding("DOC007", "low",
            "SECURITY.md names the standard library's stdin buffer but not its stdout line "
            "buffer, which keeps the last secret line printed",
            False, "Best-effort claim inaccurate.",
            ["SECURITY.md:39", "src/bin/mhfe/terminal.rs:430"],
            "Source trace through anstream to std's LineWriter.",
            "SECURITY.md lists the residual copies outside the program's control.",
            "The stdout buffer is neither named nor wiped.",
            "An extra unlocked plaintext copy for the life of the process.",
            ["source lines cited"],
            "Name the buffer, or write secret lines whole from a locked buffer.",
            "Documentation review.", "R2"),
    finding("DOC008", "low",
            "Documents say a cancelled operation stops its worker at once, but a worker still "
            "loading is kept until it loads",
            False, "No exploitable effect.",
            ["docs/BROWSER-PACKAGE.md:866", "web/client.js:734", "web/client.d.ts:558",
             "web/runtime.js:241"],
            "r3-browser/api-probes.mjs P6; worker-runtime.js:113-126 against runtime.js:241-256.",
            "Documents match the deferred termination and the order of the build check.",
            "The promise rejects at once but the worker stays until 'ready'; the build check "
            "runs after the worker has started the operation.",
            "Overstates how soon transferred secrets are released.",
            ["local-only: r3-api-probes.log (P6)"],
            "Reword the three places.", "Documentation review.", "R3"),
    finding("DOC009", "low",
            "An orphaned MhfeErrorCode doc comment and a misplaced strength() JSDoc",
            False, "Editor tooltips only.",
            ["web/runtime.d.ts:102", "web/passwords.js:84"],
            "r3-browser/static-scan.mjs S1c.",
            "Each doc comment precedes its code.",
            "A comment of a removed code remains; strength()'s JSDoc sits on wordHints().",
            "Wrong tooltips.", ["local-only: r3-static-scan.log (S1c)"],
            "Delete the orphan; move the JSDoc.", "static-scan.mjs S1c passes.", "R3"),
]

DISPOSITIONS = [
    ("AUD-011-SEC001", "Fix in the reviewed working tree; regression in verify-browser-package.mjs."),
    ("AUD-011-ARC001", "Fix in the working tree (diceware.rs uses the library message; R2)."),
    ("AUD-011-DOC001", "Fix in the working tree: API.md no longer states a literal count."),
    ("AUD-012-SEC001", "Fix in the working tree; worker count bounded before encoding (R3)."),
    ("AUD-012-SEC002", "Fix in the working tree: RecoveredPhrase keeps a private LockedText."),
    ("AUD-012-ARC001", "Fix in the working tree; r5-aud012-clone-checker exit 0."),
    ("AUD-012-ARC002", "Fix in the working tree; r5-aud012-clone-checker exit 0."),
    ("AUD-013-DOC001", "Fix in the working tree; doctests 4 passed (cargo-test.log)."),
    ("AUD-013-SEC001", "Fix in the working tree; secrets owned before decoding (R3)."),
    ("AUD-013-API001", "Fix in the working tree: address counts are u128."),
    ("AUD-013-ARC001", "Fix in the working tree; r5-aud013-clone-controls 17/17."),
    ("AUD-013-ARC002", "Fix in the working tree; r5-aud013-clone-controls 17/17."),
    ("AUD-013-ARC003", "Fix in the working tree; r5-aud013-clone-controls 17/17."),
    ("AUD-014-SEC001", "Fix in the working tree; r3-aud014-gate-race-controlled and -wasm exit 0."),
    ("AUD-014-SEC002", "Fix in the working tree: met_by reads words from Zeroizing bits; "
     "WordWishes is ZeroizeOnDrop with a redacting Debug."),
]

OBSERVATIONS = [
    "All 27 published MHFE transcripts (17 suite 3, 10 suite 4) were reproduced from the "
    "specification text by an independent oracle without Argon2; reduced-cost containers were "
    "recomputed with OpenSSL Argon2id; the Unicode 17 password rule agrees with ICU for every "
    "scalar value (R1).",
    "All 43 wallet-table rows and 679 further cases of 12 coins agree with an independent "
    "derivation; a fresh public MHFE-WALLET-CHECK-SEED-1 vector with an NFKD passphrase was "
    "found and agrees in the library and the browser package (R4).",
    "Rebuilding dist/ from the snapshot gave byte-identical files (dist-unchanged).",
    "AUD-007-FUN002 (the rekey question about funds in other wallets) is superseded by an owner "
    "decision recorded in the AUD-007 Markdown addendum; the specification change it needs is "
    "uncommitted in mhfe_spec (see DOC003).",
    "During the review another session rewrote the history of mhfe for an owner-authorized "
    "privacy redaction: HEAD 4c3a6909 became ca0086ac; against the baseline only docs/audits/* "
    "and docs/measurements/full-operation-2026-09-30.json changed in the working tree; no source "
    "file changed (snapshot-after-rewrite).",
    "The parity script compares no wallet, password or word-hint operation; the R4 probes "
    "covered those against independent references.",
    "The startup set takes about 246 ms in a release build, 201 ms of it the container-search "
    "part (coordinator, 2026-10-09).",
    "Hypotheses not reproduced: the search by the original's own wallet check takes the first "
    "of about 8 candidates that pass 16 bits (about 1e-4 for a wrong one, R1); a hidden-wallet "
    "session cannot tell the main password for a 24-word original (R1); a panic in a secret flow "
    "leaves the terminal unrestored (R2); a transient WebAssembly compile failure closes a class "
    "for good (R3).",
]

LIMITATIONS = [
    "Owner hold on long runs: no full browser suite (scripts/verify-browsers.mjs), no full-size "
    "vector replays (tests/suite3_vectors.rs ignored tests, mhfe self-test --vectors), no "
    "full-cost Argon2, no canonical Docker build.",
    "The host froze at about 23:26 UTC under memory pressure while five reviewers ran; after the "
    "reboot reviewers ran two at a time without new Rust builds, so single-feature WASM runtime "
    "sampling (CHECK-BLD-002) is blocked.",
    "Windows and macOS code paths were reviewed from source only; no network was used, so "
    "GitHub settings, upstream sources and the remote tags were not read.",
    "Residual memory was not measured: the native tool is non-dumpable; findings about unwiped "
    "copies are source-traced.",
    "This is a compact-team audit with automated probes and independent oracles; it is not a "
    "certification and does not show that no defect remains.",
]


def ids_line(rows):
    return ", ".join(rows)


def markdown(record, commands):
    lines = [f"# AUD-015 - mhfe full audit of the 0.5.1 working tree", "", "## Record metadata", ""]
    snapshot = record["snapshot"]
    lines += [
        "- **Audit number:** 15.",
        f"- **Completed (UTC):** {record['date']}.",
        f"- **Reviewer:** {record['reviewer']['name']}.",
        f"- **Model:** {record['reviewer']['model']}.",
        f"- **Reasoning effort:** {record['reviewer']['reasoningEffort']}.",
        "- **Reviewer phases:** five reviewers of the same model with distinct scopes (below); "
        "their reasoning effort was not recorded.",
        f"- **Reviewed commit:** {snapshot['commit']}. The review started at "
        f"{snapshot['commitBeforeRewrite']}, which the owner-authorized privacy rewrite replaced "
        f"by {snapshot['commitAfterFirstRewrite']} during the review, with the same source files; "
        "the second privacy rewrite of the same day replaced that by this commit, changing audit "
        "documents and one comment in src/bin/mhfe/hidden_input.rs. The source fingerprint binds "
        "the reviewed bytes.",
        f"- **Working tree:** {snapshot['workingTree']['description']}",
        f"- **Source fingerprint:** {snapshot['sourceFingerprint']} ({BASELINE['files']} files); "
        f"after the rewrite {snapshot['sourceFingerprintAfterRewrite']}.",
        f"- **Artifacts:** {record['artifacts']['description']}",
        "",
        "## Finding register",
        "",
        "| Finding ID | Category | Kind | Severity | Status | Release blocking | Title |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in record["findings"]:
        lines.append(f"| {item['id']} | {item['category']} | finding | {item['severity']} | "
                     f"{item['status']} | {'yes' if item['releaseBlocking'] else 'no'} | "
                     f"{item['title']} |")
    lines += ["", "## Review evidence", "", "### Scope and methodology", "", record["scope"], "",
              "Team:", ""]
    for name, scope in REVIEWERS:
        lines.append(f"- **{name}:** {scope}")
    lines += ["", "Procedure files and SHA-256:", ""]
    for name, digest in record["procedureHashes"].items():
        lines.append(f"- `{name}`: `{digest}`.")
    lines += ["", f"Environment: {record['environment']}", "", "### Coverage ledger", "",
              "| Check ID | Category / logical group | Owner | Outcome | Evidence / gap |",
              "| --- | --- | --- | --- | --- |"]
    for row in record["checks"]["coverage"]:
        lines.append(f"| {row['id']} | {row['group']} | {row['owner']} | {row['outcome']} | "
                     f"{row['evidenceOrGap']} |")
    lines += ["", "### Checks", "",
              "Every command ran through `docs/audits/AUD-015-harnesses/run.py`, which keeps its "
              "log and record (argv, UTC start and end, exit code, log SHA-256) in the local-only "
              "`docs/audits/AUD-015-evidence/`. A reviewer probe exits 1 where it reproduced a "
              "defect; superseded probe runs are kept and named by the reviewer.", "",
              "| Label | Exit | Seconds | Log SHA-256 |", "| --- | --- | --- | --- |"]
    for command in commands:
        lines.append(f"| `{command['label']}` | {command['exitCode']} | {command['seconds']} | "
                     f"`{command['logSha256']}` |")
    lines += ["", record["checks"]["summary"], "", "### Findings", ""]
    for item in record["findings"]:
        lines += [f"#### {item['id']} - {item['severity'].capitalize()} - {item['title']}", "",
                  f"- **Category:** {item['category']}.",
                  f"- **Severity:** {item['severity']}.",
                  f"- **Status:** {item['status']}.",
                  f"- **Release blocking:** {str(item['releaseBlocking']).lower()}; "
                  f"{item['releaseBlockingReason']}",
                  f"- **Affected files and builds:** {', '.join(item['affectedFiles'])}.",
                  f"- **Reproduction:** {item['reproduction']}",
                  f"- **Expected behavior:** {item['expected']}",
                  f"- **Observed behavior:** {item['observed']}",
                  f"- **Impact:** {item['impact']}",
                  f"- **Evidence:** {'; '.join(item['evidence'])}.",
                  f"- **Recommended fix:** {item['recommendedFix']}",
                  f"- **Required verification:** {item['requiredVerification']}",
                  f"- **Reported by:** {item['reviewer']}; challenged and accepted by the "
                  "coordinator.", ""]
    lines += ["### Remediation and follow-up", "",
              "Findings of this audit are open. Earlier findings that were open in their own "
              "records have a fix in the reviewed, uncommitted working tree; they stay open until "
              "a commit records the fix and its verification.", "",
              "| Finding ID | Status | Fix commit | Verification commit | Evidence |",
              "| --- | --- | --- | --- | --- |"]
    for row in record["remediation"]:
        lines.append(f"| {row['id']} | {row['status']} | none (uncommitted) | none | "
                     f"{row['evidence']} |")
    follow = record["remediationFollowUp"]
    lines += ["", f"#### Remediation follow-up, {follow['dateUtc']} (uncommitted)", "",
              f"Fixes of this audit's findings in the working tree, source fingerprint "
              f"`{follow['sourceFingerprint']}` ({follow['files']} files), on the same commit. "
              "The rows above with this audit's IDs give each fix; every row stays open until a "
              "commit records it. Checks run on these bytes, logs local-only in "
              "AUD-015-evidence/remediation-2026-10-09/:", ""]
    lines += [f"- {text}" for text in follow["checks"]]
    lines += ["", "### Informational observations and recommendations", ""]
    lines += [f"- {text}" for text in record["informationalObservations"]]
    lines += ["", "### Assessment and limitations", "", record["assessment"], ""]
    lines += [f"- {text}" for text in record["limitations"]]
    lines.append("")
    return "\n".join(lines)


# The remediation of this audit's own findings, made after the review in the uncommitted tree
# (the owner's request of 2026-10-09). Every row stays open until a commit records the fix and its
# verification; the evidence names the fix and the check that shows it.
REMEDIATION_FINGERPRINT = "6a25bf95ccf39666e43aa6b29fb5819caa57ab5f0273d66c7084cf7fcd43709c"
REMEDIATION_FILES = 481
REMEDIATION_CHECKS = [
    "cargo fmt --all -- --check and cargo clippy --locked --all-targets --all-features "
    "-- -D warnings: passed.",
    "cargo test --locked --all-features: library 337 passed and 2 ignored, binary 115 and 2, "
    "suite 3 vectors 3 and 1, suite 4 vectors 2 and 1, doc tests 4; passed.",
    "scripts/build-wasm.sh: dist build 3037145bb3f91f13; node scripts/verify-browser-package.mjs: "
    "passed; node scripts/verify-cli-browser-parity.mjs target/release/mhfe: passed.",
    "python3 scripts/verify-hidden-input.py target/release/mhfe: passed, with the new terminal "
    "regressions for SEC001, SEC003, SEC004 and UI002.",
    "npm run format:check: passed.",
    "Probes of this audit rerun on the fixed tree: typed_again_lists, static-scan (14 of 14), "
    "api-probes, wasm-parity, hint_rows_narrow, quit_key_private_screen, serve_checksum_name, "
    "never-use-loop and never-use-check-warning exit 0. made_password_dumb, "
    "search_reference_record and public_answer_echo exit 1 because they script the old flow: the "
    "made password is now refused before the first question, a phrase typed as a reference is "
    "refused in its field, and the quoted fingerprint now wraps on two lines with its escapes "
    "shown as text; the regressions above check each defect instead. record_commit_fields and "
    "harness_bindings exit 0 after the amendment below; record_commit_fields leaves the four "
    "mhfe_spec fields of DOC001.",
    "Owner-authorized documentation amendment of the same day, after these checks: DOC001 and "
    "DOC002 above, and privacy edits (audit-02 local times in UTC; PATH values of audit-03, 04 and "
    "05 elided; a scratchpad path in audit-10; the interruption wording of audit-13 and 14 and of "
    "AUD-013's harness README; the AUD-005 decisions title; the time-of-day keys of "
    "c-engine-2026-09-29.json). Source fingerprint after it: "
    "2d588cde2cb20d59675449657bb5b0eb2f4d2786a426de308fc0621320e39a10; no code changed.",
    "Not run, by the owner's hold: verify-browsers.mjs, full-cost Argon2, the vector replays and "
    "the canonical build.",
]
REMEDIATION = [
    ("AUD-015-SEC001", "Fixed in the tree: the search's reference field records nothing until "
     "the text is read as a fingerprint or an address of the coin asked, and refuses several "
     "words; terminal regression check_search_reference_is_recorded_once_read."),
    ("AUD-015-SEC002", "Fixed in the tree: library messages quote typed or file text with "
     "error::quoted, which escapes every control character; mhfe serve refuses a checksum page "
     "name with one; unit tests quoted_input_holds_no_control_character and the serve cases."),
    ("AUD-015-SEC003", "Fixed in the tree: made_password::refuse_kind refuses a made password "
     "where no private screen can be shown, at the start of encrypt and rekey; terminal "
     "regression with TERM=dumb."),
    ("AUD-015-SEC004", "Fixed in the tree: ctrlc's termination feature routes SIGTERM and SIGHUP, "
     "and protect::interrupt_on_quit_and_suspend routes Ctrl+\\ and Ctrl+Z, through the Ctrl+C "
     "restore path; terminal regression check_quit_keys_leave_the_private_screen."),
    ("AUD-015-SEC005", "Fixed in the tree: show_sealing decides with terminal::output_on_screen()."),
    ("AUD-015-SEC006", "Fixed in the tree: an answer's label and its drawn line are wiped when "
     "dropped (Zeroizing)."),
    ("AUD-015-SEC007", "Fixed in the tree: the page passes only the worker news it knows to its "
     "own handlers; any other message or question ends the job with PACKAGE_MISMATCH; package "
     "regression, news-list check and api-probes P3."),
    ("AUD-015-FUN001", "Fixed in the tree under the owner's rule of 2026-10-09, now in the "
     "uncommitted mhfe_spec revision: the verifiers take precedence over a stated length in every "
     "recovery; a rekey whose check contradicts the stated length is refused under the built-in "
     "check alone (LENGTH_DIFFERS) and confirmed by an address or the fingerprint, which compares "
     "every reading; startup known answers in cipher-rounds and rekey, unit and package tests."),
    ("AUD-015-API001", "Fixed in the tree: drawPhrase checks walletCheck's type and the workers "
     "range whatever the passphrase; package regression and api-probes P2."),
    ("AUD-015-BLD001", "Partly addressed in the tree: docs/releases/history-rewrite-2026-10-09.md "
     "pairs the original commits of v0.3.0 to v0.5.0 with their rewritten ones, linked from the "
     "README; open until it is committed and published."),
    ("AUD-015-BLD002", "Fixed in the tree: release.yml calls ci.yml for the tagged commit and "
     "publishes only after it; the Dockerfile comment is corrected."),
    ("AUD-015-UI001", "Fixed in the tree: hint rows are cut to the room of the terminal; unit "
     "test a_hint_row_never_wraps and probe hint_rows_narrow."),
    ("AUD-015-UI002", "Fixed in the tree: --never-use is checked with the library rule before "
     "the first question, exit code 2; terminal regression and probe never-use-loop."),
    ("AUD-015-UI003", "Fixed in the tree: the rating leaves out the never-use cost, and the "
     "placement advice comes only for a word at a fixed position (fixed_position, "
     "fixedPosition); unit and package tests, probe never-use-check-warning."),
    ("AUD-015-UI004", "Fixed in the tree: a run of letters longer than any list word gives "
     "NoWord; known answer zookeepers, unit and package tests."),
    ("AUD-015-UI005", "Fixed in the tree: the library and the page strip a detail's trailing "
     "period before the advice."),
    ("AUD-015-ARC001", "Fixed in the tree: the lists are derived from their constants; probe "
     "typed_again_lists exits 0."),
    ("AUD-015-ARC002", "Fixed in the tree: the unit test reads known_answers::ADDRESSES; the "
     "copy, found equal row for row, is removed."),
    ("AUD-015-ARC003", "Fixed in the tree: the CANCELLED comment names what exits 130 now."),
    ("AUD-015-DOC001", "Fixed in the tree on the owner's instruction: the rewrite's old-to-new "
     "map rewrote the commit references of 16 historical documents, and each amended record "
     "keeps its map in privacyRedaction.amendments. Four structured fields still name two "
     "mhfe_spec commits, e87eb5cd and 28e50e04, which were already the rewrite's replacements but "
     "which mhfe_spec no longer contains; the mhfe_spec session was told."),
    ("AUD-015-DOC002", "Fixed in the tree on the owner's instruction: 13 documentBindings bind the "
     "harness READMEs and measurements that the rewrite or the amendment changed; probe "
     "harness_bindings: 106 recorded hashes, none broken."),
    ("AUD-015-DOC003", "Fixed in the tree: the v0.5.1 notes name the two rules of the unreleased "
     "specification revision."),
    ("AUD-015-DOC004", "Fixed in the tree: the Reviews section lists AUD-011 to AUD-015."),
    ("AUD-015-DOC005", "Fixed in the tree: API.md's usage block, export list and secrets "
     "sentence; static-scan S3a and S3b pass."),
    ("AUD-015-DOC006", "Fixed in the tree: SECURITY.md names Tab and Ctrl+W of a line of words."),
    ("AUD-015-DOC007", "Fixed in the tree: SECURITY.md names the line buffer of standard output."),
    ("AUD-015-DOC008", "Fixed in the tree: the cancel passages say when a loading worker ends."),
    ("AUD-015-DOC009", "Fixed in the tree: the orphan comment is removed and strength()'s JSDoc "
     "moved; static-scan S1c passes."),
]


def main():
    commands = load_commands()
    for item in FINDINGS:
        for field in ("reproduction", "expected", "observed", "impact", "recommendedFix",
                      "requiredVerification", "evidence"):
            if not item[field]:
                sys.exit(f"{item['id']} has no {field}")
    counts = {}
    for item in FINDINGS:
        counts[item["severity"]] = counts.get(item["severity"], 0) + 1
    baseline_labels = [c for c in commands if not re.match(r"r[1-5]-", c["label"])]
    record = {
        "schemaVersion": 1,
        "auditId": "AUD-015",
        "auditNumber": 15,
        "date": DATE,
        "title": "mhfe full audit of the 0.5.1 working tree",
        "reviewer": {
            "name": "Claude Code coordinator with five independently scoped reviewers",
            "model": "claude-opus-5-5",
            "reasoningEffort": "40",
            "reasoningEffortSource": "Coordinator session setting as shown to the model; "
                                     "reviewers' setting not recorded.",
        },
        "snapshot": {
            "commit": SECOND_REWRITE_HEAD,
            "commitComplete": True,
            "commitBeforeRewrite": BASELINE["head"],
            "commitAfterFirstRewrite": AFTER["head"],
            "commitNote": "The review started at commitBeforeRewrite, which the owner-authorized "
                          "privacy rewrite replaced by commitAfterFirstRewrite during the review, "
                          "with the same source files; the second privacy rewrite of the same day "
                          "replaced that by commit, changing audit documents and one comment in "
                          "src/bin/mhfe/hidden_input.rs. sourceFingerprint binds the reviewed bytes.",
            "workingTree": {
                "description": f"Dirty: {len(BASELINE['status'])} changed or untracked paths "
                               "(the uncommitted 0.5.1 work); reviewed as the source manifest "
                               "below.",
                "initialStatus": BASELINE["status"],
            },
            "sourceFingerprint": BASELINE["sourceFingerprint"],
            "sourceFingerprintAfterRewrite": AFTER["sourceFingerprint"],
            "capturedUtc": BASELINE["capturedUtc"],
        },
        "artifacts": {
            "description": "dist/ build 6a91d106c1b87634 (runtime/mhfe.wasm sha256 "
                           "489f90e616382428e74c317a996ac5fc9c4f3692b4f0905ce4c7cc6a0208eefb), "
                           "rebuilt from the snapshot byte for byte; target/release/mhfe sha256 "
                           "89f017ae1ff26e3237dda85e7cb2ea4caaf7952397dac26e1c3eb30ba0d799c3, "
                           "built from the snapshot.",
        },
        "procedureHashes": PROCEDURE,
        "environment": "Linux x86-64 (Ubuntu 26.04), 16 threads, 14 GiB; rustc 1.99.0, cargo "
                       "1.99.0, wasm-bindgen 0.2.129, Emscripten 6.0.10, Node 26.10.0, Python "
                       "3.14.4, Playwright 1.63.0 (Chromium 153, Firefox 155).",
        "scope": "Full scope of the mhfe repository as of the snapshot: library, command-line "
                 "tool, WebAssembly bindings, browser package, scripts, CI and release "
                 "definitions, and documents, against the workspace procedure. The coordinator "
                 "ran the offline steps of scripts/check.sh; five reviewers reviewed source, "
                 "wrote audit-only probes with independent oracles and ran them through the "
                 "runner; the coordinator challenged each finding against source or logs before "
                 "accepting it. Areas that do not exist in mhfe are recorded as not applicable.",
        "checks": {
            "coverage": [{"id": cid, "group": group, "owner": owner, "outcome": outcome,
                          "evidenceOrGap": text}
                         for cid, group, owner, outcome, text in COVERAGE],
            "commands": [{"label": c["label"], "argv": c["argv"], "startUtc": c["startUtc"],
                          "endUtc": c["endUtc"], "exitCode": c["exitCode"],
                          "seconds": c["seconds"], "logSha256": c["logSha256"]}
                         for c in commands],
            "summary": f"Coordinator baseline: {len(baseline_labels)} commands, all exit 0: "
                       "vendored Argon2 hashes, notices, published rounds, cargo fmt, the copy "
                       "check and its self-test, clippy native and WASM (all features and each "
                       "browser module alone), cargo test (library 334 passed and 2 ignored, "
                       "binary 114 and 2, suite 3 vectors 3 and 1, suite 4 vectors 2 and 1, doc "
                       "tests 4), cargo doc with warnings denied, release build, mhfe self-test, "
                       "the terminal suite, dist rebuilt byte for byte, the Argon2 WebAssembly "
                       "check, the browser package check, the CLI/browser parity check, the "
                       "fast-mode script check, the release-artifact check and Prettier on the "
                       "documents.",
        },
        "findings": FINDINGS,
        "observations": [],
        "informationalObservations": OBSERVATIONS,
        "remediation": [{"id": fid, "status": "open", "fixCommit": None,
                         "verificationCommit": None, "evidence": text}
                        for fid, text in DISPOSITIONS + REMEDIATION],
        "remediationFollowUp": {
            "dateUtc": "2026-10-09",
            "sourceFingerprint": REMEDIATION_FINGERPRINT,
            "files": REMEDIATION_FILES,
            "commit": SECOND_REWRITE_HEAD,
            "commitWhenChecked": AFTER["head"],
            "checks": REMEDIATION_CHECKS,
        },
        "limitations": LIMITATIONS,
        "assessment": f"{len(FINDINGS)} findings: {counts.get('medium', 0)} medium and "
                      f"{counts.get('low', 0)} low; no critical or high. Four are release "
                      "blocking: FUN001 (a specification MUST in rekey), SEC001 (a mistyped "
                      "secret can reach the scrollback), and BLD001 and DOC001, which block "
                      "publishing the rewritten history rather than the code. The cipher, its "
                      "formats and profiles, BIP39 reading, the wallet derivations and the "
                      "browser package's secret handling agreed with independent references in "
                      "every probed case.",
    }
    record = private(record)
    OUT.with_suffix(".json").write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    OUT.with_suffix(".md").write_text(private(markdown(record, record["checks"]["commands"])))
    print(f"wrote {OUT.name}.md and .json: {len(FINDINGS)} findings, {len(commands)} commands")


if __name__ == "__main__":
    main()
