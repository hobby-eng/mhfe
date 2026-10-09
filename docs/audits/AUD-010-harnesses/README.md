# AUD-010 harnesses

Audit-only scripts of [AUD-010](../audit-10-2026-10-07.md), the full-scope audit of the uncommitted
modular refactor and the AUD-009 remediation. They were written for the MHFE working tree on HEAD
`d7af4b1035355a69779f8ad70a9dc50ba5b9ffd0` with source fingerprint
`372da577dd586932d6b3fa47711d97bc25b8fa908a980cd2373b704724ec796b` (227 paths, computed by
`fingerprint.mjs` below). They change nothing in the repository, use public test vectors and
synthetic secrets only, build no release, run no Docker and no browser, and run Argon2 at most at
256 MiB, except `run-capped.sh`, which the coordinator used for the full-size runs, and
`remediation/rekey-full.py`, which runs at full cost through it (see
[After remediation](#after-remediation)).

## Running them

Run every command from the repository root. To keep a record, wrap a command in `run-logged.sh`,
which writes `docs/audits/AUD-010-evidence/<name>.log` and `<name>.command.json` (the argv, UTC
start and end, exit code and the log's SHA-256); that folder is ignored by git and its files are
local-only evidence. The record names in the tables below are the ones the audit used.

```sh
docs/audits/AUD-010-harnesses/run-logged.sh <name> <command> [arguments...]
```

Inputs:

- the working tree and git;
- the local build that `scripts/check.sh` makes: `dist/` (build `4c948de3a4ee3f03` at the reviewed
  state), `target/wasm-bindgen/mhfe.js`, `target/wasm32-unknown-unknown/release/mhfe.wasm`,
  `target/release/mhfe` and the test binary in `target/debug/deps/`;
- Node 26.10.0, Python 3.14 (with `cryptography` for OpenSSL Argon2id in `crypto-core/oracle.py`
  and `jsonschema` for `docs-build-release/audit-records.py`) and Rust 1.99.0 with the wasm32
  target;
- read only: `../mhfe_spec` (crypto-core), `../multi-chain-wallet-tools` (the audit procedure, for
  `audit-records.py`) and the AUD-008 canonical archive in `canonical-output-aud008cached/`
  (`wasm-builder-paths.mjs`, `argon2-vs-canonical.sh`).

Rust and the full-size runs use the workspace toolchain homes:

```sh
export CARGO_HOME=/home/user/Documents/bip_tools/workingspace/cargo
export RUSTUP_HOME=/home/user/Documents/bip_tools/workingspace/rustup
export PATH="$CARGO_HOME/bin:$PATH"
```

## Exit codes

Every script ends with exit code 0 when all its checks pass and with a non-zero code when one fails
or when it cannot run (a missing program, folder or input). The scripts check in one of two ways:

- Most state the documented behaviour, so a failing check reproduces a finding: at the reviewed
  state they exit 1, and they pass once the finding is fixed.
- The `REPRODUCED-*` sections of `crypto-core/probe.py` and `crypto-core-skeptic/challenge.py` state
  the defect, so they pass (exit 0) while the finding holds and fail by design once it is fixed.

The coordinator checked the non-zero exit of every script in three ways. Each script that takes an
input was given one that must fail: 18 cases, every one non-zero (local-only evidence record
`postrecord-harness-exit-checks`, kept in the ignored local-only evidence folder). The scripts that
reproduce findings recorded exit 1 at the reviewed state. The exit path of the rest was read:
`lib.mjs` sets exit code 1 on any failed check; `network-scan.mjs`, `random-source.mjs`,
`client-lifecycle.mjs`, `doc-checks.mjs` and `error-codes.mjs` exit 1 on any problem;
`cli-process-protection.py` exits 1 on a failed check and 2 when it cannot run.

## Shared tools

| Script            | What it does                                                                                                                                                                                              | Expected                                                                                                   |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `run-logged.sh`   | Runs one command from the repository root and records it in the evidence folder                                                                                                                           | The command's own exit code; 2 without arguments                                                           |
| `run-capped.sh`   | Runs one full-size Argon2 command through `run-logged.sh` in a systemd user unit capped at 3,800 MiB with no swap, after waiting for that much free memory; needs `CARGO_HOME` and `RUSTUP_HOME`          | The command's own exit code; 2 without arguments                                                           |
| `fingerprint.mjs` | Prints the source fingerprint as JSON: SHA-256 of the JSON text of the sorted [path, SHA-256] records of `git ls-files -c -o --exclude-standard`, docs/audits excluded, missing files recorded as deleted | `node docs/audits/AUD-010-harnesses/fingerprint.mjs`: `372da577…`, 227 paths at the reviewed state; exit 0 |

## crypto-core

The reviewer's own [README](crypto-core/README.md) gives the details. The probe builds outside the
repository, in `/home/user/Documents/bip_tools/tmp/claude/aud010-crypto-core/probe-build`
(`--build-dir` to change it).

| Script                          | Checks                                                                                                                                                                                                                                                                                                      | Command                                                                                                                                                                                                                 | Expected at the reviewed state                                         |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `oracle.py`                     | An implementation written for the audit from the specification and the standards: BIP39 and BIP32 vectors, self-check digests, all 27 published vectors from their recorded round keys, the reduced-cost containers, repair words, check word, wallet check, the 43 address known answers and DIP-0017/0018 | `python3 docs/audits/AUD-010-harnesses/crypto-core/oracle.py` (record `crypto-core-oracle`)                                                                                                                             | 130 `PASS` lines, last line `0 failed`; exit 0; about 2 s              |
| `probe/`                        | A Rust program that calls mhfe's public library API; built and driven by `probe.py`, not run alone                                                                                                                                                                                                          | Built by `probe.py`                                                                                                                                                                                                     | —                                                                      |
| `probe.py`                      | About 2,300 library answers compared with `oracle.py` or the specification's rule; the sections `REPRODUCED-wallet-check-rule` (FUN001) and `REPRODUCED-fingerprint-reading` (API001) state the defects                                                                                                     | `python3 docs/audits/AUD-010-harnesses/crypto-core/probe.py` (record `crypto-core-probe`); with `--only REPRODUCED-wallet-check-rule,REPRODUCED-fingerprint-reading,phrases` (record `crypto-core-probe-reproductions`) | One `PASS` line per section, `0 failed`; exit 0; about 5 minutes       |
| `short_reading_wallet_check.py` | Finds the public passphrase `aud010 public probe 11656` whose wallet-check digest of the 12-word original of zero-12 starts with 16 zero bits under BE32(128)                                                                                                                                               | `python3 docs/audits/AUD-010-harnesses/crypto-core/short_reading_wallet_check.py` (record `crypto-core-short-reading-wallet-check`)                                                                                     | Prints the passphrase and both digests; exit 0; about 20 s on 16 cores |

## crypto-core-skeptic

See its [README](crypto-core-skeptic/README.md).

| Script         | Checks                                                                                                                                                                                                                                                                                 | Command                                                                                                           | Expected at the reviewed state                               |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `challenge.py` | The challenger's independent recomputation of FUN001 (the wallet-check digest with BE32(128) and BE32(256), the profile's answer, the library's answers, the source rules) and API001 (phrase reading of fingerprints, their callers); needs the probe built by `crypto-core/probe.py` | `python3 docs/audits/AUD-010-harnesses/crypto-core-skeptic/challenge.py` (record `crypto-core-skeptic-challenge`) | 21 `PASS` lines, `0 failed`; exit 0 while both findings hold |

## secrets-security

See its [README](secrets-security/README.md) for the inputs of each probe.

| Script                      | Checks                                                                                                                                                | Command                                                                                                                                  | Expected at the reviewed state                                                        |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `network-scan.mjs`          | No network or remote-loading API in the package scripts outside reviewed local-only uses; no socket code in Rust outside `serve.rs` and tests         | `node docs/audits/AUD-010-harnesses/secrets-security/network-scan.mjs` (record `secrets-security-network-scan`)                          | `PASSED`; exit 0                                                                      |
| `wasm-residue.mjs`          | Copies of secrets left in the WebAssembly's linear memory after each binding returns                                                                  | `node docs/audits/AUD-010-harnesses/secrets-security/wasm-residue.mjs` (record `secrets-security-wasm-residue`)                          | 26 measurements, 3 with a copy left (W3: SEC001); exit 1                              |
| `client-lifecycle.mjs`      | Every page copy of a secret is transferred to its worker or wiped                                                                                     | `node docs/audits/AUD-010-harnesses/secrets-security/client-lifecycle.mjs` (record `secrets-security-client-lifecycle`)                  | `PASSED`; exit 0                                                                      |
| `random-source.mjs`         | Broken random sources are refused and leave no part of a password behind                                                                              | `node docs/audits/AUD-010-harnesses/secrets-security/random-source.mjs` (record `secrets-security-random-source`)                        | `PASSED: R1 to R4.`; exit 0                                                           |
| `cli-process-protection.py` | Core size 0, not dumpable, seccomp and no_new_privs on every thread and an empty network namespace while `encrypt --stdin` and `decrypt --stdin` wait | `python3 -B docs/audits/AUD-010-harnesses/secrets-security/cli-process-protection.py` (record `secrets-security-cli-process-protection`) | `PASSED: P1 to P4 ...`; exit 0 (2 when not on Linux or without `target/release/mhfe`) |
| `builder-paths.mjs`         | No absolute home-directory path in a file of the package                                                                                              | `node docs/audits/AUD-010-harnesses/secrets-security/builder-paths.mjs` (record `secrets-security-builder-paths`)                        | 21 builder paths in `dist/` (BLD002); exit 1                                          |

## browser-package

The probes load the production `web/` and `dist/` modules from data URLs with a stand-in Worker and
run the real `dist/runtime/worker.js` and `dist/runtime/mhfe.wasm` in the Node process; no Argon2
work runs (an Argon2 stand-in refuses every call that would reach it). This folder has no README of
its own; each script's header comment says what it checks.

| Script            | Checks                                                                                                                                                                                                                                                                                                             | Command                                                                                                     | Expected at the reviewed state                                |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `lib.mjs`         | Shared helpers: the check recorder (sets exit code 1 on any failed check), module loading from data URLs, the stand-in Worker                                                                                                                                                                                      | Imported by the others                                                                                      | —                                                             |
| `transport.mjs`   | Worker transport and asynchronous state (CHECK-SEC-002, CHECK-API-002): compiled-module hand-over, secret transfer, the build handshake, late replies, start failures, the operation allowlist, BUSY, cancellation, callback failures, hidden-wallet sessions; the AUD-009-API001, -API002 and -SEC001 regressions | `node docs/audits/AUD-010-harnesses/browser-package/transport.mjs` (record `browser-package-transport`)     | 75 passed, 5 failed (API002, API006); exit 1                  |
| `inputs.mjs`      | Call contracts (CHECK-API-001): the classes with values outside their declared types, and the Rust translators through the real WebAssembly                                                                                                                                                                        | `node docs/audits/AUD-010-harnesses/browser-package/inputs.mjs` (record `browser-package-inputs`)           | 175 passed, 6 failed (API003, API004, API005); exit 1         |
| `surface.mjs`     | Public surface and composition (CHECK-API-003, CHECK-BLD-001): declared value exports, named imports, result shapes, error codes, `dist/modules.json`, the build id, self-check parts                                                                                                                              | `node docs/audits/AUD-010-harnesses/browser-package/surface.mjs` (record `browser-package-surface`)         | 84 passed, 0 failed; exit 0                                   |
| `static-scan.mjs` | DOM sinks, storage, dynamic code, console and network calls, remote URLs, coin names, public vectors and builder paths in `web/` and `dist/` (CHECK-SEC-006)                                                                                                                                                       | `node docs/audits/AUD-010-harnesses/browser-package/static-scan.mjs` (record `browser-package-static-scan`) | 14 passed, 0 failed; exit 0 (builder paths are notes; BLD002) |

## browser-package-skeptic

| Script          | Checks                                                                                                                                                                            | Command                                                                                                                 | Expected at the reviewed state |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| `challenge.mjs` | The challenger's independent reproduction of API002 to API006 without the reviewer's helpers; each check states the documented behaviour, so a failing check reproduces a finding | `node docs/audits/AUD-010-harnesses/browser-package-skeptic/challenge.mjs` (record `browser-package-skeptic-challenge`) | 3 passed, 20 failed; exit 1    |

## cli-terminal

The probes run `target/release/mhfe` in pipes or in an 80 x 24 pseudo-terminal (Linux). A run that
would reach the 2 GiB Argon2 area gets a 1 GiB address space, so that it stops at the reservation
(exit 4) before any round. `python3 -B` keeps them from writing `__pycache__/`. This folder has no
README of its own; each script's docstring says what it checks.

| Script                 | Checks                                                                                                                                                                                      | Command                                                                                                                                    | Expected at the reviewed state                                      |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- |
| `ptyrun.py`            | Shared helpers: pipes, the pseudo-terminal, colour codes                                                                                                                                    | Imported by the others                                                                                                                     | —                                                                   |
| `help-and-colour.py`   | Help texts and colour rules (C1 to C8): sixteen colours, no escapes in a pipe, the 80-column help width, help sections, usage errors, the NO_COLOR, CLICOLOR_FORCE, CLICOLOR and TERM rules | `python3 -B docs/audits/AUD-010-harnesses/cli-terminal/help-and-colour.py target/release/mhfe` (record `cli-terminal-help-and-colour`)     | 5 passed, 3 failed (C3, C5, C6: UI002, UI003); exit 1               |
| `scripts-mode.py`      | Scripts mode (S1 to S8): refusals before Argon2, the order of answers, the repair round trip, passwords in a pipe, refusal advice, the 78-column width, the script coin                     | `python3 -B docs/audits/AUD-010-harnesses/cli-terminal/scripts-mode.py target/release/mhfe` (record `cli-terminal-scripts-mode`)           | 4 passed, 4 failed (S5 to S8: UI004, UI005, UI006); exit 1          |
| `new-check-default.py` | The wallet-check question of `mhfe new`: nothing preselected, Enter alone does nothing, Escape gives 130                                                                                    | `python3 -B docs/audits/AUD-010-harnesses/cli-terminal/new-check-default.py target/release/mhfe` (record `cli-terminal-new-check-default`) | `new-check-default: FAILED` (N1, N2: UI001); exit 1                 |
| `module-graph.py`      | The use-graph of the library's top-level modules: no independent browser part in a cycle, no library file including a binary file                                                           | `python3 -B docs/audits/AUD-010-harnesses/cli-terminal/module-graph.py` (record `cli-terminal-module-graph`)                               | `module-graph: FAILED` (cycle {mhfe, wallet_check}: ARC002); exit 1 |

## docs-build-release

See its [README](docs-build-release/README.md).

| Script                     | Checks                                                                                                                        | Command                                                                                                                                                                                                                                                                                     | Expected at the reviewed state                                                     |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `wasm-builder-paths.mjs`   | No absolute path of the builder's folders in a WebAssembly or binary                                                          | `node docs/audits/AUD-010-harnesses/docs-build-release/wasm-builder-paths.mjs dist/runtime/mhfe.wasm target/wasm32-unknown-unknown/release/mhfe.wasm canonical-output-aud008cached/release/mhfe-v0.5.0-browser.tar.gz:./mhfe_core_bg.wasm` (record `docs-build-release-wasm-builder-paths`) | `FAIL: 61 paths ...` (BLD002); exit 1                                              |
| `dist-freshness.mjs`       | `dist/` follows from the working tree                                                                                         | `node docs/audits/AUD-010-harnesses/docs-build-release/dist-freshness.mjs dist` (record `docs-build-release-dist-freshness`)                                                                                                                                                                | `PASS: dist/ (build 4c948de3a4ee3f03) ...`; exit 0                                 |
| `feature-matrix.sh`        | `cargo clippy -D warnings` for wasm32 feature combinations and the native build; compiles into `target/`                      | `docs/audits/AUD-010-harnesses/docs-build-release/feature-matrix.sh` (record `docs-build-release-feature-matrix`)                                                                                                                                                                           | 8 combinations clean, 2 internal ones fail (an observation, not a finding); exit 1 |
| `doc-checks.mjs`           | Relative links and anchors, links to this repository, no blank line in a list                                                 | `node docs/audits/AUD-010-harnesses/docs-build-release/doc-checks.mjs` (record `docs-build-release-doc-checks`)                                                                                                                                                                             | `PASS: links, anchors and lists.`; exit 0                                          |
| `package-readme-links.mjs` | Every relative link of the packaged README resolves inside the package                                                        | `node docs/audits/AUD-010-harnesses/docs-build-release/package-readme-links.mjs dist` (record `docs-build-release-package-readme-links`)                                                                                                                                                    | Three `FAIL` lines (DOC002); exit 1                                                |
| `cli-options-in-docs.mjs`  | Every `--option` the documents name is in `mhfe <command> --help`                                                             | `node docs/audits/AUD-010-harnesses/docs-build-release/cli-options-in-docs.mjs` (record `docs-build-release-cli-options`)                                                                                                                                                                   | `PASS: every option named in the documents exists.`; exit 0                        |
| `error-codes.mjs`          | `src/error.rs`, the docs/API.md table and `MhfeErrorCode` agree                                                               | `node docs/audits/AUD-010-harnesses/docs-build-release/error-codes.mjs` (record `docs-build-release-error-codes`)                                                                                                                                                                           | `PASS: error codes agree.`; exit 0                                                 |
| `audit-records.py`         | Schema validation of every record, the AUD-009 pair, the index, unchanged earlier records, ignored evidence, procedure hashes | `python3 docs/audits/AUD-010-harnesses/docs-build-release/audit-records.py` (record `docs-build-release-audit-records`)                                                                                                                                                                     | `PASS: audit records are consistent.`; exit 0 at the reviewed state (see below)    |
| `argon2-vs-canonical.sh`   | The local Argon2 builds equal the canonical ones without their appended build constant                                        | `docs/audits/AUD-010-harnesses/docs-build-release/argon2-vs-canonical.sh` (record `docs-build-release-argon2-vs-canonical`)                                                                                                                                                                 | Two `ok` lines; exit 0                                                             |

`audit-records.py` binds the index to the reviewed state: it allows only AUD-009 lines to be added
to `docs/audits/README.md`. Once the AUD-010 row is in the index, that one check fails by design
(exit 1); every other check, including the schema validation of `audit-10-2026-10-07.json`, still
passes.

## After remediation

Every probe above was written for the baseline, the reviewed state with source fingerprint
`372da577dd586932d6b3fa47711d97bc25b8fa908a980cd2373b704724ec796b`, and reproduces the defects
found there; the "Expected at the reviewed state" columns hold for that fingerprint only. On a
remediated tree a check that reproduced a finding is expected to report the fix and pass, and the
`REPRODUCED-*` sections of `crypto-core/probe.py` and the challengers' checks that state a defect
are expected to fail by design. Some scripts no longer run as committed, because a fix changed the
interface they call or the code they read; they are not adapted, so that they keep recording the
baseline. Rerun each with `run-logged.sh` and check the fingerprint again with `fingerprint.mjs`;
the reviewed fingerprint no longer applies.

The verification of the remediation on 2026-10-07 (local-only records `remediation-*`, on the
program `target/remediation/release/mhfe` and `dist/` build `f4fbbaaa7579d2ba`) found the
following against the remediated tree. While this README was written, the two challengers and the
committed `wasm-residue.mjs` were rerun without a record on the same `dist/`, the crypto-core
challenger with the probe built from the remediated tree
(`--probe <probe-build>/target/debug/aud010-crypto-core-probe`, a probe built outside the repository),
and `cli-terminal/scripts-mode.py` and `remediation/rekey-full.py --until-reservation` on a program
built later with the owner's decision on the script coin.

Scripts that crash or fail against the remediated tree:

| Script                                      | Against the remediated tree                                                                                                                         | Why                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crypto-core/probe.py`                      | Exit 1: `FAIL probe.REPRODUCED-fingerprint-reading: 8 requests, 4 mismatches`; every other section matches (record `remediation-crypto-core-probe`) | By design: API001 is fixed, so capitals and four-letter words give the fingerprint `73c5da0a` and the address. `REPRODUCED-wallet-check-rule` still passes, because it asks `phrase_passes`, which still computes the bare criterion, and `verify`, which still refuses a 12-word phrase; FUN001 was fixed in the rehearsal and the command-line tool                                                                                                                                                                                                                                                                                    |
| `crypto-core-skeptic/challenge.py`          | Exit 1: 13 `PASS`, 8 `FAIL`                                                                                                                         | By design: the F1 checks that the rehearsal compares every reading, that `compare()` uses `phrase_passes`, that the command-line tool reads the passphrase with "Enter for none" and that the browser binding refuses an empty passphrase itself, and the F2 checks that capitals and four-letter words are refused and fullwidth letters taken, state the defects. "Only MhfeWallet.fingerprint passes caller-supplied text" fails on moved lines. "recover_to_check has no empty-passphrase refusal" still passes only because it looks for the text `is_empty`, while the refusal is now a call of `wallet_check::require_passphrase` |
| `browser-package/transport.mjs`             | Exit 1: 79 passed, 1 failed (record `remediation-browser-package-transport`)                                                                        | Its PACKAGE_MISMATCH check expects the page's message to start with `runtime/mhfe.wasm is of build`; the API006 fix makes it `The file runtime/mhfe.wasm is of build …`. The inherited operation names of API002 are now refused, as it checks                                                                                                                                                                                                                                                                                                                                                                                           |
| `browser-package/inputs.mjs`                | Crashes with `Error: no worker received its request`, exit 1, after 8 `FAIL` lines (record `remediation-browser-package-inputs`)                    | The crash: its `MhfePasswords.make` case with a `count` for "checkWord" waits for a worker, which the API005 fix never starts, since it refuses the count first. The failures: its WebAssembly `encrypt` cases pass the phrase as a string to a binding that now takes UTF-8 bytes (SEC001), so the phrase arrives as zeros and they get `INVALID_PHRASE` instead of `INVALID_PIM`, `MEMORY_LEVEL_NOT_SUPPORTED_HERE`, `INVALID_REPAIR_WORDS` or `SAME_LENGTH_NEEDS_SHORT_PHRASE`. The verifier's adapted copy, with phrases as bytes and the new refusal, passed 181 checks (record `remediation-adapted-browser-package-inputs`)       |
| `browser-package/surface.mjs`               | Throws `INVALID_PHRASE: … it has 1 words …` at its `describePhrase` call, exit 1 (record `remediation-browser-package-surface`)                     | It passes the phrase as a string (line 165) to a binding that now takes UTF-8 bytes (SEC001). The adapted copy passed 84 checks (record `remediation-adapted-browser-package-surface`)                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `browser-package-skeptic/challenge.mjs`     | Exit 1: 16 passed, 7 failed                                                                                                                         | It reads code that the fixes moved. Part 3 evaluates `requireSamePassword` cut out of `web/client.js`, which now calls `requireSecret`, not given to it: a `ReferenceError` for each case. Part 4 looks for the arm `"checkWord" => Ok(PasswordRecipe::check_word())`, which stays, after a new arm that refuses a count. Part 5 asserts that `sentence()` keeps `runtime/` and `core/` in lower case, while the API006 fix changed the messages to start with "The file" and left `sentence()` as it is. Parts 1 and 2 (API002, API003) pass                                                                                            |
| `docs-build-release/dist-freshness.mjs`     | Exit 1: "all 58 sources in the dep-info are older than target/wasm32-unknown-unknown/release/mhfe.wasm" fails (record `remediation-dist-freshness`) | It reads the WebAssembly under `target/`, while the remediation built with `CARGO_TARGET_DIR=target/remediation`, so it compares the sources with an older build                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `docs-build-release/wasm-builder-paths.mjs` | With the command above, still `FAIL`                                                                                                                | The command also names `target/wasm32-unknown-unknown/release/mhfe.wasm` and the AUD-008 canonical archive, both built before the fix. `dist/runtime/mhfe.wasm` alone passes: 23 paths, all remapped (record `remediation-wasm-builder-paths`)                                                                                                                                                                                                                                                                                                                                                                                           |
| `docs-build-release/audit-records.py`       | Exit 1 by design                                                                                                                                    | The AUD-010 row is in the index (see above)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

A script that passes on the remediated tree but measures less than it did:

| Script                              | Against the remediated tree                 | Why                                                                                                                                                                                                                                                                                                                       |
| ----------------------------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `secrets-security/wasm-residue.mjs` | Exit 0: 26 measurements, 0 with a copy left | Its W3 cases pass the phrase as a string to bindings that now take UTF-8 bytes, so the phrase never reaches the WebAssembly and those cases measure nothing. The verifier's adapted copy, with phrases as bytes, also found 0 copies left in 26 measurements (record `remediation-adapted-secrets-security-wasm-residue`) |

Scripts that report the fix and pass on the remediated tree: `cli-terminal/help-and-colour.py`
(8 passed), `cli-terminal/new-check-default.py` and `cli-terminal/module-graph.py` (only the
cycle {engine, suite} remains, outside ARC002), `secrets-security/builder-paths.mjs`,
`docs-build-release/package-readme-links.mjs`; `browser-package/static-scan.mjs`,
`docs-build-release/doc-checks.mjs`, `error-codes.mjs` and `cli-options-in-docs.mjs` still pass.
`cli-terminal/scripts-mode.py` failed `S2` on the verifier's program (7 passed, record
`remediation-cli-scripts-mode`), which refused `check --stdin --address` without `--coin`. The
owner then decided that a script keeps Bitcoin as the default coin and is told so: the summary's
Coin line says "Bitcoin, as no --coin was given", and an address of another coin is refused with
exit code 2 and an error that begins with the coin assumed and ends with how to name another with
`--coin`. On a program built with that decision all 8 checks pass (rerun without a record).
`crypto-core/oracle.py`, `short_reading_wallet_check.py`, `network-scan.mjs`,
`client-lifecycle.mjs`, `random-source.mjs`, `cli-process-protection.py`, `feature-matrix.sh` and
`argon2-vs-canonical.sh` were not rerun.

On the remediated bytes, source fingerprint `83ea7dad…d502` (the record's "Remediation and
follow-up"), the AUD-010 record update reran these scripts unchanged, each with a local-only
record `verification-<script>`: `cli-terminal/help-and-colour.py` (8 passed),
`cli-terminal/new-check-default.py`, `cli-terminal/scripts-mode.py` (8 passed, `S2` and `S7`
included), `cli-terminal/module-graph.py`, `secrets-security/builder-paths.mjs`,
`docs-build-release/wasm-builder-paths.mjs` on `dist/runtime/mhfe.wasm` and `target/release/mhfe`,
`dist-freshness.mjs`, `doc-checks.mjs`, `package-readme-links.mjs` and `cli-options-in-docs.mjs`;
all pass. `error-codes.mjs` now exits 1 although the code sets agree: README's "For developers"
names three environment variables in backticks (`RUSTFLAGS` and two others), which the script takes
for unknown error codes.

### remediation

Two harnesses of the remediation. `rekey-full.py` is for the one finding whose fix no fast test
reaches: ARC001, the command-line `rekey` sealing through the library's `Rekey::seal`. The program
cannot build a reduced-cost engine, so the sealing runs only at full cost. `source-bytes.py` checks
that the working tree still holds the bytes of a snapshot that `fingerprint.mjs` printed, so that
checks run after the snapshot can be bound to its fingerprint.

| Script                        | Checks                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Command                                                                                                                                                                                                          | Expected                                                                                                                                                                                                                                                                                                                                                                |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `remediation/rekey-full.py`   | `mhfe rekey --pim 0 --mem 0 --words 12 --new-pim 0 --new-mem 0` in a pseudo-terminal, standard output in a pipe, on the public container of `tests/fixtures/suite3-vectors/zero-12.json` with its public password: yes to the other wallets, the built-in check confirms the 12-word original, no BIP39 passphrase, no repair words, the new public password `AUD-010 public rekey test` twice. The program must end with exit code 0, print one new 24-word container, record "Recovered 12 words, passed its built-in check" and keep "the 24 words and the password"; then `mhfe decrypt --stdin --pim 0` of the new container with the new password must give "12 verified" and the zero-12 phrase | `docs/audits/AUD-010-harnesses/run-capped.sh verification-rekey-full python3 docs/audits/AUD-010-harnesses/remediation/rekey-full.py target/release/mhfe` (record `verification-rekey-full`)                     | `PASS rekey: exit code 0, a new 24-word container; Recovered  12 words, passed its built-in check; Keep the 24 words and the password` and `PASS decrypt --stdin: the new container with the new password gives the zero-12 phrase, verified`; exit 0; about 5 to 10 minutes. A failed step prints `FAIL <reason>` on standard error, exit 1; an unknown option exits 2 |
| `remediation/source-bytes.py` | The records of a fingerprint snapshot reproduce its fingerprint; every recorded file still has its recorded SHA-256 and every file recorded as deleted is still missing; with `--captured`, no recorded file was modified after that UTC time. It compares bytes only, so it holds whether or not the changes have been committed since                                                                                                                                                                                                                                                                                                                                                                | `python3 -B docs/audits/AUD-010-harnesses/remediation/source-bytes.py <snapshot.json> --captured <YYYY-MM-DDTHH:MM:SSZ>` (record `verification-source-bytes`, with the remediated snapshot and its capture time) | `PASS: the working tree holds the snapshot's bytes.`; exit 0. One `FAIL` line per kind of difference, exit 1; a usage error exits 2                                                                                                                                                                                                                                     |

Inputs: a release build of the remediated tree (`target/release/mhfe` by default, or the path
given), the public vector `tests/fixtures/suite3-vectors/zero-12.json`, Python 3 and a
pseudo-terminal, and for `run-capped.sh` a systemd user session (Linux), `CARGO_HOME` and
`RUSTUP_HOME` set as above, and 3,800 MiB of free memory. The run makes 48 Argon2 rounds at
memory level 0, 2 GiB each: 12 to recover the old container, 24 to seal and check the new one and
12 to decrypt it. Run it only through `run-capped.sh`, which caps it at 3,800 MiB with no swap,
and only alone: no other full-size Argon2 run, vector replay or reproducible build at the same
time, on this machine or in another session.

`python3 docs/audits/AUD-010-harnesses/remediation/rekey-full.py target/release/mhfe --until-reservation`
checks only the answers up to the long work, cheaply and without `run-capped.sh`: the script
limits the program's address space to 1 GiB, which Linux enforces, so the program must stop at the
reservation of the 2 GiB with exit code 4 before any Argon2 round; expected `PASS rekey, capped:
every answer taken up to the reservation, exit code 4` and exit 0, as it gave on the remediated
program (rerun without a record).

Results on the remediated bytes (fingerprint `83ea7dad…d502`): the full `rekey-full.py` run gave
both `PASS` lines and exit 0 in about seven minutes (local-only record `verification-rekey-full`).
`source-bytes.py` with the remediated snapshot (local-only `snapshot-remediated.json`) and
`--captured 2026-10-07T20:57:50Z` passed after every verification run, all 229 records holding
(local-only record `verification-source-bytes`); given the reviewed snapshot instead, it reports
63 changed paths and exits 1 (checked without a record).

`source-bytes.py` takes a snapshot JSON printed by `fingerprint.mjs`; it needs Python 3 and the
working tree, reads only and writes nothing.

Owner-authorized documentation-only amendment of 2026-10-09: commit references of the history replaced by the second privacy rewrite of 2026-10-09 now name the commits that replaced them: f4f7b017d21cbda51283f9eaa973a0cc161b95d6 -> d7af4b1035355a69779f8ad70a9dc50ba5b9ffd0.
