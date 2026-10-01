# AUD-003 implementation audit harnesses

These scripts belong to the review of MHFE branch `suite-3-c-engine`, implementation commit
`46112d2b4bec0b9eba34cbbb9d632df099e11672`, against specification commit
`1a9f4b95d29cb275becc2a035eb1fe3dd880641f`. They use public test data only.

During the review the specification advanced to `46ad87e40c742821e72bb48a7bac3c2dae6085c7`.
The normative README and design notes are byte-identical; only vector/publication notes changed.

A second phase records four concurrent edits to `README.md`, `src/bin/mhfe/encrypt.rs`,
`src/bin/mhfe/settings.rs` and `web/README.md` on top of the same implementation commit, in local
`late-snapshot.json`. They were reviewed separately, with fresh CLI tests, formatting and clippy.
One later edit removed only the words "for recovery" from the same displayed sentence. The final
CLI build includes that edit; it is recorded in `final-snapshot.json`. For the final reviewed tree,
pass `final-snapshot.json` to `metadata.py`; the default intentionally detects drift from the
initial snapshot and fails. No snapshot should be overwritten.

Run from the existing `mhfe` checkout. `python3 run.py` below means
`python3 docs/audits/AUD-003-harnesses/run.py`.

- `python3 run.py capture` records source hashes and procedure identity once. Do not recapture over
  retained evidence.
- `python3 run.py LABEL -- COMMAND ARG...` runs a bounded check with the workspace toolchain and
  one Cargo build job, keeping the actual output, timestamps, exit status and hash in the ignored
  `docs/audits/AUD-003-evidence/` directory. Labels must be unique. It exits with the command's
  status. It does not choose commands or make high-memory checks safe automatically.

Python 3 and the existing workspace toolchains are required. No full-cost MHFE operation or vector
recalculation is included. Reports distinguish fresh checks from upstream verification records.

## Reproductions

Run each through `run.py` with a fresh label, using these exact commands from the repository root:

```sh
python3 docs/audits/AUD-003-harnesses/run.py api-probe -- python3 docs/audits/AUD-003-harnesses/public_api.py
python3 docs/audits/AUD-003-harnesses/run.py terminal-probe -- python3 docs/audits/AUD-003-harnesses/terminal_input.py
python3 docs/audits/AUD-003-harnesses/run.py deadline-probe -- python3 docs/audits/AUD-003-harnesses/server_deadline.py
python3 docs/audits/AUD-003-harnesses/run.py layout-probe -- node docs/audits/AUD-003-harnesses/layout32.mjs
```

- `public_api.py` builds a consumer of the production library from `public_api.rs`. It shows the
  uppercase address rejection and writable supposedly restricted vector inputs. Exit 1 on the
  audited baseline is expected. Making the fields private should make the mutation consumer fail
  to compile; verify that intended compile failure separately from address acceptance.
- `terminal_input.py` uses the production CLI, a POSIX pseudo-terminal and the public zero-12
  container from `tests/fixtures/suite3-vectors/zero-12.json`. TAB, NUL and U+0085 in the synthetic
  password must be refused. It stops its own child before supplying a fingerprint, so no Argon2
  allocation occurs. Exit 1 means forbidden passwords reached the next prompt.
- `server_deadline.py` needs Linux `/proc` and permission to bind a loopback socket. It serves an
  8 MiB synthetic HTML file and waits 13 seconds with one non-reading client. Exit 1 means an
  answer thread outlived the documented ten-second total deadline. It stops its own server.
- `layout32.mjs` builds `layout32.rs` with the existing wasm32 Rust target and runs the allocation
  layout predicate with 32-bit integers. It allocates no 2 GiB buffer. Exit 1 means that predicate
  rejects the advertised native level 0. This is a layout proof, not an i686 execution or a
  finding against the working Emscripten browser engine.

## Bounded verification

Build the browser package with `scripts/build-wasm.sh` using the workspace Emscripten environment
before running `browser.mjs`. This harness uses Playwright already installed in the neighboring
`multi-chain-wallet-tools/node_modules` and its installed Chromium and Firefox. It adds a wrapper
only to the generated audit page: the real core must request default suite parameters, but the
test wrapper passes 256 KiB and one pass to the real C engine. Both modes run under normal browser
sandboxing and strict CSP. A pass prints seven checks for each of four browser/mode combinations;
any error exits non-zero. No production files are edited and no full-cost conformance is claimed.

```sh
python3 docs/audits/AUD-003-harnesses/run.py browser-probe -- node docs/audits/AUD-003-harnesses/browser.mjs
python3 docs/audits/AUD-003-harnesses/run.py metadata-probe -- python3 docs/audits/AUD-003-harnesses/metadata.py
python3 docs/audits/AUD-003-harnesses/run.py upstream-probe -- python3 docs/audits/AUD-003-harnesses/upstream.py
```

`metadata.py` uses the initial snapshot, the companion `../mhfe_spec` checkout, vendored hashes,
the existing full verification record and `dist/`. It checks byte identity, not vector arithmetic,
and exempts only the audit index from the original tracked-file fingerprint comparison.
`upstream.py` needs `gh` and network access; it reads public GitHub metadata to compare every
vendored file with its pinned Git blob and confirm private vulnerability reporting is enabled.
Both exit zero on success and non-zero on any failed assertion or unavailable prerequisite.

The report lists the build, unit-test and original browser-page commands separately. Do not open
the original `target/browser-check/index.html` during a memory-limited audit: it deliberately runs
a full-cost operation. Only the generated `AUD-003-evidence/bounded-browser.html` has reduced cost.

## Report validation

```sh
python3 docs/audits/AUD-003-harnesses/validate_report.py
```

This requires the Python `jsonschema` package already available in the audit environment. It
checks the canonical JSON schema without duplicate keys, all 32 procedure IDs, matching finding
IDs in both reports, command-log hashes, source identity against the late snapshot, relative
document links, and ignored/unstaged evidence. It writes the local `report-validation.json` and
`SHA256SUMS` and exits zero only when every check passes. Do not run it through `run.py`: its
manifest must be generated after other command logs have closed.

## Follow-up verification

Added after the remediation, for the findings whose verification was still incomplete.

```sh
python3 docs/audits/AUD-003-harnesses/run.py refuse32-probe -- sh docs/audits/AUD-003-harnesses/refuse32.sh
```

`refuse32.sh` (AUD-003-API002) checks a native build for `i686-unknown-linux-gnu` with
`cargo check`. It installs that Rust target in the workspace toolchain if it is missing. A stand-in
C compiler writes empty objects for the vendored Argon2 C code, so no 32-bit C headers are needed;
`cargo check` links nothing. Exit 0 means the build stopped with the 64-bit guard of
`src/engine/native.rs` and no other error.

AUD-003-DOC002 is verified by the unit tests in `src/bin/mhfe/encrypt.rs`
(`cargo test --locked --bin mhfe encrypt::`): the advice after an encryption for a short phrase at
the defaults, a phrase that length detection would misread, a 24-word phrase, and changed settings.
