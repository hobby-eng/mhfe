# AUD-004 reproduction harnesses

These scripts accompany [AUD-004](../audit-04-2026-10-01.md), reviewing MHFE
`3d2fcd0e6fd95247cb353055e7244eb61c2af8fc` against released suite 3. They
exercise only public fixtures or synthetic data. They do not replay full-cost
Argon2 vectors. None accepts private wallet data.

Run commands from the authoritative MHFE checkout. Do not create another checkout
for this audit. The recorded report contains every executed child command,
including initial failures and corrected attempts. Its JSON companion retains
exact argument arrays and environment values.

## Prerequisites and preparation

Use the toolchains from the workspace and repository `AGENTS.md`: Rust/Cargo
1.98.1, Node 26.10.0, Python 3.14.4, Emscripten 6.0.10 and wasm-bindgen 0.2.128.
`jsonschema` is needed only by the report validator. GNU `sha256sum` is needed by
the checksum-format probe. `gh` with public GitHub access is needed by the upstream
probe. Browser tests use the installed Playwright dependency of the adjacent
`multi-chain-wallet-tools` checkout and its Chromium and Firefox installations.
Do not install replacement runtimes to run this review.

```sh
export CARGO_HOME=/home/user/Documents/bip_tools/workingspace/cargo
export RUSTUP_HOME=/home/user/Documents/bip_tools/workingspace/rustup
export PATH="$HOME/.local/bin:$CARGO_HOME/bin:$PATH"
export CARGO_BUILD_JOBS=1
```

`run.py` creates local ignored evidence under `docs/audits/AUD-004-evidence/`,
records exit codes, exact commands, timestamps and log hashes, and refuses to
overwrite command records. Choose a new label for every rerun. On a first run only:

```sh
python3 docs/audits/AUD-004-harnesses/run.py capture
```

An existing snapshot must be preserved. `metadata.py` and the report validator
intentionally require the originally reviewed source bytes; after remediation,
a source-identity failure is expected and must not be bypassed or represented as a
baseline pass. Direct defect probes remain usable after remediation.

Native probes need `target/release/mhfe`; browser probes need the fresh `dist/`
package. The report records the exact serialized native and WASM build commands.
The license probe also needs the three local archives created by the report's
`packaging` command in `docs/audits/AUD-004-evidence/packages/`.

## Individual checks

Each command below exits zero on success and nonzero when its assertions fail.
The three defect probes are expected to fail on the reviewed commit.

```sh
python3 docs/audits/AUD-004-harnesses/run.py rerun-metadata -- python3 docs/audits/AUD-004-harnesses/metadata.py
python3 docs/audits/AUD-004-harnesses/run.py rerun-cli -- python3 docs/audits/AUD-004-harnesses/cli-regressions.py
python3 docs/audits/AUD-004-harnesses/run.py rerun-browser -- node docs/audits/AUD-004-harnesses/browser.mjs
python3 docs/audits/AUD-004-harnesses/run.py rerun-upstream -- python3 docs/audits/AUD-004-harnesses/upstream.py
python3 docs/audits/AUD-004-harnesses/run.py rerun-checksum -- python3 docs/audits/AUD-004-harnesses/checksum-format.py
python3 docs/audits/AUD-004-harnesses/run.py rerun-macos -- python3 docs/audits/AUD-004-harnesses/macos-memory.py
python3 docs/audits/AUD-004-harnesses/run.py rerun-licenses -- python3 docs/audits/AUD-004-harnesses/licenses.py
```

- `metadata.py` verifies the tracked source fingerprint, the adjacent
  `mhfe_spec` README and supplement, 22 vendored Argon2 hashes, 18 corpus files,
  validation fixtures and recorded independent-verification provenance. It
  verifies historical replay records without executing their KDF calculations.
- `cli-regressions.py` verifies five pre-computation CLI refusals, absence of
  secret-bearing output, and four simultaneous checksum refreshes against copies
  of public vector JSON files. Its selector matches no vector, so it generates
  no Argon2 transcript. Temporary public fixtures are removed automatically.
- `browser.mjs` exercises the actual client and workers in Chromium and Firefox,
  with normal browser sandbox and CSP, in file mode and isolated loopback mode.
  An audit-only wrapper substitutes 256 KiB and one pass at the Argon2 boundary;
  the production bundle is unchanged. It checks fixed reduced-cost output,
  recovery, rehearsal, validation, active cancellation, restart and absence of
  external requests. Generated pages remain only in ignored evidence. Loopback
  and browser execution require host permissions when the execution sandbox
  forbids them.
- `upstream.py` compares all 22 vendored files with the pinned upstream Git tree
  without cloning, and reads GitHub's private-vulnerability-reporting setting.
- `checksum-format.py` generates genuine GNU text and binary checksum records
  for synthetic HTML. On the reviewed commit text succeeds and binary fails in
  both Python and Rust launchers, reproducing **AUD-004-FUN002**. No browser is
  opened; the native loopback server is stopped after startup.
- `macos-memory.py` extracts the unchanged production arithmetic expression and
  compiles a tiny Rust fixture. It reports 2 GiB where free plus inactive pages
  account for 1.5 GiB, then fails its assertion, reproducing **AUD-004-FUN001**.
  Apple specifies that speculative pages are already included in `free_count`.
  This is a counter-contract test on Linux, not a native macOS memory-pressure
  experiment, and allocates no large buffer.
- `licenses.py` reads the locked `bech32` license using offline Cargo metadata,
  confirms production use, and searches the actual three archives for its
  copyright notice. All three lack it, reproducing **AUD-004-BLD001**. The
  assertion covers this concrete dependency, not an exhaustive legal assessment.

The report additionally records existing repository tests, Unix PTY tests, the
previous audit's 32-bit compile guard, and 17 independent transcript checks with
recorded Argon2 keys. Their exact commands are retained in the report. Supplying
`--trust-argon2-keys` is essential for the latter: omitting it would execute the
full-cost operations excluded from this audit.

## Record validation

After report edits, run directly rather than through `run.py` (a running log
would make its own checksum unstable):

```sh
python3 docs/audits/AUD-004-harnesses/validate_report.py
```

It rejects duplicate JSON keys, validates the shared report schema, accounts for
all 32 procedure IDs, matches finding IDs to Markdown, checks command log hashes,
source/specification identity and relative document links, and confirms local
evidence is ignored and unstaged. It writes local `report-validation.json` and
regenerates the local evidence `SHA256SUMS`. The original evidence is needed for
this historical-record validation; the defect probes above do not need its logs.
