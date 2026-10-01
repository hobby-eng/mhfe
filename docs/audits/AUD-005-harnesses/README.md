# AUD-005 reproduction harnesses

These scripts belong to [AUD-005](../audit-05-2026-10-01.md), the full audit of MHFE at
`d4de5e8a3da0a41bc31c6b9c40a91cbdf0d36124` (`main`, tag `v0.4.0`) against suite 3. They use only
public test data: the BIP39 phrases `abandon ... about` and `legal winner ...`, the public test
passwords of the vector corpus and words of the EFF list. None runs a full-size Argon2 operation,
and none accepts real wallet data.

Run every command from the root of the MHFE checkout. Do not make another checkout for a rerun.

## Prerequisites

The toolchains of the workspace and of the repository's `AGENTS.md`: Rust/Cargo 1.98.1 with the
workspace `CARGO_HOME` and `RUSTUP_HOME`, wasm-bindgen 0.2.129, Emscripten 6.0.10 from
`../workingspace/emsdk`, Node 26.10.0 and Python 3.8 or later (the audit used 3.14.4). Further
needs:

- `jsonschema` for Python, for `validate_report.py` only;
- `gh` with public GitHub access, for `upstream.py`;
- util-linux `script`, for the colour probes in `cli-probes.py`;
- the Playwright package and its Chromium and Firefox of the adjacent `multi-chain-wallet-tools`
  checkout, for `browser.mjs`;
- the adjacent `../mhfe_spec` checkout, for `metadata.py`, and the multi-chain-wallet-tools checkout
  for the report schema and the audit guide.

```sh
export CARGO_HOME=/home/user/Documents/bip_tools/workingspace/cargo
export RUSTUP_HOME=/home/user/Documents/bip_tools/workingspace/rustup
export PATH="$HOME/.local/bin:$CARGO_HOME/bin:$PATH"
cargo build --locked --release                     # target/release/mhfe for the CLI probes
source ../workingspace/emsdk/emsdk_env.sh && scripts/build-wasm.sh   # dist/ for browser.mjs
```

`run.py` keeps the local, git-ignored evidence in `docs/audits/AUD-005-evidence/`: for each command
a log and a record with the exact command, UTC start and end, exit code and log SHA-256. It refuses
to overwrite a label, so give every rerun a new one. `python3 run.py capture` wrote the snapshot of
the reviewed commit once and refuses to run again.

```sh
python3 docs/audits/AUD-005-harnesses/run.py <new-label> -- <command> [argument ...]
```

## The scripts

Each exits with 0 when every check passes and with a non-zero code when one fails.

| Command                                                                                                                                       | What it checks                                                                                                                                                                                                                                                                                                                                                                                                                                  | Expected at `df70ca5`                       |
| --------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| `cargo run --offline --quiet --manifest-path docs/audits/AUD-005-harnesses/phrase-copies/Cargo.toml --target-dir target/aud005-phrase-copies` | A global allocator looks into every freed or moved heap block for the start of a public phrase while `mhfe::read_phrase` runs (AUD-005-SEC001). It also prints, for information, the count for `mhfe::wallet::master_fingerprint`.                                                                                                                                                                                                              | exit 1, "4 freed heap blocks"               |
| `python3 docs/audits/AUD-005-harnesses/cli-probes.py`                                                                                         | The colour rules (`NO_COLOR`, `CLICOLOR=0`, `CLICOLOR_FORCE`, `TERM=dumb`, pipes); the weak-password warning (AUD-005-FUN001); the advice after a failed memory reservation (AUD-005-UI001); `check --stdin` without a reference option. The password probes run `mhfe encrypt --stdin` under a 1 GiB address-space limit, so the tool stops with exit code 4 at the 2 GiB reservation, after it has judged the password and before any Argon2. | exit 1, two failed expectations             |
| `python3 docs/audits/AUD-005-harnesses/cli-regressions.py`                                                                                    | Five refusals before any computation and four simultaneous checksum refreshes of copies of the vector files, with a selector that matches no vector, so no Argon2 runs.                                                                                                                                                                                                                                                                         | exit 0                                      |
| `node docs/audits/AUD-005-harnesses/browser.mjs`                                                                                              | The real client and workers in Chromium and Firefox, under a strict CSP, opened as a file (standard mode) and from an isolated loopback server (fast mode). An audit-only wrapper replaces the 2 GiB, 12-pass Argon2 call by 256 KiB and one pass; the package files are not changed. Encryption, recovery, rehearsal, a refused password, cancellation before and during a round and restart.                                                  | exit 0                                      |
| `python3 docs/audits/AUD-005-harnesses/metadata.py`                                                                                           | The tracked files are the reviewed bytes; the 22 vendored Argon2 files match their recorded hashes; the 18 corpus files and the fast cases equal `../mhfe_spec/vectors/suite3/`. It reads the working tree, so after the remediation commits it reports the changed files and fails, as intended.                                                                                                                                               | exit 0 at `df70ca5`, exit 1 after the fixes |
| `python3 docs/audits/AUD-005-harnesses/upstream.py`                                                                                           | The vendored Argon2 files against the Git blobs of upstream commit `f57e61e1` (read through the GitHub API, nothing cloned), and that private vulnerability reporting is enabled.                                                                                                                                                                                                                                                               | exit 0                                      |
| `python3 docs/audits/AUD-005-harnesses/validate_report.py`                                                                                    | The JSON record against the shared schema, without duplicate keys; finding IDs, headings, severities and statuses in both records; all 32 procedure IDs; every command log hash; the snapshot against the git objects of the reviewed commit; local links; evidence ignored, untracked and unstaged. It writes the local `report-validation.json` and `SHA256SUMS`. Run it directly, not through `run.py`.                                      | exit 0                                      |

The report records the other commands it ran, such as the test suites, the browser package checks,
the 17 transcripts checked with `scripts/independent-suite3.py vector --trust-argon2-keys`, the
RustSec scan and the 32-bit guard of `../AUD-003-harnesses/refuse32.sh`. The option
`--trust-argon2-keys` matters: without it the independent script recomputes every Argon2 call at
full size.

After the remediation, `phrase-copies` reports 0 copies and `cli-probes.py` passes every
expectation; both are rerun under new labels and quoted in the report's remediation table.
