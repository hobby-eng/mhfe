# AUD-024 verify-script-arguments harness

Audit AUD-024, commit b6fca69238344dd2525b06270ee6ff3b055e68c1.

What it checks: that the repository's check and generator scripts refuse a command line outside
their usage (CORE-48, the precedent of AUD-012-ARC002 and `scripts/gate-command-line.mjs`) instead
of running another check, or none, and exiting 0. Cases:

- `verify-browser-package-misspelled-full`: a static trace (`full-flag-trace.mjs`) of
  `scripts/verify-browser-package.mjs`, which is not run because it writes
  `target/build-id-check/`. It lists where the script reads `process.argv`, evaluates the
  expression of line 54 for misspellings of `--full` (`--Full`, `-full`, `--full-size`, `--fulll`,
  `full`, `--full=1`), and fails while they run only the fast parts and nothing in the script
  refuses an argument.
- `verify-argon2-wasm-unknown-option`: `node scripts/verify-argon2-wasm.mjs --full`, a script
  without options, must be refused.
- `suite3-vector-no-file`, `suite3-passwords-no-file`, `suite4-vector-no-file`,
  `suite4-validation-no-file`: the independent checkers with a command and no file must be refused
  (their usage requires a file).
- `generate-cell-widths-misspelled-check`: a copy of `scripts/generate-cell-widths.py` in a
  temporary tree, run with `--chek` against a changed copy of the table, must refuse and leave the
  table as it was. The tracked `src/bin/mhfe/cell_widths.rs` is never written.

Inputs: none beyond the repository. Requirements: Node.js (the audit ran v26.10.0), the browser package in `dist/` (from
`scripts/build-wasm.sh`; the Argon2 check runs at most 256 MiB), and `PYTHONPATH` naming a folder
with the packages of `scripts/independent-suite3-requirements.txt` (`unicodedata2` 17.0.1,
`cryptography`). No full-size Argon2 runs; no file of the repository is written.

Command, from the repository root:

    PYTHONPATH=<folder with the packages> docs/audits/AUD-024-harnesses/verify-script-arguments/run.sh

Expected output at b6fca69: `FAIL` on all seven lines (`6 misspellings run only the fast parts,
with no refusal`; `exit 0, the command line was not refused` five times; `exit 0; wrote
src/bin/mhfe/cell_widths.rs`) and exit code 1. After a fix every line is `PASS` and the exit code
is 0.
