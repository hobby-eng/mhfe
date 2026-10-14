# verify-dup-output-helpers (AUD-024)

Audit AUD-024, verifier role verify-dup-output-helpers, at commit
b6fca69238344dd2525b06270ee6ff3b055e68c1 (branch aud023-remediation). It checks the candidate
finding "two output helpers exist twice" in the command-line tool (`src/bin/mhfe`):

- D1: `style::fact` (through `fact_as` with `Kind::Fact`) and `style::fact_wrapped` run the same
  statements: `fact_lines`, then `flow::keep`, then `write_lines`.
- D2: the AUD-023 fix commit 253ca3c gave `fact_as` the wrap (AUD-023-UI007) and left
  `fact_wrapped` as it was.
- D3: the doc of `fact_wrapped` still presents it as the wrapping variant of `fact`.
- D4: two `fn write_control(sequence: &str)`: `choice::write_control` returns the io error, and
  the copy in `terminal/private_screen.rs` discards it with `let _`, although its parent module
  `terminal.rs` already calls `choice::write_control`.
- D5: neither copy has a "deliberate copy" marker (CORE-10).

Inputs: the git history of the repository (it reads the commit with `git show`, so the working
tree does not matter; set `COMMIT` to check another commit). Needs bash and git. No binary runs,
no secret is used.

Command, from the repository root:

    bash docs/audits/AUD-024-harnesses/verify-dup-output-helpers/dup_output_helpers.sh

Expected at b6fca69: the cited lines, ten call sites of `style::fact_wrapped` in six files, then
`PRESENT` for D1 to D5, `5 of 5 parts present`, `DEFECT REPRODUCED` and exit 1. Once the helpers
are merged (one fact writer, one `write_control`), it prints `DEFECT NOT REPRODUCED` and exits 0.

Log: `docs/audits/AUD-024-evidence/verify-dup-output-helpers/v03-dup-output-helpers.log`, written
by `docs/audits/AUD-024-harnesses/run-logged.sh`. The same folder holds v01 (an earlier scratch run
of the same checks, plus the copies gate at 50 and 20 tokens, which reports neither copy) and v02
(see below).

v02 is a probe of the third fact writer, `style::fact_before_work`, which does not wrap. With the
public zero-12 container and password, the BIP84 test address of "abandon ... about" and a
ten-step `--path`, `mhfe check --stdin --address` stops at the missing passphrase line, before
any Argon2 round, and its "Search" line is 88 columns. That width is not caused by the missing
wrap: `style::wrap` never breaks a word, so `style::fact` would print the 75-character path at 88
columns too. v02 is kept as a record of that check, not as evidence of the finding.
