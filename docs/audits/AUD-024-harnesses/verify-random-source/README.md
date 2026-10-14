# AUD-024 verify-random-source harness

Audit AUD-024, commit b6fca69238344dd2525b06270ee6ff3b055e68c1.

What it checks: that a random source which passes `random::check_source` (two different, non-zero
32-byte probes) and then misbehaves is refused with `RANDOM_FAILED` instead of hanging a password
draw or giving out a weak phrase. Cases:

- `stuck-source-ends-password-draw-*`: `PasswordRecipe::make` for 16 characters, 5 words and the
  check word with a source that gives 0xff for ever after its probes (`uniform_below` refuses every
  value, CORE-50).
- `stuck-source-gives-no-phrase-ff` and `-5a`: `PhraseDraw::unchecked().draw` with a source stuck
  on one byte after its probes (CHECK-SEC-004, repeated responses).
- `half-filling-source-gives-no-phrase`: the same draw with a source that writes only the first half
  of each buffer (CHECK-SEC-004, short responses).
- Two controls that pass at b6fca69: the full self-test's `check_spread` refuses both faulty
  sources, and a working source makes a 16-character password.

Inputs: none beyond the repository; the sources are synthetic and no Argon2 runs. Requirements: the
pinned Rust toolchain 1.99.0 with the workspace `CARGO_HOME` and `RUSTUP_HOME`, offline registry.

Command, from the repository root:

    CARGO_TARGET_DIR=<a folder outside target/> docs/audits/AUD-024-harnesses/verify-random-source/run.sh

Expected output at b6fca69: two `note:` lines saying `check_source` returns `Ok(())` for both
faulty sources, then `FAIL` for the three `stuck-source-ends-password-draw-*` lines (no return
within 5 s), the two `stuck-source-gives-no-phrase-*` lines and `half-filling-source-gives-no-phrase`,
`PASS` for the two controls, and exit code 1. After a fix every line is `PASS` and the exit code is 0.
