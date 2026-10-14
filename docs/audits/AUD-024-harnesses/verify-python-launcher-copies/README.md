# Python fast-mode launcher copies: mutation check

Audit AUD-024, commit b6fca69 (b6fca69238344dd2525b06270ee6ff3b055e68c1).

## What it checks

Whether a test keeps the values and messages that `packaging/mhfe-fast-mode.py` copies from
`src/bin/mhfe/serve.rs` and `src/bin/mhfe/exit.rs` equal to their Rust sources (CORE-10: a copy a
build cannot avoid says "deliberate copy" next to it, with its reason, and a test keeps both copies
in step).

For each mutation it copies the launcher, `scripts/verify-fast-mode-script.py`, `serve.rs`,
`style.rs`, `hidden_input.rs`, `exit.rs` and `Cargo.lock` into a scratch tree, changes one copy
(one refusal or running message, the title, `SHA256_HEX_DIGITS` or an exit code, in the Rust source
or in the launcher alone) and runs `python3 scripts/verify-fast-mode-script.py` there. Four
controls change copies the tests do read (MALFORMED, MAX_CONNECTIONS, a security header,
CHECKSUM_FILE) and must fail.

## Inputs

The repository at the commit above. Standard library Python 3.8 or later. The tests open loopback
sockets on 127.0.0.1 only; no network and no Argon2.

## Command, from the repository root

    python3 docs/audits/AUD-024-harnesses/verify-python-launcher-copies/mutate.py . [scratch folder]

## Expected output

At b6fca69: the baseline passes (31 tests, OK), all 16 mutations of copied messages, the title,
`SHA256_HEX_DIGITS` and the exit codes print `PASSED (drift unnoticed)`, the four controls print
`FAILED (drift caught)`, and the harness exits 1 with
`mutations of copies that no test caught or invalid controls: 16`.

Once the defect is fixed, every mutation prints `FAILED (drift caught)` and the harness exits 0.
