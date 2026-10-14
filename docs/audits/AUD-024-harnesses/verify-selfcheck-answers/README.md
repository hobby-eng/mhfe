# AUD-024 harness: verify-selfcheck-answers

Audit AUD-024, adversarial verifier of the candidate "the startup self-checks do not cover four
library answers that the front ends show", reviewed commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1`.

## What it checks

`run.py` copies the crate (`src`, `Cargo.toml`, `Cargo.lock`, `build.rs`, `vendor`,
`rust-toolchain.toml`, `clippy.toml`, `tests/fixtures`, `scripts/independent-suite3.py`) to a work
directory and never writes into the repository. It first runs the unchanged copy, then applies four
faults, each alone, that differ from the guide-lib-wallet harness's mutants:

- V1 `src/rehearsal.rs` `evidence_of`: the 16-bit evidence `CheckEvidence::wallet_check` is inverted.
- V2 `src/rehearsal.rs` `CheckEvidence::own_checks_passed`: the verified reading's built-in check
  is left out of the list.
- V3 `src/operation.rs` `Keep::old_container`: a PIM or memory level other than 0 is left out.
- V4 `src/rekey.rs` `ConfirmedPhrase::replacement_rehearsal`: a phrase confirmed by an address or a
  fingerprint is rehearsed by a fingerprint instead of its confirming reference.

For each it runs `self_check::sets::tests::every_set_passes_at_startup` (the repair, passwords,
wallet and native sets at the startup tier; the native set holds the core set that the browser runs
too) and the known-answer tests of the part. A fault "survives" when they all pass. The unit test
that covers the answer is run as a control and must fail. Only library unit tests run, at the
reduced test cost: no full-cost Argon2.

Exit 0 when every fault is killed and every control fails; exit 1 when any fault survives or a
control passes; exit 2 when the unchanged copy does not pass.

Inputs: public test data only (the published vectors of `tests/fixtures`). Needs cargo (the
toolchain of `rust-toolchain.toml`) with the crates of `Cargo.lock` fetched, and python3.
`CARGO_TARGET_DIR` is honoured (default `../tmp/aud024/target` beside the repository).

## Running

From the repository root:

```sh
CARGO_TARGET_DIR=../tmp/aud024/target \
  python3 docs/audits/AUD-024-harnesses/verify-selfcheck-answers/run.py \
  ../tmp/aud024/verify-selfcheck-answers/work
```

## Expected output at b6fca69

Exit 1. `unchanged copy: exit 0, 8 tests`; each of V1 to V4 prints `SURVIVES (exit 0)` and
`control ...: fails (the fault is real)`; the last line is
`4 of 4 faults survive the self-checks or have no failing control`.
