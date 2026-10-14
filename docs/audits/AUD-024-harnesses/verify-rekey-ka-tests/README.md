# verify-rekey-ka-tests

Harness of audit AUD-024 (verifier role `verify-rekey-ka-tests`), reviewed commit b6fca69
(`b6fca69238344dd2525b06270ee6ff3b055e68c1`, branch aud023-remediation).

## What it checks

Whether the known-answer meta-tests of the rekey self-check (`src/rekey/known_answers.rs`) and of
the Argon2 engine check (`src/engine/known_answers.rs`) reach the failures they name, and whether
the rekey self-check's container comparison, refusals and second confirmation can be disabled
with every test of the crate still passing.

- `probes`: appends `probes/rekey_known_answers.rs` and `probes/engine_known_answers.rs` to a
  scratch copy of the crate and runs them (`cargo test --lib aud024_verify`).
  - The rekey probe runs the third case of `a_rekey_is_compared_with_its_target_vector`
    (zero-12 to nonzero-12), traces the seal it stops in, runs `sealed_as` against a target whose
    container was changed (control: the comparison fails when it is reached), and asserts that the
    case fails on the comparison, as the test's comment says.
  - The engine probe runs `a_wrong_lane_count_fails`'s own two-lane call, and a call that gives
    two lanes to the MHFE-shaped call only (control), and asserts that the test's call fails on the
    1 MiB vector, as its doc comment says.
- `mutants`: three changes to `src/rekey/known_answers.rs`, each alone, on a scratch copy: M5 the
  comparison of `sealed_as` always true, M6 every refusal passes, M7 `confirmed_again` always
  passes. A mutant survives when every non-ignored test (`cargo test --lib --bins --tests`) passes.

## Inputs

The repository at b6fca69 (copied: src, tests, Cargo.toml, Cargo.lock, build.rs, vendor,
rust-toolchain.toml, clippy.toml, README.md, scripts/independent-suite3.py) and the published
vectors in tests/fixtures. No Argon2 at suite cost: the rekey check replays recorded round keys,
the engine check runs 1 MiB. The repository is never written; the copy lives in
`../tmp/aud024/verify-rekey-ka-tests/work` unless a work directory is given.

## Command, from the repository root

```
CARGO_TARGET_DIR=../tmp/aud024/target python3 docs/audits/AUD-024-harnesses/verify-rekey-ka-tests/run.py all
```

(`probes` or `mutants` runs one part.)

## Expected output

Exit 0 when the defect is fixed: both probes pass and the three mutants are killed.

At b6fca69 it exits 1 with:

```
AUD024 L1 the test's own two-lane call: Failed("the SSE2 core gives another tag for the RFC 9106 vector")
AUD024 L2 two lanes for the MHFE-shaped call only: Failed("the SSE2 core gives another tag for the 1 MiB vector")
AUD024 V1 RekeyCheck(zero-12 -> nonzero-12): Failed("rekey 1 of 1 stops with INTERNAL_ERROR")
AUD024 V2 seal under nonzero-12's password: Err(INTERNAL_ERROR: internal error: no published round has this password and salt) before any comparison
AUD024 V3 sealed_as(unicode-password with another container): Err("the sealed container differs from the published one")
... 2 failed ...
M5 sealed_as's container comparison always true: SURVIVES (cargo exit 0, 507 tests passed in 4 test binaries)
M6 every rekey refusal passes: SURVIVES (cargo exit 0, 507 tests passed in 4 test binaries)
M7 confirmed_again always passes: SURVIVES (cargo exit 0, 507 tests passed in 4 test binaries)
3 of 3 mutants survive every non-ignored test of the crate
```

Evidence: `docs/audits/AUD-024-evidence/verify-rekey-ka-tests/harness-probes.log` and
`harness-mutants.log`, each with its `.command.json`.
