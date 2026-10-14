# AUD-024 verifier harness: the self-test at other settings than the vectors'

Audit AUD-024, verifier of the candidate finding "SelfTest::run does not refuse an engine at other
settings than the published vectors' and reports a false 'fault before Argon2id'", reviewed commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1`.

What it checks: that `SelfTest::run` (src/self_test.rs), whose documentation says its `mhfe` "must
be at the default settings", refuses with `INVALID_REQUEST` an `Mhfe` at PIM 1 or at memory level
1, as `Rekey::recover_state` refuses a recovery at other settings than the old container's. The
engine of the probe is right for every published round (the recorded key for a recorded input, a
hash for any other), as a correct Argon2id would be; a control runs it at the default settings,
where the self-test must pass. A fourth test prints the settings that the published table records
for the two vectors `run` already looks up.

Inputs: the public vectors `tests/fixtures/suite3-vectors/zero-12.json` and
`tests/fixtures/suite4-vectors/same-length-zero-12.json` built into the library. No Argon2 runs at
all. Needs cargo with the crates of `Cargo.lock` already fetched (`--offline`). The repository is
never written: the crate is copied to a work directory and `probe.rs` is appended to the copy's
`src/self_test.rs`. `CARGO_TARGET_DIR` is honoured.

## Running

From the repository root, with an optional work directory (default
`${TMPDIR:-/tmp}/aud024-verify-selftest-settings`):

```sh
CARGO_TARGET_DIR=../tmp/aud024/target docs/audits/AUD-024-harnesses/verify-selftest-settings/run.sh [work dir]
```

## Expected output at b6fca69

It exits 101 (a probe fails). The control prints `run at PIM 0, memory level 0: Ok(SelfTestResult
{ suite_3: true, suite_4: true, first_round_fault: None }); 24 rounds ran` and passes. At PIM 1
and at memory level 1 it prints `Ok(SelfTestResult { suite_3: false, suite_4: false,
first_round_fault: Some(Argon2Input { round: 1 }) }); 24 rounds ran` and the shown fault
`first wrong round 1 of 24: Argon2id was given an input that the published vector does not have,
so the fault is before Argon2id, ...`, and both tests fail with `left: None` against
`right: Some("INVALID_REQUEST")`. The table test prints `pim 0, memory_level 0` for `zero-12` and
`same-length-zero-12`. Once fixed, all four tests pass and the script exits 0.
