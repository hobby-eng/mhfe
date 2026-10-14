# AUD-024 harness: guide-lib-wallet

Audit AUD-024, reviewer role guide-lib-wallet (coding-guide conformance and architecture of the
wallet, rehearsal, search, rekey, hidden-wallet, wallet-check, self-check, self-test, vector and
known-answer modules), reviewed commit `b6fca69238344dd2525b06270ee6ff3b055e68c1`.

`run.py` works on a scratch copy of the crate (`src`, `Cargo.toml`, `Cargo.lock`, `build.rs`,
`vendor`, `rust-toolchain.toml`, `clippy.toml`, `tests/fixtures` and
`scripts/independent-suite3.py`); it never writes into the repository. It runs only unit tests of
the library at the reduced test cost: no full-cost Argon2.

## What it checks

`mutants`: each of seven changes, applied alone, must make a self-check or its tests fail.

- M1 to M4 change library answers that the front ends show: the 16-bit wallet-check evidence of a
  rehearsal check (`CheckEvidence::wallet_check`), the list of the phrase's own checks that passed
  (`CheckEvidence::own_checks_passed`), the keep list of a rekey's old container
  (`Keep::old_container`) and the rehearsal reference of a rekey's replacement
  (`ConfirmedPhrase::replacement_rehearsal`). The tests run are the startup self-check of every set
  (`self_check::sets::tests::every_set_passes_at_startup`) and the known-answer tests of the part.
  Each is also run against the unit test that covers it, as a control that the change is real.
- M5 to M7 break the rekey self-check itself (`src/rekey/known_answers.rs`): its comparison with the
  published container, its three refusals and its second confirmation always pass. The tests run
  are those of `rekey::known_answers`.

A mutant that leaves every test passing "survives". Exit 1 when any survives.

`probes`: five Rust tests (`probes/*.rs`, appended to the copy) assert the behaviour that the
coding guide or the code's own documentation asks for:

- `rekey_known_answers.rs`: `a_rekey_is_compared_with_its_target_vector` fails its rekey to
  `nonzero-12` on the comparison with the published container, as its comment says.
- `engine_known_answers.rs`: `a_wrong_lane_count_fails` fails on the MHFE-shaped 1 MiB call, as its
  comment says.
- `self_test.rs`: `SelfTest::run` refuses an engine at other settings than the published vectors'
  (PIM 1; a hashing stand-in replaces Argon2).
- `wallet_keys.rs`: a BIP39 passphrase of 8 MiB is refused (CORE-48).
- `wallet_encodings.rs`: an address text of up to 32,000 characters is refused within 50 ms
  (CORE-48, CORE-50).

Exit 1 when any probe fails.

Inputs: public test data only (the published vectors of `tests/fixtures`, the "abandon ... about"
phrase, BIP-0084's address). Needs cargo (Rust 1.99.0) with the crates of `Cargo.lock` fetched and
python3. `CARGO_TARGET_DIR` is honoured (default `../tmp/aud024/target` beside the repository).

## Running

From the repository root, with an optional work directory (default
`../tmp/aud024/guide-lib-wallet/harness-work`):

```sh
python3 docs/audits/AUD-024-harnesses/guide-lib-wallet/run.py mutants [work dir]
python3 docs/audits/AUD-024-harnesses/guide-lib-wallet/run.py probes [work dir]
python3 docs/audits/AUD-024-harnesses/guide-lib-wallet/run.py all [work dir]
```

## Expected output at b6fca69

`mutants` exits 1 and ends with `7 of 7 mutants survive the self-checks`; each of M1 to M4 prints
`control ...: fails (mutation is real)`.

`probes` exits 1 and ends with `5 probe(s) fail`. Among its lines:

- `AUD024 RekeyCheck zero-12 -> nonzero-12: Failed("rekey 1 of 1 stops with INTERNAL_ERROR")`;
- `AUD024 Argon2 check with two lanes: Failed("the SSE2 core gives another tag for the RFC 9106
  vector")` (on x86-64; another processor names its own core);
- `AUD024 SelfTest::run at PIM 1: Ok(SelfTestResult { suite_3: false, suite_4: false,
  first_round_fault: Some(Argon2Input { round: 1 }) })`;
- `AUD024 passphrase of 8388608 bytes: normalized buffer reserved 92274688 bytes` and
  `AUD024 master_fingerprint: Ok("27f79526") ...`, `AUD024 PhraseDraw::with_check accepted: true`;
- the Base58 times growing with the square of the length, about 0.1 s, 0.5 s and 2 s for 8,000,
  16,000 and 32,000 characters in a debug build.
