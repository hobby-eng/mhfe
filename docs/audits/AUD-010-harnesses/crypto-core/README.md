# AUD-010 crypto-core harnesses

Audit-only scripts of the AUD-010 crypto-core review (CHECK-FUN-001, CHECK-FUN-002, CHECK-FUN-006,
CHECK-API-004, CHECK-ARC-003) of mhfe at HEAD `d7af4b1035355a69779f8ad70a9dc50ba5b9ffd0` plus the
uncommitted working tree with source fingerprint
`372da577dd586932d6b3fa47711d97bc25b8fa908a980cd2373b704724ec796b` (227 paths,
`../fingerprint.mjs`). They change nothing in the repository and use public test data only.

| Script                          | What it checks                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `oracle.py`                     | An implementation written for this audit from the specification and the cited standards, sharing no code with mhfe or its `scripts/independent-suite*.py`: BIP39 list hash and the 24 trezor vectors of the bip39 3.0.0 crate, BIP32 vectors 1 and 3, every self-check digest, suites 3 and 4 on all 27 published vectors with their recorded round keys, `src/mhfe/published_rounds.rs`, the reduced-cost containers through OpenSSL Argon2id, repair words and repairs (own GF(2^11) decoder), check word, EFF list, wallet check, all 43 wallet address known answers and the DIP-0017/DIP-0018 vectors. |
| `probe/`                        | A small Rust program that calls mhfe's public library API (phrase reading, fingerprints, `find_address`, `Address::parse`, paths, limits, `AddressSearch::describe`, wallet check, repair words and repair, check word, EFF list, password encoding). Built by `probe.py` outside the repository.                                                                                                                                                                                                                                                                                                           |
| `probe.py`                      | Builds `probe/` against the reviewed tree with a copy of mhfe's `Cargo.lock` (and checks that every shared package keeps mhfe's version), then compares about 2,300 library answers with `oracle.py` or with the specification's rule. Sections `REPRODUCED-wallet-check-rule` and `REPRODUCED-fingerprint-reading` reproduce the two AUD-010 crypto-core findings (the wallet-check rule, the strict phrase reading of fingerprints and address searches) and pass while those defects are present; their answers change by design once they are fixed.                                                    |
| `short_reading_wallet_check.py` | Finds the public passphrase `aud010 public probe 11656` with which the MHFE-WALLET-CHECK-SEED-1 digest of the 12-word phrase "abandon" x11 "about", computed with BE32(128) as mhfe's `phrase_passes` does, starts with 16 zero bits (the input of the reproduction above).                                                                                                                                                                                                                                                                                                                                 |

## Inputs and running

From the mhfe root, with the workspace toolchain:

```bash
export CARGO_HOME=/home/user/Documents/bip_tools/workingspace/cargo
export RUSTUP_HOME=/home/user/Documents/bip_tools/workingspace/rustup
export PATH="$CARGO_HOME/bin:$PATH"
docs/audits/AUD-010-harnesses/run-logged.sh crypto-core-oracle python3 docs/audits/AUD-010-harnesses/crypto-core/oracle.py
docs/audits/AUD-010-harnesses/run-logged.sh crypto-core-probe python3 docs/audits/AUD-010-harnesses/crypto-core/probe.py
python3 docs/audits/AUD-010-harnesses/crypto-core/short_reading_wallet_check.py
```

Needs Python 3 with `cryptography` (OpenSSL Argon2id; the Debian package 46.0.5 was used), the
bip39 3.0.0 crate sources in `$CARGO_HOME/registry`, the specification checkout at `../mhfe_spec`
(read only) and network-free `cargo build --offline`. `probe.py` builds in
`/home/user/Documents/bip_tools/tmp/claude/aud010-crypto-core/probe-build` (`--build-dir` to change
it); dependencies are built with `opt-level = 3` so that the address searches take minutes, not
hours. The heaviest Argon2id call is 256 MiB (the engine's own full-tier known answer).

## Expected output

Every line `PASS ...` and a last line `0 failed`; exit code 0. Any `FAIL` or `MISMATCH` line names
the check and the value that differed, and the exit code is 1. `oracle.py` takes about two seconds,
`probe.py` about five minutes (most of it the address searches), `short_reading_wallet_check.py`
about twenty seconds on 16 cores.

Owner-authorized documentation-only amendment of 2026-10-09: commit references of the history replaced by the second privacy rewrite of 2026-10-09 now name the commits that replaced them: f4f7b017d21cbda51283f9eaa973a0cc161b95d6 -> d7af4b1035355a69779f8ad70a9dc50ba5b9ffd0.
