# AUD-010 crypto-core skeptic harness

Audit-only script of the AUD-010 skeptic who challenged the two crypto-core findings (the wallet
check on short readings and an empty passphrase; the strict phrase reading of fingerprints and
address searches) of mhfe at HEAD `d7af4b1035355a69779f8ad70a9dc50ba5b9ffd0` plus the uncommitted
working tree with source fingerprint
`372da577dd586932d6b3fa47711d97bc25b8fa908a980cd2373b704724ec796b` (227 paths,
`../fingerprint.mjs`). It changes nothing in the repository and uses public test data only.

| Script         | What it checks |
| -------------- | -------------- |
| `challenge.py` | Recomputes without the reviewer's scripts the MHFE-WALLET-CHECK-SEED-1 digest of the 12-word original of the published vector zero-12 with the public passphrase `aud010 public probe 11656`, with BE32(128) and BE32(256), and the profile's answer on zero-12's 24-word reading; asks the reviewed library (the crypto-core probe) `phrase_passes`, `verify`, `master_fingerprint` and `read_phrase`; checks in the source that the rehearsal compares every reading for `Reference::WalletCheck`, that the CLI accepts an empty wallet-check passphrase while only the WebAssembly binding refuses it, and that only `MhfeWallet.fingerprint` passes caller-supplied text to `master_fingerprint`. |

## Inputs and running

From the mhfe root, after `../crypto-core/probe.py` has built the probe (or with the same
`cargo build --offline` of its build directory):

```bash
docs/audits/AUD-010-harnesses/run-logged.sh crypto-core-skeptic-challenge \
  python3 docs/audits/AUD-010-harnesses/crypto-core-skeptic/challenge.py
```

`--probe PATH` names another probe binary. Needs Python 3, the bip39 3.0.0 crate sources in
`$CARGO_HOME/registry` (its English list) and `tests/fixtures/suite3-vectors/zero-12.json`. No
Argon2 is computed; it takes about a second.

## Expected output

Every line `PASS ...` and a last line `0 failed`; exit code 0 while both findings hold. A `FAIL`
line names the claim that did not hold, and the exit code is then 1. After the fixes the `F1`
library and source lines and the `F2` refusal lines change by design.

Owner-authorized documentation-only amendment of 2026-10-09: commit references of the history replaced by the second privacy rewrite of 2026-10-09 now name the commits that replaced them: f4f7b017d21cbda51283f9eaa973a0cc161b95d6 -> d7af4b1035355a69779f8ad70a9dc50ba5b9ffd0.
