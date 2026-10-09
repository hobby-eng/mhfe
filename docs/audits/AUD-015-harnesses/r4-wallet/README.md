# AUD-015 R4 harnesses: wallet and word features

Audit AUD-015 of mhfe, reviewer R4 (wallet and word features). Reviewed tree: commit
`4c3a6909bced0f0907f61ae291b11bb6bb419689` plus the uncommitted working tree with source fingerprint
`f79444dc9884d11a54c2c0b316ce31bf3a3a734e5bb604e9667df09cf0482a93`. Run everything from the
repository root through `docs/audits/AUD-015-harnesses/run.py`, which keeps each log and its record
in the ignored `docs/audits/AUD-015-evidence/`. Public test data only; no full-cost Argon2.

Inputs: the read-only `node_modules` of `../multi-chain-wallet-tools` (`@scure/bip39`, `@scure/bip32`,
`@scure/base`, `@scure/btc-signer`, `@noble/hashes`, `@noble/curves`) as independent references;
the release binary `target/release/mhfe` (`cargo build --release`); the browser package
(`scripts/build-wasm.sh`: `target/wasm-bindgen/mhfe.js`, `dist/runtime/mhfe.wasm`).

| Script                        | What it checks                                                                                                                                                                                                                                                                                                                                | Expected now                                                       |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `address-oracle.mjs`          | An independent derivation and encoding of every coin's addresses, first proven on published values (BIP44/49/84/86, CashAddr spec, EIP-55, XRP genesis, btc-signer P2TR); reproduces the 43-row `ADDRESSES` table of `src/wallet.rs` read as text; writes 679 extra cases and 9 fingerprints to `r4-wallet-cases.json` in the evidence folder | exit 0                                                             |
| `wallet-check-oracle.mjs`     | MHFE-WALLET-CHECK-SEED-1 from the specification's text with Node's OpenSSL: every published digest, then a fresh vector for the NFKD-changing passphrase `Café ﬁ` (`r4-wallet-check-vector.json`); about 65,536 PBKDF2 seeds, under two minutes                                                                                                | exit 0, counter 53098                                              |
| `rust-probe/` `addresses`     | `find_address` at each case's path and by the default search (and outside the default limits), the `AddressSearch` statement against the standards' paths, master fingerprints                                                                                                                                                                 | exit 0, 2049 checks                                                |
| `rust-probe/` `hints`         | `word_hints` against the documented rule for every prefix of both lists, with typing past the end of a word                                                                                                                                                                                                                                   | exit 1: 19,156 lines of more than 9 letters get no "no word" hint  |
| `rust-probe/` `wishes`        | The documented bit figures from first principles; measured draws per phrase against `odds().expected_draws` in six wish sets; every drawn phrase read back                                                                                                                                                                                     | exit 0                                                             |
| `rust-probe/` `wallet-check`  | The fresh vector through `passes`, `verify` (as typed), checked draws from a scripted source just before it, with and without wishes, a missed wish skipped, and `draw_on_every_core`; about 1,100 PBKDF2 seeds in all                                                                                                                         | exit 0                                                             |
| `wasm-parity.mjs`             | The browser package's `walletParameters`, `walletFingerprint`, `describeAddress`, `wordHints`, `describeDraw`, `walletCheck` and `drawPhrase` against the same oracles and rules (what `scripts/verify-cli-browser-parity.mjs` does not compare)                                                                                            | exit 1: the same long-word hint difference, 8,481 lines            |
| `never-use-loop.py`           | `mhfe new --never-use notaword` in a pseudo-terminal: the refused option word is asked about again and again                                                                                                                                                                                                                                 | exit 1 (defect reproduced)                                         |
| `never-use-check-warning.py`  | `mhfe new --never-use abandon` with the wallet check and no chosen word: the warning shown, stopped before any draw                                                                                                                                                                                                                         | exit 1 (defect reproduced)                                         |

Build the probe (its own workspace; the `Cargo.lock` began as a copy of the repository's):

```sh
python3 docs/audits/AUD-015-harnesses/run.py r4-probe-build env \
  CARGO_HOME=$PWD/../workingspace/cargo RUSTUP_HOME=$PWD/../workingspace/rustup \
  CARGO_TARGET_DIR=$PWD/target/aud015-r4 \
  cargo build --release --offline --locked -j 1 \
  --manifest-path docs/audits/AUD-015-harnesses/r4-wallet/rust-probe/Cargo.toml
```

Then, in this order (the probe reads the oracles' output):

```sh
python3 docs/audits/AUD-015-harnesses/run.py r4-address-oracle node docs/audits/AUD-015-harnesses/r4-wallet/address-oracle.mjs
python3 docs/audits/AUD-015-harnesses/run.py r4-wallet-check-oracle node docs/audits/AUD-015-harnesses/r4-wallet/wallet-check-oracle.mjs
python3 docs/audits/AUD-015-harnesses/run.py r4-probe-addresses target/aud015-r4/release/aud015-r4-probe addresses
python3 docs/audits/AUD-015-harnesses/run.py r4-probe-hints target/aud015-r4/release/aud015-r4-probe hints
python3 docs/audits/AUD-015-harnesses/run.py r4-probe-wishes target/aud015-r4/release/aud015-r4-probe wishes
python3 docs/audits/AUD-015-harnesses/run.py r4-probe-wallet-check target/aud015-r4/release/aud015-r4-probe wallet-check
python3 docs/audits/AUD-015-harnesses/run.py r4-wasm-parity node docs/audits/AUD-015-harnesses/r4-wallet/wasm-parity.mjs
python3 docs/audits/AUD-015-harnesses/run.py r4-never-use-loop python3 -B docs/audits/AUD-015-harnesses/r4-wallet/never-use-loop.py target/release/mhfe
python3 docs/audits/AUD-015-harnesses/run.py r4-never-use-check-warning python3 -B docs/audits/AUD-015-harnesses/r4-wallet/never-use-check-warning.py target/release/mhfe
```

Each script exits non-zero on a difference and prints each one; the two pseudo-terminal scripts
exit 1 while the defect they reproduce is present and 0 once it is fixed.
