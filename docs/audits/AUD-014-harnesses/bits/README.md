# AUD-014 bit oracle

`public-api-oracle.rs` reviews the chosen/excluded-word implementation through the actual public unchecked `PhraseDraw::try_draws` API. It belongs to AUD-014, with baseline commit `abb16671b641378c0fc3c4d855f8d126498e754b` and the dirty source fingerprints retained by the coordinator. Build from the reviewed current checkout first; a previously compiled library does not establish source freshness.

The probe independently represents entropy as a string of MSB-first binary digits and replaces only the prescribed word substring. It checks all 2048 indices at all 23 full-entropy positions against eight edge entropies; all 2048 final indices, their three entropy bits, their eight checksum bits, and every overwritten three-bit preimage; uniform fixed-word preimage multiplicities; every word at every position with anywhere/exclusion/combined predicates; repetitions; constructor range, count and conflict checks; error redaction; and source failure boundaries. It trusts the existing BIP39 dependency for the English word list and SHA-256, after validating the public all-zero and all-ff 24-word vectors. This independence covers MHFE's bit and filter logic, not an independent cryptographic audit of that dependency.

Only synthetic/public data are used. No Argon2, wallet-check seed search, cards, network or installation is performed. The all-zero raw-source refusal is explicitly tested; the fixed-word edge cases use a nonzero bit inside the overwritten region so every free bit can still be zero.

From the repository root, after the coordinator's serialized current-source library build:

```sh
export CARGO_HOME=/home/user/Documents/bip_tools/workingspace/cargo
export RUSTUP_HOME=/home/user/Documents/bip_tools/workingspace/rustup
rustc --edition=2021 -C opt-level=2 -C panic=abort docs/audits/AUD-014-harnesses/bits/public-api-oracle.rs --extern mhfe=target/release/libmhfe.rlib -L dependency=target/release/deps -o docs/audits/AUD-014-evidence/bits-public-api-oracle
docs/audits/AUD-014-evidence/bits-public-api-oracle
```

Use the shared `run.py` wrapper for command metadata, timestamps, log hashes and memory observations. The probe prints independent case counts and a final `PASS`, returning 0 only when every assertion passes. A failed assertion exits nonzero. Compilation is not a runtime result. Compiled artifacts and command records remain in the ignored local evidence directory.

Owner-authorized documentation-only amendment of 2026-10-09: commit references of the history replaced by the second privacy rewrite of 2026-10-09 now name the commits that replaced them: ca0086acf545d07bfe008ae340554124a48442bf -> abb16671b641378c0fc3c4d855f8d126498e754b.
