# AUD-015 R1 harnesses: cryptographic core and formats

Audit-only probes of reviewer R1 of AUD-015 (CHECK-SEC-004, CHECK-FUN-001, CHECK-FUN-006). They
were run against HEAD `4c3a6909bced0f0907f61ae291b11bb6bb419689` plus the uncommitted working tree
of source fingerprint `f79444dc9884d11a54c2c0b316ce31bf3a3a734e5bb604e9667df09cf0482a93`, with the
browser package `dist/` of build id `6a91d106c1b87634`, and the specification working tree in
`../mhfe_spec`. They change no product file. Public test data only: the BIP39 zero vectors, the
specification's published vectors and synthetic passwords and phrases.

Run every command from the repository root through the evidence runner, for example
`python3 docs/audits/AUD-015-harnesses/run.py r1-oracle-vectors python3 docs/audits/AUD-015-harnesses/r1-crypto/oracle.py vectors ../mhfe_spec/vectors`.
Each probe exits non-zero on its first disagreement and prints it. None runs Argon2 at the suite's
cost: the transcripts are replayed with their recorded round keys, and every other Argon2id call is
at 256 KiB and one pass (the reduced cost of `src/test_support.rs`) or 1 MiB (the package's own
known answer). Each needs well under 800 MiB.

| File                  | What it checks                                                                                                                                                                                                                                                                                                                       | Inputs                                                                                                   | Expected output                     |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| `oracle.py`           | An independent suite 3 and suite 4 implementation written from the specification text (hashlib, hmac, `openssl kdf ... ARGON2ID`, the BIP39 list from @scure/bip39 pinned by the hash of `english.txt`). Subcommands below.                                                                                                          | Python 3, OpenSSL 3.2 or later, the workspace's `multi-chain-wallet-tools/node_modules`                   | `PASS ...` per subcommand           |
| `oracle.py vectors`   | Replays all 17 suite 3 and 10 suite 4 transcripts in both directions without Argon2: password bytes, packing, verifier, every salt and mask input, salt, mask and state, container words, recovery readings; the fast detection, serialization and settings cases; three negative controls that must fail                             | `../mhfe_spec/vectors`                                                                                   | three expected `FAIL` lines, `PASS` |
| `oracle.py reduced`   | Recomputes `REDUCED_COST_CONTAINER` and `REDUCED_COST_SAME_LENGTH_CONTAINER` pinned in `src/mhfe.rs`                                                                                                                                                                                                                                 | repository root                                                                                          | `PASS reduced`                      |
| `oracle.py profiles`  | MHFE-WALLET-CHECK-SEED-1 digests and negatives, MHFE-REPAIR-1 cards and generator coefficients, MHFE-PASSWORD-CHECK-1 passwords, all parsed from the specification text                                                                                                                                                             | `../mhfe_spec`                                                                                           | `PASS profiles`                     |
| `password-probe/`     | A small Rust program on the library's public API (`Password::from_utf8`, `read_phrase`), path dependency on the repository root. Build: `env CARGO_TARGET_DIR=target/aud015-r1 cargo build --release --offline -j 1 --manifest-path docs/audits/AUD-015-harnesses/r1-crypto/password-probe/Cargo.toml` with the workspace toolchain | Rust 1.99.0                                                                                              | a binary                            |
| `passwords.mjs`       | Every Unicode scalar value, 20,008 random strings rich in combining marks and the length boundaries, and the specification's 33 password cases, against ICU's Unicode 17.0 data (Cc, Cn, NFKD)                                                                                                                                       | the probe binary, `../mhfe_spec/vectors/suite3/validation-cases.json`, Node.js with `process.versions.unicode` 17.0 | `PASS passwords`                    |
| `gen_phrases.py`      | 22,143 typed phrases: every word cut to every length, in three letter cases, at the first and at a random place, with mixed whitespace; piped through `password-probe phrases` and compared by `oracle.py phrases` with the Reading words rule                                                                                       | the probe binary                                                                                         | `PASS phrases`                      |
| `wasm_probe.mjs`      | The built browser core at the reduced cost: 27 encryptions and wrong-password readings (recomputed by `oracle.py batch`), refusals before any round, and the rekey with a detected length confirmed by the built-in check alone (AUD-015 finding of R1)                                                                              | `dist/`, `target/wasm-bindgen/mhfe.js`, output path for the cases                                        | `PASS wasm probe`, `PASS batch`     |
| `profiles_probe.mjs`  | The built package's repair words and repairs within `2e + s <= k`, check-word reviews and wallet checks, recomputed by `oracle.py profilecases`                                                                                                                                                                                     | `dist/`, `target/wasm-bindgen/mhfe.js`, output path                                                       | `PASS profilecases`                 |
| `selfcheck_probe.mjs` | The core module's own full-tier self-check in the package; only the 1 MiB Argon2 known answer may run                                                                                                                                                                                                                               | `dist/`, `target/wasm-bindgen/mhfe.js`                                                                   | every part `passed`                 |
| `provenance.sh`       | Vendored Argon2 files against `vendor/phc-winner-argon2.md`, the EFF list against the specification's hash, the fixtures against the specification's vectors and SHA256SUMS, `src/mhfe/published_rounds.rs` against its generator                                                                                                  | `../mhfe_spec`                                                                                           | five lines, exit 0                  |

The pipelines as run, with the evidence labels of AUD-015:

```sh
H=docs/audits/AUD-015-harnesses/r1-crypto; E=docs/audits/AUD-015-evidence
python3 $H/gen_phrases.py | target/aud015-r1/release/aud015-r1-password-probe phrases > $E/r1-phrase-reading.probe.txt
python3 $H/oracle.py phrases $E/r1-phrase-reading.probe.txt
node $H/wasm_probe.mjs $E/r1-wasm-cases.json && python3 $H/oracle.py batch $E/r1-wasm-cases.json
node $H/profiles_probe.mjs $E/r1-profiles-cases.json && python3 $H/oracle.py profilecases $E/r1-profiles-cases.json
```

Limits: the vendored Argon2 files are compared with the list in the repository, not with the
upstream repository (no network); the oracle's NFKD is Python's (Unicode 16.0), so its Unicode test
passwords use characters older than 16.0, while `passwords.mjs` uses ICU's Unicode 17.0; no
suite-cost Argon2 call and no published-vector replay with Argon2 was run.
