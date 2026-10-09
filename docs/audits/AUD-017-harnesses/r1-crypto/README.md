# AUD-017 R1 harnesses: the length rule

- `length_rule_probe.py` checks the stated-length recovery of `scripts/independent-suite3.py` against an oracle written from the specification's rule ("Recovering a mnemonic", mhfe_spec README).
  - The script's functions are loaded by AST.
  - It covers 9 packed states (12, 15, 18, 21, zero-24, random, and the three ambiguous ones) with every stated length: 54 cases.
  - It compares the recorded `stated-24-words` case of `tests/fixtures/suite3-vectors/negative-cases.json`.
  - It recomputes the wallet-check fixtures (MHFE-WALLET-CHECK-SEED-1).
- Inputs: the repository's own files only. No Argon2 runs.
- Run it from the repository root:

  ```sh
  python3 docs/audits/AUD-017-harnesses/run.py r1-length-rule python3 docs/audits/AUD-017-harnesses/r1-crypto/length_rule_probe.py
  ```

- Expected: exit 0.
