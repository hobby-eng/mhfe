# AUD-008 independent wallet challenge

This supplement challenges Dash Platform address parsing and BIP32 path/count boundaries in the
dirty source snapshot at `01978aa01f86cbec7dbc9fb9afd131dfa1a1d650`. The audit snapshot and
`wallet-independent-review.json` bind the reviewed source bytes; the commit alone does not.

`wallet-challenge-probe.rs` calls production public APIs. `wallet-challenge-run.py` independently
encodes synthetic 21-byte Dash payment payloads and checks residual padding. Inputs use no wallet
secrets, Argon2 work, derivation, blockchain provider or network calls.

From the `mhfe` checkout, first use the documented toolchain to build the production debug library
if it does not exist. The audit reused the coordinator's freshly built library and ran no Cargo
job. Set `AUDIT_RLIB` to the current production `target/debug/deps/libmhfe-*.rlib`, then run:

```sh
CARGO_HOME=/home/sergio/Documents/bip_tools/workingspace/cargo \
RUSTUP_HOME=/home/sergio/Documents/bip_tools/workingspace/rustup \
/home/sergio/Documents/bip_tools/workingspace/cargo/bin/rustc --edition=2021 \
  docs/audits/AUD-008-harnesses/wallet-challenge-probe.rs \
  --extern "mhfe=$AUDIT_RLIB" -L dependency=target/debug/deps \
  -o docs/audits/AUD-008-evidence/wallet-challenge-probe
python3 docs/audits/AUD-008-harnesses/wallet-challenge-run.py \
  docs/audits/AUD-008-evidence/wallet-challenge-probe \
  docs/audits/AUD-008-evidence/wallet-challenge-results.json
```

The driver runs 34 cases: 18 address cases and 16 path/count cases. In the reviewed snapshot it exits
1 and reports ten padding acceptance mismatches, five each for `dash` and `tdash`; all other cases
pass. After a fix, the expected result is no mismatches and exit 0. Parsed maximum counts are never
used to start an address search. The JSON, compiled probe, logs and command ledgers remain local in
the ignored evidence directory.
