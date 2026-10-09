# AUD-016 core review harnesses

These audit-only probes cover missing-word search input handling, native cancellation, and three
published wallet addresses. They belong to AUD-016, reviewed HEAD
`3c60594479302827fe40975b04fd07f9f6fd4b3b` plus the current working tree with code fingerprint
`0c282ddd47edbe418644f19a5ae136fedd68fc13cb1e3b61972dc7f7e6d74f41`. The specification HEAD is
`2cd5e4c96a2bf2cc177f8b99b81fa7427bdf1b86`; its current working-tree bytes also matter.

Run commands from the mhfe repository root. Use only public inputs. These probes use the BIP39
zero-entropy phrases, published BIP49/BIP84/BIP86 addresses, and the public example
`1BoatSLRHtKNngkdXEeobR76b53LETtpyT`. No Argon2 operation is performed. The library must already
have been compiled from the reviewed source. The coordinator records which linked rlib was used.

Compile `public_probe.rs` with the workspace's Rust toolchain, choosing the current rlib explicitly:

```sh
env CARGO_HOME=/home/user/Documents/bip_tools/workingspace/cargo \
    RUSTUP_HOME=/home/user/Documents/bip_tools/workingspace/rustup \
    rustc --edition 2021 docs/audits/AUD-016-harnesses/core/public_probe.rs \
    --extern mhfe=target/debug/deps/libmhfe-REVIEWED_HASH.rlib \
    -L dependency=target/debug/deps -o target/aud016-core-public-probe
python3 docs/audits/AUD-016-harnesses/run.py core-search-inputs \
    target/aud016-core-public-probe search-inputs
python3 docs/audits/AUD-016-harnesses/run.py core-wallet \
    target/aud016-core-public-probe wallet
python3 docs/audits/AUD-016-harnesses/run.py core-cancel \
    python3 docs/audits/AUD-016-harnesses/core/cancel_watchdog.py \
    target/aud016-core-public-probe
```

Replace `/home/user` with the local workspace owner in executable commands. Replace
`REVIEWED_HASH` with the selected library filename. A fresh build must precede these commands;
merely linking an older rlib does not establish current-source behavior.

- `search-inputs` compares 90 inputs containing one unknown word with the same input marked `?`.
  It exits 1 if an unknown-only input is rejected. This tests the module-level description that an
  unknown word marks a missing word; the external API document instead requires a literal `?`.
  A failure therefore establishes that documentation disagreement, not a cryptographic defect.
- `wallet` checks three exact published addresses at the first receiving index, and refuses a
  corrupted address. It prints a pass and exits 0 when all four controls pass.
- `cancel_watchdog.py` uses Linux CPU affinity to run one native worker. It allows 45 seconds for
  enumerating the two missing words, then requires the search to return within two seconds of its
  progress callback returning `MhfeError::Cancelled`. It kills the child at that deadline, prints a
  failure, and exits 1 if the native worker has not returned. Setup that exceeds the earlier bound
  is reported separately as blocked, exit 2. It does not run the enormous address search to
  completion or leave a worker behind.

The review also reuses the independent AUD-015 oracle instead of copying it. Its vector command
replays recorded keys and checks the Feistel transcripts in both directions; its profiles command
recomputes the published repair cards, source-check digests and password check-word vectors:

```sh
python3 docs/audits/AUD-016-harnesses/run.py core-transcripts \
    python3 docs/audits/AUD-015-harnesses/r1-crypto/oracle.py vectors ../mhfe_spec/vectors
python3 docs/audits/AUD-016-harnesses/run.py core-profiles \
    python3 docs/audits/AUD-015-harnesses/r1-crypto/oracle.py profiles ../mhfe_spec
```

The oracle needs Python 3 and the installed `@scure/bip39` English wordlist in the sibling
multi-chain-wallet-tools checkout; it verifies the wordlist's published SHA-256. Successful replay
prints three deliberately failed negative controls, then `PASS vectors`. Profile success prints
`PASS profiles`. Neither command computes a full-cost Argon2 key, so neither replaces the deferred
full-size vector replay. Each evidence label is write-once; use a new label for a rerun.

`address_table.mjs` reuses the independent address oracle from AUD-015 while parsing the table
moved to `src/wallet/known_answers.rs` in the current tree. It verifies that every declared row was
read, preserves the oracle's literal published known answers and independent arithmetic, and
recomputes all 43 table entries. It requires Node 26.10.0 and the installed `@scure` and `@noble`
packages in the sibling multi-chain-wallet-tools checkout. It writes no prior evidence or product
file. A success prints `PASS independent address table: 43 current rows` and exits 0.

```sh
python3 docs/audits/AUD-016-harnesses/run.py core-address-table-r2 \
    node docs/audits/AUD-016-harnesses/core/address_table.mjs
```

The first run, evidence label `core-address-table`, retained a harness failure: the old oracle
looked for its table in `src/wallet.rs`. The `core-address-table-r2` run fixes only that input
adapter and passes. It does not suppress a product failure or alter expected address values.
