# AUD-019 core probes

Time zone: UTC (+00:00)

Privacy-only documentation update: this is not a new audit. No checks were rerun; recorded results and evidence are unchanged.

These probes belong to MHFE AUD-019, reviewed commit
`66f142566464255e331763966b00ea1681c2dabd`. They use public or synthetic inputs only.
They do not construct an Argon2 engine or claim that the construction is secure.

`source_review.py` inventories Rust files, binds 25 core modules to their SHA-256 values,
compares the retained local AUD-018 manifest when present, independently checks three public
ambiguous states with Python SHA-256, checks specification tag/source protocol identity, and verifies
the four historical unavailable source fields have explicit annotations. The local AUD-018
manifest is optional; the annotation and verifier assertions are not.

```sh
python3 docs/audits/AUD-019-harnesses/run.py core-source-review python3 docs/audits/AUD-019-harnesses/core/source_review.py
```

`public_preflight.rs` checks early rekey confirmation requirements, normalized password
boundaries, hidden-wallet availability, detection of public ambiguous states, a published
BIP84 master fingerprint, passphrase normalization, and wrong-field error redaction.
The coordinator compiles it once after the scheduled checks have validated the current debug
library, using Rust 1.99.0 from the workspace toolchain. The recorded run linked the existing
Cargo-cached `libmhfe-c7deccbb61c23144.rlib`; it was not a fresh build from an empty cache.
Replace `HASH` with the current rlib filename; no Cargo project or additional checkout is created.

```sh
CARGO_HOME=/home/user/Documents/bip_tools/workingspace/cargo RUSTUP_HOME=/home/user/Documents/bip_tools/workingspace/rustup python3 docs/audits/AUD-019-harnesses/run.py core-preflight-compile /home/user/Documents/bip_tools/workingspace/cargo/bin/rustc --edition=2021 docs/audits/AUD-019-harnesses/core/public_preflight.rs --extern mhfe=target/debug/deps/libmhfe-HASH.rlib -L dependency=target/debug/deps -o docs/audits/AUD-019-evidence/core-public-preflight
python3 docs/audits/AUD-019-harnesses/run.py core-public-preflight docs/audits/AUD-019-evidence/core-public-preflight
```

The recorded source probe passed with 97 Rust files, 23 of 25 core module hashes unchanged
since the retained AUD-018 manifest, three independently checked ambiguous verifier states,
and four annotated unavailable historical source references. The first run's assertion that
the entire specification README equalled its tag failed on two archive metadata additions.
The corrected probe compares normative protocol text; both records remain in local evidence.
The public preflight exits zero with 128 assertions passed and makes no Argon2 call.

The unchanged AUD-015 document-binding harness was also run once:

```sh
python3 docs/audits/AUD-019-harnesses/run.py core-historical-harness-bindings python3 docs/audits/AUD-015-harnesses/r5-build-docs/harness_bindings.py
```

It checked 160 retained document-hash pairs with zero broken bindings. It skips absent named
files, so that result does not establish that every historical release asset is available.

Both core probes exit zero on success and print bounded assertion/identity results. The shared
runner retains command records and log hashes locally under `AUD-019-evidence`. Compilation
and execution are scheduled by the coordinator; do not overlap them with heavy checks.
Neither probe measures physical memory erasure or confirms external artifact provenance.
