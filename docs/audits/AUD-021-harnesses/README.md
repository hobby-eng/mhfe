# AUD-021 remediation harnesses

Time zone: UTC (+00:00)

Privacy-only documentation update: this is not a new audit. No checks were rerun; recorded results and evidence are unchanged.

Owner-authorized signed privacy amend (2026-10-13 UTC): original reviewed base `0155c951ab9deee0301b7e37b42ebc994cbd28b7` is retained under a local audit-snapshot ref and was replaced on main by `e8dca53a5d17cb80f1f5ac1f5a40b351f939e7e7`. The full trees differ in audit documentation and its publication emitter; product files outside `docs/audits/` are byte-for-byte unchanged between these commits. Original reviewed-commit fields, source inventories, fingerprints and raw evidence remain bound to the original bytes. This relationship does not extend the historical audit to the amended publication files; no audit checks were rerun.

These harnesses belong to the scoped follow-up for AUD-020-SEC001 and AUD-020-SEC002. The baseline HEAD is `0155c951ab9deee0301b7e37b42ebc994cbd28b7`; fixes and regression tests were verified in the uncommitted working tree. The report binds exact before/after source bytes. No signed fix or verification commit exists, and the historical AUD-020 report remains unchanged.

Run commands from the MHFE repository root. Use Python with the existing `jsonschema` package, pinned Rust 1.99.0 from the workspace toolchain, and Node 26.10.0 with local Prettier 3.9.9. The terminal harness requires a Unix PTY. No dependency installation or network access is performed by these harnesses.

## Files and inputs

- `record.py` delegates to the retained `AUD-016-harnesses/run.py` command runner. It captures exact argv, UTC times, exit code, selected environment, memory guard and log hash under the ignored, local-only `docs/audits/AUD-021-evidence/` directory. Give each run a new label to preserve earlier evidence. It returns the executed command's exit code.
- `terminal.py` reuses `scripts/verify-hidden-input.py`. Without `direct` it runs three adjacent terminal-control functions, covering hidden own-password entry, generated-password refusal/display and private reveals. With `direct` it uses the published `tests/fixtures/suite3-vectors/zero-24.json` phrase in the exact explicit encryption path for words, check-word and chars. Each case cancels before Argon2, checks private display and terminal restoration, and prints only its case result. It exits nonzero on any assertion failure.
- `build_report.py` imports unchanged JSON, hashing and privacy helpers from `AUD-020-harnesses/build_report.py`, using the existing Python `jsonschema` package. Inputs are the original AUD-020 Markdown/JSON pair, current shared procedure files in the sibling multi-chain-wallet-tools checkout, the initial/final local snapshots, and immutable command logs/records. It checks those bindings, writes only the AUD-021 report pair with `--write`, and validates schema, 32 dispositions, original finding IDs, paired records, resolved links, privacy and unstaged evidence. It runs pinned local Prettier for the new reports. It does not execute product code or modify raw evidence. Both modes print validation metadata and exit nonzero on a mismatch.

The initial `snapshot.json` records HEAD, pre-existing status and file hashes before adding regression tests. `remediation-snapshot.json` records final HEAD, UTC completion and the final hash map, excluding AUD-021 report/harness files to avoid circular bindings. The final map includes fixes, tests, release notes and the index. It also binds the original sealed scan and source-only post-patch review. The report's source fingerprints exclude all audit records and hash the path-sorted `file SHA-256 + two spaces + path + LF` manifests. Original failed regression logs were recorded after adding the tests and before implementing fixes; the initial snapshot does not purport to hash the later test additions.

All inputs are public or synthetic: the published zero-entropy phrase, fake procfs/sysfs swap metadata and a public display sentinel. The harness never requests a real mnemonic, password or private key. Published reports use `/home/user/...`; raw local evidence keeps its original bytes.

## Reproduce the scoped checks

Set the workspace toolchain for individual commands or in the shell running these commands:

```sh
export CARGO_HOME=/home/user/Documents/bip_tools/workingspace/cargo
export RUSTUP_HOME=/home/user/Documents/bip_tools/workingspace/rustup
export CARGO_BUILD_JOBS=2
```

Replace the anonymized home component in `/home/user/...` with the actual checkout location. From the repository root, a new post-fix run is:

```sh
python3 -B docs/audits/AUD-021-harnesses/record.py rerun-swap -- "$CARGO_HOME/bin/cargo" test --locked --offline --bin mhfe swap -- --test-threads=2
python3 -B docs/audits/AUD-021-harnesses/record.py rerun-settings -- "$CARGO_HOME/bin/cargo" test --locked --offline --bin mhfe settings::tests -- --test-threads=2
python3 -B docs/audits/AUD-021-harnesses/record.py rerun-terminal -- "$CARGO_HOME/bin/cargo" test --locked --offline --bin mhfe terminal::tests -- --test-threads=2
python3 -B docs/audits/AUD-021-harnesses/record.py rerun-display -- "$CARGO_HOME/bin/cargo" test --locked --offline --bin mhfe made_password::tests -- --test-threads=2
python3 -B docs/audits/AUD-021-harnesses/record.py rerun-classification -- "$CARGO_HOME/bin/cargo" test --locked --offline --bin mhfe -- a_plain_partition_is_unprotected dm_crypt_and_zram_are_protected lvm_without_encryption_is_unprotected a_file_whose_device_cannot_be_seen_is_unknown --test-threads=2
python3 -B docs/audits/AUD-021-harnesses/record.py rerun-build -- "$CARGO_HOME/bin/cargo" build --locked --offline --bin mhfe
python3 -B docs/audits/AUD-021-harnesses/record.py rerun-controls -- python3 -B docs/audits/AUD-021-harnesses/terminal.py target/debug/mhfe
python3 -B docs/audits/AUD-021-harnesses/record.py rerun-direct -- python3 -B docs/audits/AUD-021-harnesses/terminal.py target/debug/mhfe direct
```

Each post-fix command should exit zero. Rust display tests report one ignored isolated child; the parent regression executes that child explicitly, so it is not a skipped sink test or an additional suite count. Overlapping swap/settings tests are counted once by name. PTY case counts are separate from Rust tests. The original `before-swap` run has two failing assertions and exit 101; `before-display` has one failing assertion and exit 101. Those retained failures demonstrate that the regression checks could fail before remediation and are not rerun by reverting the checkout.

The report also records `cargo clippy --locked --offline --all-targets --all-features -- -D warnings`, `cargo fmt --check`, and a byte-identity comparison of 31 companion-specification JSON fixtures. That comparison checks unchanged fixture bytes; it does not replay full-cost vectors.

## Generate and validate the record

After supplying the retained local evidence and final snapshot:

```sh
python3 -B docs/audits/AUD-021-harnesses/build_report.py --write
python3 -B docs/audits/AUD-021-harnesses/build_report.py --validate
```

Expected output is a JSON validation summary with `schemaValid`, `pairAgreement`, `sourceAndLogHashesValid` and `pathsAnonymized` true, `coverageChecks: 32`, `newFindings: 0`, the two original finding IDs, and `signedCommitClosure: false`. The coordinator retains that output as local report-validation evidence and seals the evidence `SHA256SUMS` separately. Report-validation command logs are excluded from report inputs to avoid a self-referential hash.

Actual Windows VT API failure, Windows/macOS console behavior, forced paging, real browser suites, full-cost Argon2, canonical builds and release acceptance are outside this follow-up. Passing Unix and synthetic refusal checks do not claim those cases were executed.
