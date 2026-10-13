# AUD-022 bounded verification harness

Time zone: UTC (+00:00)

Privacy-only documentation update: this is not a new audit. No checks were rerun; recorded results and evidence are unchanged.

Owner-authorized signed privacy amend (2026-10-13 UTC): original reviewed base `0155c951ab9deee0301b7e37b42ebc994cbd28b7` is retained under a local audit-snapshot ref and was replaced on main by `e8dca53a5d17cb80f1f5ac1f5a40b351f939e7e7`. The full trees differ in audit documentation and its publication emitter; product files outside `docs/audits/` are byte-for-byte unchanged between these commits. Original reviewed-commit fields, source inventories, fingerprints and raw evidence remain bound to the original bytes. This relationship does not extend the historical audit to the amended publication files; no audit checks were rerun.

Checks native library/CLI public-data tests, all-feature WASM compilation and launcher routing/checksums. Reviewed HEAD: `0155c951ab9deee0301b7e37b42ebc994cbd28b7`, with the report-described pre-existing dirty changes.

Run from the repository root, with workspace toolchains and public fixtures already present:

```bash
CARGO_HOME=/home/user/Documents/bip_tools/workingspace/cargo RUSTUP_HOME=/home/user/Documents/bip_tools/workingspace/rustup CARGO_TARGET_DIR=/tmp/mhfe-aud022-target python3 docs/audits/AUD-022-harnesses/verify.py
```

Replace the anonymized home path with the local workspace path. Requires Rust 1.99.0, wasm32-unknown-unknown, Python 3, a compiler and permitted loopback sockets. No external network, real secrets, full-size ignored tests, vector replay or release build. Expected exit 0 with test/compiler success. A failed command exits nonzero. A socket-restricted sandbox reproduces the initial three recorded CLI failures. The harness reruns existing checks rather than providing an independent cryptographic oracle.

The original terminal script was stopped during the expensive two-missing-word debug search; the earlier security cases and separately executed tail functions are recorded as subsets, not a complete passing suite. To reproduce the full script deliberately: `python3 scripts/verify-hidden-input.py /tmp/mhfe-aud022-target/debug/mhfe`. The full script can take many minutes in a debug build.

Rerun exactly the separately executed terminal tail: `python3 docs/audits/AUD-022-harnesses/terminal_tail.py /tmp/mhfe-aud022-target/debug/mhfe`. Requires pseudo-terminals; uses only public fixtures and synthetic passwords. Expected exit 0 with the selected-checks-passed line; assertions fail nonzero.
