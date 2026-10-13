# AUD-020 harness

Time zone: UTC (+00:00)

Privacy-only documentation update: this is not a new audit. No checks were rerun; recorded results and evidence are unchanged.

Owner-authorized signed privacy amend (2026-10-13 UTC): original reviewed base `0155c951ab9deee0301b7e37b42ebc994cbd28b7` is retained under a local audit-snapshot ref and was replaced on main by `e8dca53a5d17cb80f1f5ac1f5a40b351f939e7e7`. The full trees differ in audit documentation and its publication emitter; product files outside `docs/audits/` are byte-for-byte unchanged between these commits. Original reviewed-commit fields, source inventories, fingerprints and raw evidence remain bound to the original bytes. This relationship does not extend the historical audit to the amended publication files; no audit checks were rerun.

This folder belongs to the Standard Codex Security review of MHFE source at commit
`0155c951ab9deee0301b7e37b42ebc994cbd28b7`. It uses only public fixtures and reduced-cost unit tests.
It does not run full-size vectors, release checks or builds that replace browser artifacts.

`record.py` reuses this repository's retained `AUD-016-harnesses/run.py` command runner with
AUD-020's root and evidence destination. It records exact arguments, selected toolchain environment,
UTC times, exit status, peak RSS and the output SHA-256. Logs and command records are in ignored
`AUD-020-evidence/`; the child's nonzero exit is propagated. The runner refuses to overwrite a
label, limits a child to 1,200 seconds and monitors a 3 GiB RSS budget. The original early FFI
record predates this wrapper and has its explicitly retained older envelope. Neither format
turns an unexecuted check into a passing one.

From the repository root, for example:

```sh
CARGO_HOME=/path/to/workspace/workingspace/cargo RUSTUP_HOME=/path/to/workspace/workingspace/rustup python3 -B docs/audits/AUD-020-harnesses/record.py ffi -- /path/to/workspace/workingspace/cargo/bin/cargo test --locked --offline --lib engine::ffi::tests -- --test-threads=2
```

Expected: the scoped tests pass and exit zero; a failed assertion or build returns nonzero. The
report records actual commands and the platform limits of any operating-system probes. Reused
historical checks and existing browser artifacts are identified separately from fresh execution.

`swap_probe.py` emits JSON containing a small Rust probe and the SHA-256 of the exact source
file and extracted production helper. Save its `code` in an audit-only temporary directory,
compile with the workspace Rust compiler, and pass a new synthetic directory to the executable.
It must print `missing_inventory=0 known_empty=0 visible_unknown_swap=1 unreadable_inventory=0`.
The device-resolution stubs supply only a positive unknown-area control; the inventory-error
branches are unchanged production text. This proves the lost error state, not real swap paging,
password recovery or Windows console behavior. The source and proof are also retained in the
Codex Security scan's `artifacts/validation/swap-inventory/` directory.

`build_report.py` reads the retained scan review artifacts and local command records, renders the
AUD-020 Markdown/JSON pair, anonymizes published paths and validates source, procedure, log and
review hashes. It needs Python with the already available `jsonschema` package, the companion
audit procedure under `../multi-chain-wallet-tools/docs/`, and the existing local evidence.
From this repository root:

```sh
python3 -B docs/audits/AUD-020-harnesses/build_report.py --review-dir /path/to/scan/artifacts --write
python3 -B docs/audits/AUD-020-harnesses/build_report.py --review-dir /path/to/scan/artifacts --validate
```

Expected: validation prints JSON metadata and exits zero; missing or mismatched evidence returns
nonzero. Keep its output as local `report-validation.json`, never as a tracked evidence file.
Format only the new report pair and this README with the repository's pinned Prettier before
the final validation. The generator does not run product code, modify original evidence or
claim that either reported vulnerability has been fixed.
