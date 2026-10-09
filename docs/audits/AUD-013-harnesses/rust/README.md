# AUD-013 Rust audit probes

These probes belong to AUD-013 and review the dirty source snapshot identified in that report, whose base commit and source fingerprint are retained in local evidence. They do not run Argon2, derive keys, or search addresses. The address fixtures are public BIP44/BIP84 values already retained in `src/wallet.rs`.

`address-search-boundary.rs` calls the public search-description API with its documented maximum counts. It compares the reported number with an independently calculated `u128` value, retaining the largest one-root case and adjacent two-root cases as controls. It prints each expected and observed count and exits 1 if any count differs or construction panics; exit 0 means all counts matched. The maximum two-root count is 2^64, which cannot be represented by the current `u64` return type. Compiling this probe against a release library requires the library's `panic=abort` setting; its overflow checks are normally disabled, so the observed faulty count is zero. A debug library normally panics, which the probe catches.

`recovered-read-consume.rs` verifies that a native caller can read a recovered phrase and take ownership of its `LockedText` without accessing mutable fields. It compiles as a library and has no runtime entry point. Compile the original AUD-012 public mutation witness separately and expect a nonzero exit with private-field errors after remediation.

Use the workspace Rust homes and `target/release/libmhfe.rlib` freshly built from the reviewed snapshot. The coordinator's recorded `cargo build --locked --release -j 1` supplied the library for this execution. From the repository root:

```sh
export CARGO_HOME=/home/user/Documents/bip_tools/workingspace/cargo
export RUSTUP_HOME=/home/user/Documents/bip_tools/workingspace/rustup
rustc --edition=2021 -C panic=abort docs/audits/AUD-013-harnesses/rust/address-search-boundary.rs --extern mhfe=target/release/libmhfe.rlib -L dependency=target/release/deps -o docs/audits/AUD-013-evidence/address-search-boundary-release
docs/audits/AUD-013-evidence/address-search-boundary-release
rustc --edition=2021 --crate-type=lib -C panic=abort docs/audits/AUD-013-harnesses/rust/recovered-read-consume.rs --extern mhfe=target/release/libmhfe.rlib -L dependency=target/release/deps -o docs/audits/AUD-013-evidence/recovered-read-consume.rlib
rustc --edition=2021 --crate-type=lib -C panic=abort docs/audits/AUD-012-harnesses/rust/public-mutation.rs --extern mhfe=target/release/libmhfe.rlib -L dependency=target/release/deps -o docs/audits/AUD-013-evidence/public-mutation.rlib
```

The shared `record.mjs` wrapper retains the exact command, UTC timestamps, exit code, and SHA-256 of each log. In this sandbox the wrapper additionally recorded `spawnSync ... EPERM` while the commands completed and produced their expected output and artifacts; direct terminal reruns confirmed the same exit codes and outcomes. Those wrapper metadata warnings are retained in local evidence. Compiled artifacts and logs stay in the ignored evidence folder. Do not use artifact timestamps alone to establish source freshness. No debug overflow probe was executed.
