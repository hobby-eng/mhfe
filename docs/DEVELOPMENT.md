# Building and checking MHFE

The [README](../README.md) covers using the program. This guide covers source builds, checks and
generated data. See the [API reference](API.md) to use the Rust library and the
[browser guide](BROWSER-PACKAGE.md) to embed its modules.

## Build from source

Use the Rust version pinned in `rust-toolchain.toml`. Clone with `--recurse-submodules`, or run
`git submodule update --init` in an existing checkout. The `tests/spec` submodule supplies the
specification's published vectors used by the tests and startup self-test.

```bash
git clone --recurse-submodules https://github.com/hobby-eng/mhfe.git
cd mhfe
cargo build --release --locked
```

The program is written to `target/release/mhfe` (`mhfe.exe` on Windows). The release scripts
(`scripts/check.sh`, `scripts/build-wasm.sh`, `scripts/package-release.sh` and the reproducible
Dockerfile) remap the builder's paths in native and WebAssembly output using
`packaging/remap-builder-paths.sh`. They refuse `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS`; use
target-specific flags instead, such as `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS`.

The browser build uses Emscripten 6.0.12 and wasm-bindgen 0.2.129. See `scripts/build-wasm.sh` and
the [browser package layout](BROWSER-PACKAGE.md#modules).

## Checks

Run the smallest check that covers your change. Full-size cryptographic tests and canonical builds
are separate, expensive steps.

```bash
cargo test --locked                         # reduced-cost tests
cargo test --locked --package xtask         # the tools in xtask/
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --package xtask --all-targets -- -D warnings
cargo clippy --locked --lib --target wasm32-unknown-unknown --features wasm -- -D warnings
cargo fmt --all --check
dprint check                                # dprint 0.63.0, plugins pinned in dprint.json
cargo xtask copies
cargo xtask code-rules
cargo xtask terminal                        # the terminal cases, after cargo build --locked
```

A change to the browser package also needs `scripts/build-wasm.sh`, then `cargo xtask wasm verify
dist`; a change to the fast-mode launchers needs `cargo xtask fast-mode`.

For the release procedure, `scripts/check.sh` runs the lints, tests, builds and browser-package
checks, without the ignored full-size tests. Then run the browser cases with the pinned Chrome and
Firefox unpacked in `DIR` as `.github/actions/browser-checks` specifies. Browser versions are in
`xtask/src/browser.rs`.

```bash
scripts/check.sh
MHFE_BROWSERS=DIR cargo xtask package-check
MHFE_BROWSERS=DIR cargo xtask browsers
MHFE_BROWSERS=DIR cargo xtask parity
```

The parity task includes full-cost work. Run heavy checks sequentially, with enough memory for the
Argon2 level. The separate full-size library tests and canonical build are:

```bash
cargo test --locked --release --lib full_size -- --ignored
scripts/build-reproducible.sh
```

[Preparing a release](RELEASING.md) describes the additional uncached build, artifact comparison,
platform checks and signing. A local build alone does not establish reproducibility.

## Generated data

| Output                                         | Generator                      | Input                                                  |
| ---------------------------------------------- | ------------------------------ | ------------------------------------------------------ |
| `src/mhfe/published_rounds.rs`                 | `cargo xtask published-rounds` | Published vectors in `tests/spec/vectors/`             |
| `src/bin/mhfe/cell_widths.rs`                  | `cargo xtask cell-widths`      | Unicode 18.0.0 data in `tests/fixtures/unicode18-ucd/` |
| Rust-crate section of `THIRD_PARTY_NOTICES.md` | `cargo xtask licences`         | `Cargo.lock` and crate licences                        |

Each task accepts `--check` to compare without writing; `scripts/check.sh` runs those comparisons.
Regenerate the round table when vectors change, the cell table when the password rule's Unicode
version changes, and the licence list when dependencies change. The vectors and their independent
checkers are maintained in the [specification repository](https://github.com/hobby-eng/mhfe-spec).

## Engines and dependencies

[mhfe-core](https://github.com/hobby-eng/mhfe_core) owns the cipher, password rules, native Argon2
and secret-memory protections. `Cargo.toml` pins a Git revision until the next core release. Native
Argon2 uses RustCrypto's `argon2`; on x86-64 it selects AVX2 at runtime and also works where AVX2 is
unavailable, including virtual machines that hide it.

Browser Argon2 uses the unchanged [reference C source](../vendor/phc-winner-argon2.md), compiled to
WebAssembly. [Third-party notices](../THIRD_PARTY_NOTICES.md) gives the licences shipped in every
archive. [Security](../SECURITY.md) describes memory and platform limits; the
[measurement records](measurements/README.md) retain dated results, including earlier engines.
