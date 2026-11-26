# Test coverage

The Linux x86-64 run on 2026-11-26 covered **75.27%** of the measured source lines (15,364 of
20,412): **95.80%** of the library (10,761 of 11,233) and **50.15%** of the command-line tool's own
code (4,603 of 9,179). The tool's prompts, menus and hidden input are checked from outside by the
terminal suite in a pseudo-terminal, which this measurement does not count.

## Measurement

Rust 1.99.1 and cargo-llvm-cov 0.9.1 measured commit `14f4dda`
(`14f4dda099988078bcb766be57a8381f0cd3c2db`), before the release of 0.8.0. The commit that adds this
report changes only documentation and audit records, so the measured code is unchanged.

The suites were those of `cargo test -p mhfe-experimental`: 264 tests of the library, 129 of the
tool (one more fails only under coverage, below), 3 validation cases and 4 doctests. The full-cost
vectors and the terminal suite were left out.

## Scope and exclusions

The percentage counts the source lines of `src/`, the library and the tool, compiled for Linux
x86-64. The test files of `tests/`, `xtask`, the fuzz targets and the dependencies, mhfe-core among
them, are outside the denominator; mhfe-core records its own coverage. The browser package's
WebAssembly and the code of other systems are not measured.

Under coverage the isolated-command test of `src/bin/mhfe/protect.rs` fails: the profile runtime
keeps its file mapped as shared memory the process can write, which secret-protection-core's census
of open channels counts, as it should. Its counters are recorded all the same.

## Reproduce on Linux

From the repository root, in bash, with the pinned toolchain:

```sh
mkdir -p target
export CARGO_TARGET_DIR="$(mktemp -d "$PWD/target/coverage.XXXXXXXX")"
export CARGO_LLVM_COV_TARGET_DIR="$CARGO_TARGET_DIR"
source <(cargo llvm-cov show-env --sh)
export RUSTFLAGS="-C llvm-args=-runtime-counter-relocation"
export LLVM_PROFILE_FILE="$CARGO_TARGET_DIR/mhfe-%p%c.profraw"
cargo test --locked --offline -p mhfe-experimental --no-fail-fast
cargo llvm-cov report --summary-only \
  --ignore-filename-regex '(/tests/|/xtask/|/fuzz/|cargo/registry|/git/checkouts/)'
```

`%p` gives each process its own profile, and `%c` lets a child process record its counters after
isolation has taken away its right to open files.
