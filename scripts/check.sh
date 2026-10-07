#!/usr/bin/env bash
# The full check of the repository, for release-level verification on request. It does not
# replay the full-size test vectors (tests/suite3_vectors.rs), which take about an hour.
#
# Needs the pinned Rust toolchain, wasm-bindgen 0.2.129, Emscripten 6.0.10, Node.js and Python 3.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
# Every build below writes the builder's directories under the fixed names of
# packaging/remap-builder-paths.sh, as the canonical build does, since
# scripts/check-release-artifacts.sh refuses a release program or WebAssembly that names one. One
# set of flags for every step, so that no step rebuilds what another built.
. packaging/remap-builder-paths.sh
remap_builder_paths "$repo_root"

# The vendored Argon2 code must be byte for byte the recorded upstream files.
sed -n '/^```text$/,/^```$/p' vendor/phc-winner-argon2.md | grep -v '^```' |
  (cd vendor/phc-winner-argon2 && sha256sum --check --quiet)

# The Rust crates part of THIRD_PARTY_NOTICES.md must match the crates every release target ships.
# The generator reads their sources offline, so fetch the sources of every target first (a no-op
# when they are there).
cargo fetch --locked
python3 scripts/third-party-licenses.py --check
# The table of published rounds that the self-checks replay must be what the fixtures give.
python3 scripts/generate-published-rounds.py --check

cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --lib --target wasm32-unknown-unknown --features wasm -- -D warnings
# On x86-64 the tests run both the SSE2 and the SSSE3 copy of the Argon2 core.
cargo test --locked
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
cargo build --locked --release
# The terminal in a pseudo-terminal: hidden input (control characters refused, editing keys,
# Ctrl+C), the self-test report, a start that prints nothing, and damaged copies of the program
# that stop before any prompt.
# The program the release build above made, wherever CARGO_TARGET_DIR puts it.
target_dir="$(cargo metadata --locked --no-deps --format-version 1 |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
python3 scripts/verify-hidden-input.py "$target_dir/release/mhfe"

scripts/build-wasm.sh
node scripts/verify-argon2-wasm.mjs
node scripts/verify-browser-package.mjs
python3 scripts/verify-fast-mode-script.py
scripts/check-release-artifacts.sh
echo "All checks passed."
