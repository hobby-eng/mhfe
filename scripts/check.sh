#!/usr/bin/env bash
# The full check of the repository, for release-level verification on request. It does not
# replay the full-size test vectors (tests/suite3_vectors.rs), which take about an hour.
#
# Needs the pinned Rust toolchain, wasm-bindgen 0.2.128, Emscripten 6.0.10, Node.js and Python 3.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# The vendored Argon2 code must be byte for byte the recorded upstream files.
sed -n '/^```text$/,/^```$/p' vendor/phc-winner-argon2.md | grep -v '^```' |
  (cd vendor/phc-winner-argon2 && sha256sum --check --quiet)

cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --lib --target wasm32-unknown-unknown --features wasm -- -D warnings
cargo test --locked
# The opt-in SSSE3 build must give byte for byte the same Argon2 results: its tests check the
# same expected tags and containers.
if [[ "$(uname -m)" == "x86_64" ]]; then
  cargo test --locked --features ssse3 --target-dir target/ssse3
fi
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
cargo build --locked --release
cargo build --locked --release --features ssse3 --target-dir target/ssse3
# Hidden terminal input in a pseudo-terminal: control characters refused, editing keys, Ctrl+C.
python3 scripts/verify-hidden-input.py target/release/mhfe

scripts/build-wasm.sh
node scripts/verify-argon2-wasm.mjs
node scripts/verify-browser-package.mjs
python3 scripts/verify-fast-mode-script.py
scripts/check-release-artifacts.sh
echo "All checks passed."
