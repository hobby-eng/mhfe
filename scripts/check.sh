#!/usr/bin/env bash
# The full check of the repository, for release-level verification on request. It does not
# replay the full-size test vectors (tests/suite3_vectors.rs, about an hour, and
# tests/suite4_vectors.rs, about half an hour) or check them with the independent scripts;
# vectors.yml does that, in about three hours.
#
# Needs the pinned Rust toolchain, wasm-bindgen 0.2.129, Emscripten 6.0.12, Node.js and Python 3.
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
# No code copied from one place to another in the library, the tool, the bindings or the page
# classes: each rule lives in one function that every front end calls (AGENTS.md).
node scripts/verify-no-copies.mjs --self-test
node scripts/verify-no-copies.mjs
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --lib --target wasm32-unknown-unknown --features wasm -- -D warnings
# Each browser module builds alone, so that another program can take one part without the rest.
for module in browser-core browser-repair browser-passwords browser-wallet; do
  cargo clippy --locked --lib --target wasm32-unknown-unknown --no-default-features \
    --features "$module" -- -D warnings
done
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
# The program and the package give the same results, as both call the same library.
node scripts/verify-cli-browser-parity.mjs "$target_dir/release/mhfe"
python3 scripts/verify-fast-mode-script.py
scripts/check-release-artifacts.sh
echo "All checks passed."
