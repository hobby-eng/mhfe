#!/usr/bin/env bash
# The full check of the repository, for release-level verification on request. It does not
# replay the full-size test vectors (tests/suite3_vectors.rs, about an hour, and
# tests/suite4_vectors.rs, about half an hour) or check them with the independent scripts;
# vectors.yml does that, in about three hours.
#
# Needs the pinned Rust toolchain, wasm-bindgen 0.2.129, Emscripten 6.0.12, Node.js with the tools
# of `npm ci --ignore-scripts`, Python 3, GNU tar and zip.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
# Every build below writes the builder's directories under the fixed names of
# packaging/remap-builder-paths.sh, as the canonical build does, since
# scripts/check-release-artifacts.sh refuses a release program or WebAssembly that names one. One
# set of flags for every step, so that no step rebuilds what another built.
. packaging/remap-builder-paths.sh
remap_builder_paths "$repo_root"

# The vendored Argon2 code must be byte for byte the recorded upstream files, with none added.
node scripts/verify-vendored-argon2.mjs --self-test
node scripts/verify-vendored-argon2.mjs

# The Rust crates part of THIRD_PARTY_NOTICES.md must match the crates every release target ships,
# and its standard library section the pinned toolchain.
# The generator reads their sources offline, so fetch the sources of every target first (a no-op
# when they are there).
cargo fetch --locked
python3 scripts/third-party-licenses.py --self-test
python3 scripts/third-party-licenses.py --check
# The table of published rounds that the self-checks replay must be what the fixtures give.
python3 scripts/generate-published-rounds.py --check

# Formatting, the copy gate, clippy for every build, the fast tests and Prettier.
scripts/check-fast.sh
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
cargo build --locked --release
# The terminal in a pseudo-terminal: hidden input (control characters refused, editing keys,
# Ctrl+C), the self-test report, a start that prints nothing, and damaged copies of the program
# that stop before any prompt, with the cases that run Argon2 at full size.
# The program the release build above made, wherever CARGO_TARGET_DIR puts it.
target_dir="$(cargo metadata --locked --no-deps --format-version 1 |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
python3 scripts/verify-hidden-input.py --full "$target_dir/release/mhfe"

scripts/build-wasm.sh
node scripts/verify-argon2-wasm.mjs
node scripts/verify-browser-package.mjs
# Each module built alone: its startup self-check passes, and it carries no other part's vectors.
node scripts/verify-single-modules.mjs
# The program and the package give the same results, as both call the same library.
node scripts/verify-cli-browser-parity.mjs "$target_dir/release/mhfe"
python3 scripts/verify-fast-mode-script.py
scripts/check-release-artifacts.sh
# A release archive's bytes depend on its content alone, not on the umask of the checkout.
scripts/verify-archive-packing.sh
echo "All checks passed."
