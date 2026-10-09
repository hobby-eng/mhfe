#!/usr/bin/env bash
# Compile every declared browser module independently, never in parallel with another heavy check.
set -euo pipefail
workspace=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
export CARGO_HOME="$workspace/workingspace/cargo"
export RUSTUP_HOME="$workspace/workingspace/rustup"
cargo="$CARGO_HOME/bin/cargo"
for feature in browser-core browser-repair browser-passwords browser-wallet wasm; do
  printf 'Checking feature %s\n' "$feature"
  "$cargo" clippy --locked -j 2 --lib --target wasm32-unknown-unknown \
    --no-default-features --features "$feature" -- -D warnings
done
