#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

expected_bindgen="wasm-bindgen 0.2.128"
actual_bindgen="$(wasm-bindgen --version)"
if [[ "$actual_bindgen" != "$expected_bindgen" ]]; then
  echo "Expected $expected_bindgen, found $actual_bindgen" >&2
  exit 1
fi

cargo rustc --locked --release --lib --target wasm32-unknown-unknown --features wasm \
  --crate-type cdylib
rm -rf dist/wasm
mkdir -p dist/wasm
wasm-bindgen \
  target/wasm32-unknown-unknown/release/mhfe.wasm \
  --target web \
  --out-dir dist/wasm \
  --out-name mhfe \
  --typescript
cp web/mhfe-worker.js web/client.js web/client.d.ts web/README.md dist/
if command -v node >/dev/null 2>&1; then
  node --check dist/client.js
  node --check dist/mhfe-worker.js
  node scripts/verify-wasm-api.mjs
fi
echo "Built standalone browser API in $repo_root/dist"
