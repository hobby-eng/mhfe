#!/usr/bin/env bash
# Builds the browser package in dist/:
#
#   mhfe_core_bg.wasm        the Rust core: all MHFE logic except Argon2
#   mhfe-worker.js           its wasm-bindgen glue, web/argon2-engine.js and web/mhfe-worker.js
#   argon2-mt.js             threaded Argon2 build, for cross-origin isolated pages
#   argon2-st.js             single-threaded Argon2 build, for every other page
#   client.js, client.d.ts   the page-side client
#   mhfe-fast-mode.py        the fast-mode launcher for computers with Python but without mhfe
#   README.md                how to use the package, with the SHA-256 of every file
#
# Needs wasm-bindgen 0.2.129 and Emscripten 6.0.10 (see scripts/build-argon2-wasm.sh), unless
# PREBUILT_ARGON2_DIR names a folder with argon2-mt.js and argon2-st.js built by that script.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

expected_bindgen="wasm-bindgen 0.2.129"
actual_bindgen="$(wasm-bindgen --version)"
if [[ "$actual_bindgen" != "$expected_bindgen" ]]; then
  echo "Expected $expected_bindgen, found $actual_bindgen" >&2
  exit 1
fi

cargo rustc --locked --release --lib --target wasm32-unknown-unknown --features wasm \
  --crate-type cdylib

# "no-modules" makes the glue a classic script that defines the global `wasm_bindgen`, so that
# it can be joined with the Argon2 build and the worker into one Blob worker.
bindgen_dir="target/wasm-bindgen"
rm -rf "$bindgen_dir"
mkdir -p "$bindgen_dir"
wasm-bindgen target/wasm32-unknown-unknown/release/mhfe.wasm \
  --target no-modules \
  --no-typescript \
  --out-dir "$bindgen_dir" \
  --out-name mhfe_core
# The glue's asynchronous loader fetches the WebAssembly by URL; the worker uses initSync instead.
node scripts/remove-network-code.mjs glue "$bindgen_dir/mhfe_core.js"

rm -rf dist
mkdir -p dist
# The reproducible build compiles the Argon2 files in its own Emscripten stage and passes them in.
if [[ -n "${PREBUILT_ARGON2_DIR:-}" ]]; then
  cp "$PREBUILT_ARGON2_DIR/argon2-mt.js" "$PREBUILT_ARGON2_DIR/argon2-st.js" dist/
else
  scripts/build-argon2-wasm.sh
fi
cp "$bindgen_dir/mhfe_core_bg.wasm" dist/
cat "$bindgen_dir/mhfe_core.js" web/argon2-engine.js web/mhfe-worker.js > dist/mhfe-worker.js
cp web/client.js web/client.d.ts dist/
cp packaging/mhfe-fast-mode.py dist/
for script in dist/mhfe-worker.js dist/client.js dist/argon2-mt.js dist/argon2-st.js; do
  node --check "$script"
done
# A syntax check that, unlike py_compile, writes no bytecode into the package.
python3 -c 'import ast, sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' \
  dist/mhfe-fast-mode.py

package_files=(mhfe_core_bg.wasm mhfe-worker.js argon2-mt.js argon2-st.js client.js client.d.ts
  mhfe-fast-mode.py)
{
  cat web/README.md
  printf '\n## SHA-256 of this build\n\n```text\n'
  (cd dist && sha256sum "${package_files[@]}")
  printf '```\n'
} > dist/README.md

echo "Built the browser package in $repo_root/dist"
