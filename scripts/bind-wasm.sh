#!/usr/bin/env bash
# Builds the library for the browser with the Cargo features given first and binds it with
# wasm-bindgen into the folder given second, as mhfe.js and mhfe_bg.wasm:
#
#   scripts/bind-wasm.sh wasm target/wasm-bindgen
#
# The one build of the browser package's WebAssembly (scripts/build-wasm.sh) and of each module
# built alone (scripts/verify-single-modules.mjs, browser-core and the others), so that a module
# is checked as the package's build makes it. Needs wasm-bindgen 0.2.129.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: scripts/bind-wasm.sh <cargo features> <output folder>" >&2
  exit 2
fi
features="$1"
out_dir="$2"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

expected_bindgen="wasm-bindgen 0.2.129"
actual_bindgen="$(wasm-bindgen --version)"
if [[ "$actual_bindgen" != "$expected_bindgen" ]]; then
  echo "Expected $expected_bindgen, found $actual_bindgen" >&2
  exit 1
fi

# Cargo's target folder, relative to the repository root as cargo reads it from here.
target_dir="${CARGO_TARGET_DIR:-target}"

# The folders of this machine that would be compiled into the WebAssembly, such as the panic
# locations of the dependencies under CARGO_HOME, are written under the fixed names of
# packaging/remap-builder-paths.sh, the one remapping of every build: cargo/registry/src/...
# instead of /home/<account>/.../registry/src/..., the same names as in the native programs and in
# the canonical build. A caller that already remapped, as scripts/check.sh and the Dockerfile do,
# gets nothing twice. It refuses RUSTFLAGS and CARGO_ENCODED_RUSTFLAGS, which would replace the
# remapping; extra flags go into CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS instead.
# scripts/verify-browser-package.mjs refuses a WebAssembly that names any other absolute source
# path.
. packaging/remap-builder-paths.sh
remap_builder_paths "$repo_root"

mkdir -p "$out_dir"
# "no-modules" makes the glue a classic script that defines the global `mhfe`, to be joined into
# the worker.
cargo rustc --locked --release --lib --target wasm32-unknown-unknown --no-default-features \
  --features "$features" --crate-type cdylib
wasm-bindgen "$target_dir/wasm32-unknown-unknown/release/mhfe.wasm" \
  --target no-modules \
  --no-modules-global mhfe \
  --no-typescript \
  --out-dir "$out_dir" \
  --out-name mhfe
# Where the shadow stack ends, for the worker to zero the dead stack between calls.
node scripts/mark-wasm-stack.mjs "$out_dir/mhfe_bg.wasm"
