#!/usr/bin/env bash
# Builds the browser package in dist/: one WebAssembly with every module of the library and one
# worker script, shared by the module classes, and a folder per class, so that a page or another
# program takes only the classes it needs:
#
#   runtime/    what every class shares: runtime.js, runtime.d.ts (errors, workers, secrets),
#               mhfe.wasm (the library) and worker.js (the worker that runs it)
#   core/       MhfeClient: encryption, recovery, check, rekey, hidden wallets, self-test, with
#               Argon2: client.js, client.d.ts, argon2-mt.js, argon2-st.js, mhfe-fast-mode.py
#   repair/     MhfeRepair: repair words and container phrase repair: repair.js, repair.d.ts
#   passwords/  MhfePasswords: check word, strength, generator: passwords.js, passwords.d.ts
#   wallet/     MhfeWallet: wallet check, fingerprints, address searches, new phrases: wallet.js,
#               wallet.d.ts
#   modules.json  the version, the build, and the files of the runtime and of each class with their
#                 SHA-256
#   README.md     how to use the package, with the same SHA-256
#
# scripts/stamp-build-id.mjs derives one build identity from every file a page loads (mhfe.wasm,
# runtime.js, worker.js, each class and both Argon2 builds) before any is stamped, and stamps it
# into each of them. The classes, the runtime and the worker compare these stamps before they use
# the files together, so that files of two builds mixed by accident, even ones that differ in a
# script alone, are refused with PACKAGE_MISMATCH. Deliberate tampering is not caught this way;
# SHA256SUMS and its signature cover that.
#
# One WebAssembly rather than one per module: the modules share most of their code (the word list,
# Unicode tables, hashing, BIP39), so separate files were together more than twice the size of the
# one file, and a page that uses several classes would load and compile that shared code several
# times. worker.js is the wasm-bindgen glue, the Argon2 bridge, web/worker-runtime.js, each
# module's operations and web/worker-start.js, one script, as a worker under the tools' CSP may
# load no other. Needs wasm-bindgen 0.2.129 and Emscripten 6.0.12 (see
# scripts/build-argon2-wasm.sh), unless PREBUILT_ARGON2_DIR names a folder with argon2-mt.js and
# argon2-st.js built by that script.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

expected_bindgen="wasm-bindgen 0.2.129"
actual_bindgen="$(wasm-bindgen --version)"
if [[ "$actual_bindgen" != "$expected_bindgen" ]]; then
  echo "Expected $expected_bindgen, found $actual_bindgen" >&2
  exit 1
fi

bindgen_dir="target/wasm-bindgen"
rm -rf "$bindgen_dir"
mkdir -p "$bindgen_dir"
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

# "no-modules" makes the glue a classic script that defines the global `mhfe`, to be joined into
# the worker.
cargo rustc --locked --release --lib --target wasm32-unknown-unknown --no-default-features \
  --features wasm --crate-type cdylib
wasm-bindgen "$target_dir/wasm32-unknown-unknown/release/mhfe.wasm" \
  --target no-modules \
  --no-modules-global mhfe \
  --no-typescript \
  --out-dir "$bindgen_dir" \
  --out-name mhfe
# The glue's asynchronous loader fetches the WebAssembly by URL; the worker uses initSync instead.
node scripts/remove-network-code.mjs glue "$bindgen_dir/mhfe.js"

classes=(core repair passwords wallet)
rm -rf dist
mkdir -p dist/runtime "${classes[@]/#/dist/}"
# The reproducible build compiles the Argon2 files in its own Emscripten stage and passes them in.
if [[ -n "${PREBUILT_ARGON2_DIR:-}" ]]; then
  cp "$PREBUILT_ARGON2_DIR/argon2-mt.js" "$PREBUILT_ARGON2_DIR/argon2-st.js" dist/core/
else
  scripts/build-argon2-wasm.sh
  mv dist/argon2-mt.js dist/argon2-st.js dist/core/
fi
# Each Argon2 build ends with its build constant, which scripts/stamp-build-id.mjs stamps and
# web/core-worker.js compares with the worker's before the build runs. The names differ, as a
# self-check worker may have both builds in front of it.
printf '\nconst ARGON2_THREADED_BUILD_ID = "development";\n' >> dist/core/argon2-mt.js
printf '\nconst ARGON2_SINGLE_THREADED_BUILD_ID = "development";\n' >> dist/core/argon2-st.js

# wasm-bindgen names the WebAssembly mhfe_bg.wasm; nothing loads it by name, so it ships as
# mhfe.wasm.
cp web/runtime.js web/runtime.d.ts dist/runtime/
cp "$bindgen_dir/mhfe_bg.wasm" dist/runtime/mhfe.wasm
cat "$bindgen_dir/mhfe.js" web/argon2-engine.js web/worker-runtime.js web/core-worker.js \
  web/repair-worker.js web/passwords-worker.js web/wallet-worker.js web/worker-start.js \
  > dist/runtime/worker.js
cp web/client.js web/client.d.ts packaging/mhfe-fast-mode.py dist/core/
for class in repair passwords wallet; do
  cp "web/$class.js" "web/$class.d.ts" "dist/$class/"
done

node scripts/stamp-build-id.mjs dist
for script in dist/*/*.js; do
  node --check "$script"
done
# A syntax check that, unlike py_compile, writes no bytecode into the package.
python3 -c 'import ast, sys; ast.parse(open(sys.argv[1], encoding="utf-8").read())' \
  dist/core/mhfe-fast-mode.py

node scripts/write-package-manifest.mjs dist
echo "Built the browser package in $repo_root/dist"
