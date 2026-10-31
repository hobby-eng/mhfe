#!/usr/bin/env bash
# Builds the browser versions of the vendored reference Argon2 code with Emscripten:
#
#   dist/argon2-mt.js  threaded; used only when the page is cross-origin isolated
#   dist/argon2-st.js  single-threaded; used everywhere else, including file:// pages
#
# Each output is one classic script with its WebAssembly embedded, so a page with a
# strict Content-Security-Policy can run it from a Blob Worker without fetching anything.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

expected_emscripten="6.0.12"
actual_emscripten="$(emcc --version | head -n 1 | sed -E 's/^.* ([0-9]+\.[0-9]+\.[0-9]+) .*$/\1/')"
if [[ "$actual_emscripten" != "$expected_emscripten" ]]; then
  echo "Expected Emscripten $expected_emscripten, found $actual_emscripten" >&2
  exit 1
fi

argon2="vendor/phc-winner-argon2"

# The files of every build and the portable core, from the list that build.rs reads too.
sources=()
while read -r part path; do
  case "$part" in
    common | portable) sources+=("$path") ;;
  esac
done < src/engine/argon2-sources.txt

common_flags=(
  -O3
  "-I$argon2/include"
  # One classic script that defines a factory function returning the module.
  -sMODULARIZE=1
  # Embed the WebAssembly as base64: nothing is fetched and the file stays plain ASCII.
  -sSINGLE_FILE=1
  -sSINGLE_FILE_BINARY_ENCODE=0
  # Runs in a Web Worker in the browser. No test runs it in Node.js any more; `node` goes at the
  # next change of the package, as it changes the package's bytes.
  -sENVIRONMENT=worker,node
  # The default memory level needs 2 GiB; WebAssembly can address at most 4 GiB.
  -sALLOW_MEMORY_GROWTH=1
  -sMAXIMUM_MEMORY=4GB
  # The JavaScript glue needs nothing else from the module.
  -sEXPORTED_FUNCTIONS=_argon2id_hash_raw,_malloc,_free
  -sEXPORTED_RUNTIME_METHODS=HEAPU8
  # No eval() or new Function(), which the strict CSP forbids, and no file system.
  -sDYNAMIC_EXECUTION=0
  -sFILESYSTEM=0
)

threaded_flags=(
  -pthread
  # One Worker per Argon2 lane, started before the first call. Argon2 creates and joins
  # its threads for every segment, so a thread must never wait for a new Worker.
  -sPTHREAD_POOL_SIZE=4
  # The worker passes this build's own source as a Blob for the lane Workers, because
  # the CSP allows Workers only from blob: URLs.
  -sINCOMING_MODULE_JS_API=mainScriptUrlOrBlob
  # The warning concerns JavaScript reads of a growing shared heap; the glue copies only
  # a few dozen bytes per call.
  -Wno-pthreads-mem-growth
  -sEXPORT_NAME=createArgon2Mt
)

single_threaded_flags=(
  -DARGON2_NO_THREADS
  -sINCOMING_MODULE_JS_API=[]
  -sEXPORT_NAME=createArgon2St
)

mkdir -p dist
emcc "${common_flags[@]}" "${threaded_flags[@]}" "${sources[@]}" -o dist/argon2-mt.js
emcc "${common_flags[@]}" "${single_threaded_flags[@]}" "${sources[@]}" -o dist/argon2-st.js
# Emscripten always emits loaders that fetch a WebAssembly file; scripts/build-wasm.sh replaces
# them by stubs, so that this output is the same here and in the reproducible build's own stage.
echo "Built dist/argon2-mt.js and dist/argon2-st.js with Emscripten $actual_emscripten"
