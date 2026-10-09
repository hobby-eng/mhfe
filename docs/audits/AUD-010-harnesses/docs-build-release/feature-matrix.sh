#!/usr/bin/env bash
# AUD-010 probe (docs-build-release): compiles (cargo clippy, no code generation) the library for
# WebAssembly with each browser feature alone and with all of them, and the native library and
# program without features, each with warnings as errors. It builds nothing for a release and runs
# nothing. Exits 1 if any combination fails; prints one line per combination.
#
#   docs/audits/AUD-010-harnesses/docs-build-release/feature-matrix.sh
#
# Needs the pinned toolchain with the wasm32-unknown-unknown target and the crates fetched
# (`cargo fetch --locked`); runs offline. CARGO_BUILD_JOBS (default 2) bounds the compiler's
# parallelism, so that the probe stays light beside other checks.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$repo_root"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"

failed=0
run() {
  local label="$1"
  shift
  if cargo clippy --locked --offline --quiet "$@" -- -D warnings; then
    echo "ok    $label"
  else
    echo "FAIL  $label"
    failed=1
  fi
}

wasm=(--lib --target wasm32-unknown-unknown --no-default-features)
run "wasm32, no features (library only)" "${wasm[@]}"
run "wasm32, wasm-bindings alone" "${wasm[@]}" --features wasm-bindings
for feature in browser-core browser-repair browser-passwords browser-wallet; do
  run "wasm32, $feature alone" "${wasm[@]}" --features "$feature"
done
run "wasm32, browser-core + browser-wallet" "${wasm[@]}" --features browser-core,browser-wallet
run "wasm32, wasm (all four)" "${wasm[@]}" --features wasm
run "native, default features, library and program" --bins --lib
run "native, every feature, all targets" --all-targets --all-features

if ((failed)); then
  echo "FAIL: at least one combination does not compile cleanly."
  exit 1
fi
echo "PASS: every combination compiles without warnings."
