#!/usr/bin/env bash
# AUD-024, role gap-1-browser-argon2-heap-residue, commit b6fca69: checks that no Argon2 call leaves
# bytes from which its output (a round key) can be rebuilt, in the browser package's Emscripten
# Argon2 builds and in the native engine. Reduced cost and public data only. Exits 1 when any check
# finds such bytes (the state at b6fca69), 0 when none does, 2 on a usage or build error.
#
#   docs/audits/AUD-024-harnesses/gap-1-browser-argon2-heap-residue/run.sh <libargon2.a> [--browsers]
#
# <libargon2.a> is the static library `cargo build --release` writes under
# $CARGO_TARGET_DIR/release/build/mhfe-experimental-*/out/. --browsers also runs the check in
# Playwright's Chromium and Firefox. Run from the repository root, after the browser package was
# built (dist/ and target/wasm-bindgen/mhfe.js).
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(pwd)"
library="${1:-}"
if [[ -z "$library" || ! -f "$library" || ! -f "$root/dist/core/argon2-mt.js" ]]; then
  echo "usage: $0 <libargon2.a> [--browsers], from the repository root after the package build" >&2
  exit 2
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
argon2="$root/vendor/phc-winner-argon2"
gcc -O2 -DARGON2_NO_THREADS -I "$argon2/include" -I "$argon2/src" "$here/blocks.c" \
  "$argon2/src/argon2.c" "$argon2/src/core.c" "$argon2/src/encoding.c" "$argon2/src/ref.c" \
  "$argon2/src/blake2/blake2b.c" -o "$work/blocks" 2>/dev/null || exit 2
gcc -O2 -Wno-format-truncation -I "$argon2/include" -I "$argon2/src" "$here/lane-stacks.c" \
  "$library" -lpthread -o "$work/lane-stacks" || exit 2
export MHFE_BLOCKS="$work/blocks"

failed=0
step() {
  echo "== $*"
  "$@"
  local code=$?
  echo "== exit $code"
  if [[ $code -ne 0 ]]; then failed=1; fi
}
step "$work/lane-stacks" 32768 1
step node "$here/residue-node.mjs" "$root" bridge 32768
step node "$here/residue-node.mjs" "$root" operations 32768
if [[ "${2:-}" == "--browsers" ]]; then
  step node "$here/residue-browser.mjs" "$root" 32768
fi
exit "$failed"
