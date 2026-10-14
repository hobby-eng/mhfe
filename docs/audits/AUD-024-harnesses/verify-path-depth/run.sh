#!/usr/bin/env bash
# Audit AUD-024, verifier of the path-depth finding: is a BIP32 path deeper than 255 refused by the
# library, the browser package and the command line? Exits 1 while any of them accepts one.
#
#   docs/audits/AUD-024-harnesses/verify-path-depth/run.sh [work dir]
#
# Run from the repository root. See README.md.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(pwd)"
work="${1:-${TMPDIR:-/tmp}/aud024-verify-path-depth}"
mkdir -p "$work/probe/src"
cat > "$work/probe/Cargo.toml" <<TOML
[package]
name = "aud024-verify-path-depth"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
mhfe-experimental = { path = "$root" }

[workspace]
TOML
cp "$here/probe/src/main.rs" "$work/probe/src/main.rs"
cp "$root/rust-toolchain.toml" "$work/probe/"
[ -f "$work/probe/Cargo.lock" ] || cp "$root/Cargo.lock" "$work/probe/Cargo.lock"
target="${CARGO_TARGET_DIR:-$work/target}"
(cd "$work/probe" && CARGO_TARGET_DIR="$target" cargo build --offline --release --quiet) || exit 2

status=0
echo "== library"
"$target/release/aud024-verify-path-depth" || status=1
echo "== browser package (dist/runtime/mhfe.wasm, target/wasm-bindgen/mhfe.js)"
node "$here/wasm_depth.mjs" "$root" || status=1
echo "== command line (target/release/mhfe; empty input ends it before any Argon2 round)"
p256="m$(printf '/0%.0s' $(seq 256))"
out="$(timeout 20 target/release/mhfe check --address --coin bitcoin --path "$p256" --stdin </dev/null 2>&1)"
if grep -q "invalid derivation path" <<<"$out"; then
  echo "PASS --path of depth 256 is refused"
else
  echo "FAIL --path of depth 256 is refused: $(grep -m1 Error <<<"$out")"
  status=1
fi
exit "$status"
