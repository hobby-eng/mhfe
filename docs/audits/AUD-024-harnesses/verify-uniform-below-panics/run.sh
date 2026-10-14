#!/usr/bin/env bash
# AUD-024 verifier harness: public library calls of mhfe that panic on wrong input. Run from the
# repository root. Copies probe/ to a temporary folder, builds it against this repository (offline,
# with the repository's Cargo.lock and toolchain) into CARGO_TARGET_DIR, and runs it. Exits 1 when
# any call panicked instead of returning, 0 when every call returned.
set -euo pipefail

repo="$(pwd)"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR to a folder outside the repository}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp -r "$here/probe/src" "$work/src"
sed "s|@REPO@|$repo|" "$here/probe/Cargo.toml.in" > "$work/Cargo.toml"
cp "$repo/Cargo.lock" "$work/Cargo.lock"
cp "$repo/rust-toolchain.toml" "$work/rust-toolchain.toml"
cargo build --offline --quiet --manifest-path "$work/Cargo.toml"
"$CARGO_TARGET_DIR/debug/aud024-verify-uniform-below-panics"
