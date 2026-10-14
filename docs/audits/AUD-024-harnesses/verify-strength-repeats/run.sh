#!/usr/bin/env bash
# AUD-024 verifier harness: builds probe/ against the repository in the current directory (offline,
# into CARGO_TARGET_DIR, outside the repository) and runs it. Exits 1 when a password that repeats
# one short group that is not a list word is rated 50 bits or more (not weak). Writes nothing into
# the repository.
set -euo pipefail
: "${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR to a folder outside the repository}"
repo="$(pwd)"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/src"
cp "$here/probe/src/main.rs" "$work/src/main.rs"
sed "s|@REPO@|$repo|" "$here/probe/Cargo.toml.in" > "$work/Cargo.toml"
cp "$repo/Cargo.lock" "$repo/rust-toolchain.toml" "$work/"
(cd "$work" && cargo build --offline --quiet)
"$CARGO_TARGET_DIR/debug/aud024-verify-strength-repeats"
