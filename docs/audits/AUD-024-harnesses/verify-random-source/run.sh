#!/usr/bin/env bash
# AUD-024 verify-random-source harness (commit b6fca69): a random source that passes check_source
# and then misbehaves must end a draw with RANDOM_FAILED. Exits 1 while any expectation fails.
#
#   docs/audits/AUD-024-harnesses/verify-random-source/run.sh
#
# Run from the repository root with the pinned Rust toolchain (CARGO_HOME and RUSTUP_HOME of the
# workspace AGENTS.md, offline registry). The probe crate is copied to a temporary folder and built
# there, with CARGO_TARGET_DIR if it is set, never in target/.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$repo_root"
here="docs/audits/AUD-024-harnesses/verify-random-source"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/probe/src"
cp "$here/probe/src/main.rs" "$work/probe/src/main.rs"
sed "s#@REPO_ROOT@#$repo_root#" "$here/probe/Cargo.toml.in" > "$work/probe/Cargo.toml"
cp Cargo.lock "$work/probe/Cargo.lock"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$work/target}"
(cd "$work/probe" && RUSTUP_TOOLCHAIN=1.99.0 cargo build --offline --release --quiet)
"$CARGO_TARGET_DIR/release/aud024-verify-random-source"
