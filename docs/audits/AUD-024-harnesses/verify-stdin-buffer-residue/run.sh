#!/usr/bin/env bash
# AUD-024 verify-stdin-buffer-residue: builds the probe (std only, no dependency) and runs run.py.
# Exits 1 when a whole copy of a piped or pasted line is left inside std's stdin buffer after the
# program wiped its own copy, 0 when none is, 2 when the probe could not be built or run.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/aud024-verify-stdin-target}"
cargo build --offline --release --quiet --manifest-path "$here/probe/Cargo.toml" || exit 2
python3 "$here/run.py" "$CARGO_TARGET_DIR/release/stdin-residue-verify"
