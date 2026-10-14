#!/usr/bin/env bash
# AUD-024 guide-lib-core harness (reviewed commit b6fca69). Run from the repository root:
#   docs/audits/AUD-024-harnesses/guide-lib-core/run.sh <check>
# with <check> one of locked-text, cgroup-usage, strength-repeats (Rust probes built against this
# repository, offline, into CARGO_TARGET_DIR), unreachable-pub (cargo clippy into
# CARGO_TARGET_DIR), module-edges, module-cycles, unused-api, copies (static Python scans). Each exits 1 when its
# check fails and 0 when it passes. Writes nothing into the repository.
set -euo pipefail

check="${1:?usage: run.sh locked-text|cgroup-usage|strength-repeats|unreachable-pub|module-edges|module-cycles|unused-api|copies}"
repo="$(pwd)"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

probe() {
  : "${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR to a folder outside the repository}"
  local work
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' RETURN
  cp -r "$here/probe/src" "$here/probe/build.rs" "$work/"
  sed "s|@REPO@|$repo|" "$here/probe/Cargo.toml.in" > "$work/Cargo.toml"
  cp "$repo/Cargo.lock" "$work/Cargo.lock"
  cp "$repo/rust-toolchain.toml" "$work/rust-toolchain.toml"
  (cd "$work" && MHFE_ROOT="$repo" cargo build --offline --quiet --bin "$1")
  "$CARGO_TARGET_DIR/debug/$1"
}

case "$check" in
  locked-text) probe locked_text ;;
  cgroup-usage) probe cgroup_usage ;;
  strength-repeats) probe strength_repeats ;;
  unreachable-pub)
    : "${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR to a folder outside the repository}"
    log="$(mktemp)"
    trap 'rm -f "$log"' EXIT
    cargo clippy --locked --lib --quiet -- -W unreachable_pub 2> "$log" || true
    python3 "$here/unreachable_pub.py" "$log"
    ;;
  module-edges) python3 "$here/module_edges.py" ;;
  module-cycles) python3 "$here/module_cycles.py" ;;
  unused-api) python3 "$here/unused_api.py" ;;
  copies) python3 "$here/copies.py" ;;
  *) echo "unknown check: $check" >&2; exit 2 ;;
esac
