#!/usr/bin/env bash
# The AUD-024 core-crypto harness (audit AUD-024, commit b6fca69): the independent oracles of the
# cipher, its formats and profiles ("conformance", which passes at b6fca69) and the expected
# behaviour of the core-crypto findings ("findings", which fails at b6fca69 until they are fixed).
#
#   docs/audits/AUD-024-harnesses/core-crypto/run.sh conformance|findings
#
# Run from the repository root with the pinned Rust toolchain (CARGO_HOME and RUSTUP_HOME of the
# workspace AGENTS.md, offline registry), and the hash-pinned Python packages of
# scripts/independent-suite3-requirements.txt on PYTHONPATH. The probe crate is copied to a
# temporary folder and built there, with CARGO_TARGET_DIR if it is set, never in target/.
set -euo pipefail

mode="${1:-}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$repo_root"
here="docs/audits/AUD-024-harnesses/core-crypto"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

build_probe() {
  mkdir -p "$work/probe/src"
  cp "$here/probe/src/main.rs" "$work/probe/src/main.rs"
  sed "s#@REPO_ROOT@#$repo_root#" "$here/probe/Cargo.toml.in" > "$work/probe/Cargo.toml"
  cp Cargo.lock "$work/probe/Cargo.lock"
  export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$work/target}"
  (cd "$work/probe" && RUSTUP_TOOLCHAIN=1.99.0 cargo build --offline --release --quiet)
  probe="$CARGO_TARGET_DIR/release/aud024-core-crypto-probe"
}

case "$mode" in
  conformance)
    build_probe
    failed=0
    for oracle in argon2_tags.py profiles_oracle.py reduced_cost_oracle.py; do
      python3 "$here/oracles/$oracle" || failed=1
    done
    python3 "$here/oracles/bip39_reading_oracle.py" "$probe" || failed=1
    python3 "$here/oracles/repair_bound_oracle.py" "$probe" || failed=1
    rust="$("$probe" password-scan)"
    python="$(python3 "$here/oracles/password_scan.py")"
    echo "$rust"
    if [ "$rust" = "$python" ]; then
      echo "password rule: the Rust encoding equals the Unicode 17.0.0 oracle for every scalar value"
    else
      echo "password rule: DIFFERS from the oracle: $python"
      failed=1
    fi
    exit "$failed"
    ;;
  findings)
    build_probe
    failed=0
    "$probe" findings || failed=1
    # A doc comment of another item joined to an item's own (AUD-023-ARC003 pattern).
    if python3 "$here/oracles/doc_join_scan.py" src/feistel.rs src/bin/mhfe/style.rs \
      src/bin/mhfe/hidden_input.rs | grep -E "half \^= mask|without its colour codes|up to the first Quit"; then
      echo "FAIL doc-comments-describe-their-own-item"
      failed=1
    else
      echo "PASS doc-comments-describe-their-own-item"
    fi
    exit "$failed"
    ;;
  *)
    echo "usage: $here/run.sh conformance|findings" >&2
    exit 2
    ;;
esac
