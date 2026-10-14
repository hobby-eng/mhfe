#!/usr/bin/env bash
# AUD-024 verify-decoy-fingerprint-collision: a two-word decoy search with a master key
# fingerprint that two candidates share. Builds and runs the library probe (probe/), then drives
# `mhfe decrypt` on a pseudo-terminal to the found container phrase (cli_found.py). Exits 1 when
# either shows the defect, 2 when the probe cannot be built. See README.md.
#   docs/audits/AUD-024-harnesses/verify-decoy-fingerprint-collision/run.sh [mhfe binary]
set -uo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
here="$root/docs/audits/AUD-024-harnesses/verify-decoy-fingerprint-collision"
binary="${1:-$root/target/release/mhfe}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/aud024-verify-decoy-target}"
(cd "$here/probe" && cargo build --offline --release --quiet) || exit 2
status=0
"$CARGO_TARGET_DIR/release/aud024-verify-decoy-collision" || status=1
(cd "$root" && PYTHONDONTWRITEBYTECODE=1 python3 "$here/cli_found.py" "$binary" decrypt --pim 0) \
  || status=1
exit "$status"
