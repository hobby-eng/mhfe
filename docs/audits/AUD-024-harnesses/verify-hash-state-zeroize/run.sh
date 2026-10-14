#!/usr/bin/env bash
# AUD-024 verify-hash-state-zeroize: do the hash and MAC states that mhfe feeds with secrets wipe
# themselves on drop? Exits 1 when a check finds the defect, 2 when a check could not run, 0 when
# both pass. Pass --features wipe to run the probes with the fix the finding recommends (the
# control). See README.md.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/aud024-hash-state-target}"
features=()
if [[ "${1:-}" == "--features" && -n "${2:-}" ]]; then
  features=(--features "$2")
elif [[ $# -gt 0 ]]; then
  echo "usage: run.sh [--features wipe]" >&2
  exit 2
fi
worst=0
for probe in drop-probe residue-probe; do
  echo "=== $probe ${features[*]:-(features as mhfe pins them)}"
  (cd "$here/$probe" && cargo build --offline --release --quiet "${features[@]}") || exit 2
  (cd "$here/$probe" && cargo run --offline --release --quiet "${features[@]}")
  code=$?
  if [[ $code -gt 1 ]]; then exit 2; fi
  if [[ $code -gt $worst ]]; then worst=$code; fi
done
echo "run.sh: exit $worst"
exit "$worst"
