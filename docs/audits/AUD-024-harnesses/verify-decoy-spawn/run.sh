#!/usr/bin/env bash
# AUD-024 verify-decoy-spawn: the missing-word search with the container's own wallet when the
# system refuses a new thread (src/search.rs compare_candidates). Exits 1 while the defect is
# present, 0 once the search goes on with the threads it got. See README.md.
set -uo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
here="$root/docs/audits/AUD-024-harnesses/verify-decoy-spawn"
target="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/aud024-verify-decoy-spawn-target}"
status=0
(cd "$here/probe" && CARGO_TARGET_DIR="$target" cargo build --offline --release --quiet) || exit 2
(cd "$root" && CARGO_TARGET_DIR="$target" cargo build --locked --release --quiet --bin mhfe) || exit 2
probe="$target/release/aud024-verify-decoy-spawn"
mhfe="$target/release/mhfe"
scope=(systemd-run --user --scope --quiet)

out="$("${scope[@]}" -p TasksMax=4 "$probe" 2>&1)"; code=$?
echo "$out"
if [ $code -eq 0 ] && grep -q 'decoy search: Ok(Some(\[(24, "art")\]))' <<<"$out"; then
  echo "PASS library: the decoy search finds the word with 3 threads allowed"
else
  echo "FAIL library: the decoy search ended with exit $code when a thread was refused"; status=1
fi
out="$("${scope[@]}" -p TasksMax=4 "$probe" draw 2>&1)"; code=$?
echo "$out"
[ $code -eq 0 ] && echo "PASS contrast: the wallet-check draw goes on with the threads it got" \
  || { echo "FAIL contrast: the draw ended with exit $code"; status=1; }

out="$("${scope[@]}" -p TasksMax=8 "$mhfe" check --fingerprint --pim 0 </dev/null 2>&1)"; code=$?
echo "$out"
if grep -q 'Self-test at start failed' <<<"$out"; then
  echo "FAIL CLI start: a thread limit is reported as a failed self-test (exit $code)"; status=1
else
  echo "PASS CLI start: no self-test failure under TasksMax=8 (exit $code)"
fi

out="$(cd "$root" && PYTHONDONTWRITEBYTECODE=1 python3 "$here/cli_decoy.py" "$mhfe" 9 2>&1)"; code=$?
echo "$out"
if [ $code -eq 0 ] && grep -q 'Found word 24: peace' <<<"$out"; then
  echo "PASS CLI search: the decoy search finds word 24 under TasksMax=9"
else
  echo "FAIL CLI search: the decoy search did not finish under TasksMax=9"; status=1
fi
exit $status
