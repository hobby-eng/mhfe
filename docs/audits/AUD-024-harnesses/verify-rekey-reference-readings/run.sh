#!/usr/bin/env bash
# AUD-024 harness (verify-rekey-reference-readings): checks that a rekey compares a wallet
# reference with every reading, as the rehearsal check does and as docs/API.md,
# docs/BROWSER-PACKAGE.md and RecoveredForRekey::confirm's rustdoc say. It exports the crate at a
# commit (default b6fca69) into a scratch folder with git archive, adds one reduced-cost unit test
# (probe.patch, test-only Argon2 engine at 256 KiB and one pass), runs it and exits 1 when a
# reference that the rehearsal check matches is refused by the rekey. No tracked file is changed.
#
#   docs/audits/AUD-024-harnesses/verify-rekey-reference-readings/run.sh [commit]
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(git -C "$here" rev-parse --show-toplevel)"
workspace="$(cd "$root/.." && pwd)"
commit="${1:-b6fca69238344dd2525b06270ee6ff3b055e68c1}"
scratch="${AUD024_SCRATCH:-$workspace/tmp/aud024/verify-rekey-reference-readings/harness-crate}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$workspace/tmp/aud024/target}"
if [ -d "$workspace/workingspace/cargo/bin" ]; then
    export CARGO_HOME="${CARGO_HOME:-$workspace/workingspace/cargo}"
    export RUSTUP_HOME="${RUSTUP_HOME:-$workspace/workingspace/rustup}"
    export PATH="$CARGO_HOME/bin:$PATH"
fi

rm -rf "$scratch"
mkdir -p "$scratch"
git -C "$root" archive "$commit" | tar -x -C "$scratch"
patch -s -d "$scratch" -p1 < "$here/probe.patch"

output="$(cd "$scratch" && cargo test --locked --offline --lib \
    aud024_verify_rekey_reference_readings -- --nocapture 2>&1)" || {
    printf '%s\n' "$output" | tail -40
    echo "FAIL: the probe test did not run"
    exit 1
}
printf '%s\n' "$output" | grep -E '^AUD024'

failed=0
expect() {
    if printf '%s\n' "$output" | grep -qF -- "$1"; then
        echo "PASS: $1"
    else
        echo "FAIL: expected: $1"
        failed=1
    fi
}
# The rehearsal check matches the original's own fingerprint in both cases.
expect "AUD024 A: rehearsal check (Mhfe::check) with the original's fingerprint: Matches"
expect "AUD024 B: rehearsal check with the original's fingerprint: Matches"
# A rekey given the same fingerprint must confirm the same phrase: the 24-word original (case A)
# with the length detected, and the 12-word original (case B) after AMBIGUOUS_LENGTH at a stated
# 21, where the documents say the fingerprint compares every reading.
expect "AUD024 A: rekey confirm, length Detect, original's fingerprint: Ok(words 24"
expect "AUD024 A: Rekey::new(Detect).recover with the original's fingerprint: Ok(24)"
expect "AUD024 B: rekey confirm, length 21 stated, original's fingerprint: Ok(words 12"
exit "$failed"
