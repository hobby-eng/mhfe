#!/usr/bin/env bash
# AUD-024 (commit b6fca69): how many places the compiler makes a new coin touch.
# Run from the repository root. Extracts the tracked tree at REVISION (default HEAD) into a scratch
# folder, adds one variant `Probe` to `enum Coin` in src/wallet.rs and nothing else, runs
# `cargo check --locked --lib` and counts the non-exhaustive-match errors (E0004) it gives.
# Exits 1 when more than one place must grow a case for the new coin (CORE-06, CORE-11), 0 when
# one place does, 2 on a setup failure. Also prints, for information, the coin-specific sites
# that compile unchanged with the new variant (which the compiler does not point at).
set -uo pipefail
revision="${1:-HEAD}"
scratch="${AUD024_SCRATCH:-../tmp/aud024/verify-coin-rules}"
work="$scratch/harness-crate"
target="$(realpath -m "${CARGO_TARGET_DIR:-../tmp/aud024/target}")"
rm -rf "$work" && mkdir -p "$work" || exit 2
git archive "$revision" | tar -x -C "$work" || exit 2
python3 - "$work/src/wallet.rs" <<'PY' || exit 2
import re, sys
path = sys.argv[1]
text = open(path).read()
match = re.search(r"pub enum Coin \{.*?\n\}", text, re.S)
if not match:
    sys.exit("no `pub enum Coin { ... }` in src/wallet.rs")
body = match.group(0)
text = text.replace(body, body[:-1] + "    /// A probe coin added by the AUD-024 harness.\n    Probe,\n}", 1)
open(path, "w").write(text)
PY
output="$(cd "$work" && CARGO_TARGET_DIR="$target" cargo check --locked --lib --message-format short 2>&1)"
sites="$(printf '%s\n' "$output" | grep -E '^src/.*error\[E0004\].*Coin::Probe' | cut -d: -f1,2 | sort -u)"
count="$(printf '%s' "$sites" | grep -c . || true)"
echo "== places the compiler makes the new coin grow a case ($count) =="
printf '%s\n' "$sites"
echo "== coin-specific sites that compile unchanged with the new variant (information) =="
grep -n "pub const ALL: \[Self; [0-9]*\]" src/wallet.rs
grep -n "match self.coin" src/wallet.rs
grep -n "Coin::[A-Za-z]* if \|_ => parse_base58" src/wallet/encodings.rs
grep -n '(Coin::[A-Za-z]*, "[a-z]*")\|, Coin::Bitcoin) =>\|Coin::Xrp => bs58' src/wallet/encodings.rs
if [ "$count" -eq 0 ]; then
    echo "SETUP: cargo check gave no E0004 error for Coin::Probe; output follows"
    printf '%s\n' "$output" | tail -20
    exit 2
elif [ "$count" -gt 1 ]; then
    echo "FAIL: a new coin must grow a case in $count places"
    exit 1
fi
echo "PASS: a new coin grows a case in one place"
