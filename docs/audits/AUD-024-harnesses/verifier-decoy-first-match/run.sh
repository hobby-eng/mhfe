#!/usr/bin/env bash
# AUD-024 verifier-decoy-first-match: the two-word decoy search with a master key fingerprint
# returns the first matching candidate. See README.md. Exits 1 when the defect is present, 2 when
# a check could not run, 0 when every check passes.
set -uo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
here="$root/docs/audits/AUD-024-harnesses/verifier-decoy-first-match"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/aud024-verifier-decoy-target}"
words="${BIP39_ENGLISH_RS:-$(cargo metadata --format-version 1 --offline --manifest-path "$root/Cargo.toml" 2>/dev/null \
  | python3 -c 'import json,sys,os; d=json.load(sys.stdin); print(next(os.path.dirname(p["manifest_path"]) for p in d["packages"] if p["name"]=="bip39"))')/src/language/english.rs}"
python3 "$here/fingerprints.py" "$words" || exit 2
(cd "$here/probe" && cargo build --offline --quiet) || exit 2
(cd "$root" && cargo build --offline --locked --quiet --bin mhfe) || exit 2
failed=0
echo "== library: ContainerSearch::search_decoy"
"$CARGO_TARGET_DIR/debug/aud024-verifier-decoy-probe"
case $? in 0) echo "PASS: library" ;; 1) echo "FAIL: library"; failed=1 ;; *) exit 2 ;; esac
echo "== command line: mhfe repair at TERM=dumb"
python3 "$here/cli_search.py" "$CARGO_TARGET_DIR/debug/mhfe" | grep -v -E '^ *Compared [0-9]+ of [0-9]+$'
case ${PIPESTATUS[0]} in 0) echo "PASS: command line" ;; 1) echo "FAIL: command line"; failed=1 ;; *) exit 2 ;; esac
exit $failed
