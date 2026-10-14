#!/usr/bin/env bash
# AUD-024 harness (verify-coin-type-selfcheck): whether the runtime self-checks notice a wrong
# search root of the address check. Extracts the crate at a revision (default HEAD) into a
# temporary folder and, for each mutation of src/wallet.rs below, runs the self-check tests that
# would have to notice it (the startup sets, the `addresses` check and the `address-search` check
# at both tiers). As a control it runs the unit test that searches every address-table row, which
# must fail, so that a mutation that did not take is not read as missed.
#
#   docs/audits/AUD-024-harnesses/verify-coin-type-selfcheck/mutations.sh [revision]
#
# Exit 0: every mutation is noticed by a self-check. Exit 1: at least one mutation passes every
# self-check (the defect). Exit 2: a mutation did not apply or did not take.
set -uo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
revision="${1:-HEAD}"
target="$(realpath -m "${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/aud024-coin-type-target}")"
copy="$(mktemp -d "${TMPDIR:-/tmp}/aud024-coin-type.XXXXXX")"
trap 'rm -rf "$copy"' EXIT
(cd "$root" && git archive "$revision" Cargo.toml Cargo.lock build.rs rust-toolchain.toml \
  clippy.toml src vendor tests scripts web packaging README.md SECURITY.md docs/API.md \
  docs/BROWSER-PACKAGE.md THIRD_PARTY_NOTICES.md) | tar -x -C "$copy"
cp "$copy/src/wallet.rs" "$copy/wallet.rs.orig"

# Each mutation: name, the exact text at b6fca69, its replacement, separated by tabs.
mutations=(
  $'litecoin coin type 2 -> 3\tSelf::Litecoin => &[2],\tSelf::Litecoin => &[3],'
  $'ethereum and injective coin type 60 -> 61\tSelf::Ethereum | Self::Injective => &[60],\tSelf::Ethereum | Self::Injective => &[61],'
  $'xrp coin type 144 -> 145\tSelf::Xrp => &[144],\tSelf::Xrp => &[145],'
  $'nested SegWit purpose 49 -> 48\tSelf::P2shP2wpkh => 49,\tSelf::P2shP2wpkh => 48,'
  $'Taproot purpose 86 -> 85\tSelf::P2tr => 86,\tSelf::P2tr => 85,'
  $'DIP17 chains not hardened in the search loop\tCHAINS.map(|chain| chain | HARDENED)\tCHAINS.map(|chain| chain)'
  $'dash coin type 5 -> 6 (control: noticed)\tSelf::Dash => &[5],\tSelf::Dash => &[6],'
)

passes() {
  (cd "$copy" && CARGO_TARGET_DIR="$target" cargo test --locked --offline --lib "$1" >/dev/null 2>&1)
}

status=0
for entry in "${mutations[@]}"; do
  IFS=$'\t' read -r name from to <<<"$entry"
  cp "$copy/wallet.rs.orig" "$copy/src/wallet.rs"
  if ! python3 - "$copy/src/wallet.rs" "$from" "$to" <<'PY'; then
import sys
path, old, new = sys.argv[1:]
text = open(path, encoding="utf-8").read()
if text.count(old) != 1:
    sys.exit(1)
open(path, "w", encoding="utf-8").write(text.replace(old, new))
PY
    echo "SETUP: '$name': the text is not once in src/wallet.rs as at b6fca69; adapt it." >&2
    exit 2
  fi
  noticed=""
  for filter in every_set_passes_at_startup \
    wallet::known_answers::addresses::tests::the_address_check_passes \
    the_address_search_is_stated_as_known; do
    passes "$filter" || noticed="$noticed $filter"
  done
  if passes addresses_are_found_where_their_wallets_put_them; then
    echo "SETUP: '$name' did not take: the unit test that searches every row still passes" >&2
    exit 2
  fi
  if [[ -n "$noticed" ]]; then
    echo "PASS: $name: noticed by$noticed"
  else
    echo "FAIL: $name: every self-check passes; only the unit test fails"
    status=1
  fi
done
exit "$status"
