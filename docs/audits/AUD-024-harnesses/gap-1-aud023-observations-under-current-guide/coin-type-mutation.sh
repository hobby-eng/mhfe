#!/usr/bin/env bash
# AUD-024 harness: whether the runtime self-checks notice a wrong coin type of the address search.
# Extracts the crate at a revision (default HEAD) into a temporary folder, changes Litecoin's coin
# type from 2 to 3 (Dogecoin's) in Coin::coin_types, and runs the startup sets, the addresses check
# and the address-search check at both tiers, then the unit test that searches every table row.
# Exits 1 when the self-checks pass with the wrong coin type.
#
#   docs/audits/AUD-024-harnesses/gap-1-aud023-observations-under-current-guide/coin-type-mutation.sh [revision]
set -uo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
revision="${1:-HEAD}"
copy="$(mktemp -d "${TMPDIR:-/tmp}/aud024-coin-type.XXXXXX")"
trap 'rm -rf "$copy"' EXIT
target="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/aud024-gap1-mutation-target}"
(cd "$root" && git archive "$revision" Cargo.toml Cargo.lock build.rs rust-toolchain.toml clippy.toml \
  src vendor tests scripts web packaging README.md SECURITY.md docs/API.md docs/BROWSER-PACKAGE.md \
  THIRD_PARTY_NOTICES.md) | tar -x -C "$copy"
if ! grep -q 'Self::Litecoin => &\[2\],' "$copy/src/wallet.rs"; then
  echo "Litecoin's coin type line is not as at b6fca69; adapt the mutation." >&2
  exit 2
fi
sed -i 's/Self::Litecoin => &\[2\],/Self::Litecoin => \&[3],/' "$copy/src/wallet.rs"
run() {
  (cd "$copy" && CARGO_TARGET_DIR="$target" cargo test --locked --offline --lib "$1" 2>&1) |
    grep -E '^test |test result' | head -3
  return "${PIPESTATUS[0]}"
}
status=0
self_checks_pass=1
for filter in every_set_passes_at_startup the_address_check_passes the_address_search_is_stated_as_known; do
  echo "### $filter, Litecoin's coin type changed to 3"
  if run "$filter"; then echo "  passes"; else echo "  fails"; self_checks_pass=0; fi
done
echo "### addresses_are_found_where_their_wallets_put_them (unit test, control)"
if run addresses_are_found_where_their_wallets_put_them; then
  echo "  passes (unexpected: the mutation did not take)"; status=2
else
  echo "  fails, as it should"
fi
if [[ $self_checks_pass -eq 1 ]]; then
  echo "FAIL: the startup and full self-checks pass with a wrong coin type for Litecoin's address search"
  status=1
else
  echo "PASS: a self-check notices the wrong coin type"
fi
exit "$status"
