#!/usr/bin/env bash
# AUD-024 gap-1-aud023-observations-under-current-guide: the cheap checks of this role's findings,
# in one run. Exits 1 when any check finds its defect, 2 when a check could not run. The heavy
# two-word decoy search is in decoy.sh. See README.md.
set -uo pipefail
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
here="$root/docs/audits/AUD-024-harnesses/gap-1-aud023-observations-under-current-guide"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${TMPDIR:-/tmp}/aud024-gap1-target}"
cd "$root"
(cargo build --locked --release --quiet --bin mhfe) || exit 2
(cd "$here/probe" && cargo build --offline --release --quiet) || exit 2
mhfe="$CARGO_TARGET_DIR/release/mhfe"
probe="$CARGO_TARGET_DIR/release"
worst=0
check() {
  local name="$1"
  shift
  echo "=== $name"
  "$@"
  local code=$?
  if [[ $code -gt $worst ]]; then worst=$code; fi
}
digest_zeroize() {
  if cargo tree --locked --offline -e features -i digest@0.11.3 | grep -q 'digest feature "zeroize"'; then
    echo "PASS: digest 0.11.3 is built with its zeroize feature"
  else
    echo "FAIL: digest 0.11.3, under sha2, hmac, blake2 and sha3, is built without its zeroize feature"
    return 1
  fi
}
stdin_buffer() {
  local std direct
  std="$(printf 'public test password\nsecond line\n' | "$probe/stdin-residue" std "drowssap tset cilbup")"
  direct="$(printf 'public test password\nsecond line\n' | "$probe/stdin-residue" descriptor "drowssap tset cilbup")"
  echo "$std"
  echo "$direct"
  if grep -q 'edit_line(&mut io::stdin().lock()' src/bin/mhfe/hidden_input.rs &&
    grep -q 'copies left in heap and anonymous memory: [1-9]' <<<"$std"; then
    echo "FAIL: mhfe reads typed lines through std's stdin buffer, which keeps a copy after the line is wiped"
    return 1
  fi
  echo "PASS"
}
address_forms() {
  local out
  out="$("$probe/address-forms")"
  echo "$out"
  if grep -Eq 'REFUSED .*(only single-key addresses|its checksum or format is wrong|it is not an address of Dash)' <<<"$out"; then
    echo "FAIL: single-key forms of supported coins are refused with a reason that is false for them"
    return 1
  fi
  echo "PASS"
}
check "hash and MAC states (RUST-13)" digest_zeroize
check "standard input buffer (RUST-13)" stdin_buffer
check "Ctrl+D exit codes (exit.rs)" python3 "$here/ctrl-d.py" "$mhfe"
check "option values in another case (CORE-10, CORE-48)" "$here/option-case.sh" "$mhfe"
check "address forms (CORE-48)" address_forms
check "coin types of the address search in the self-checks (CORE-27)" "$here/coin-type-mutation.sh"
check "CORE-25 gate on Cargo.toml" node "$here/cargo-pin-gate.mjs"
check "browser WebAssembly stack residue (RUST-13, TS-07)" node "$here/wasm-stack-residue.mjs"
check "worker handshake (web/runtime.js)" node --no-warnings "$here/worker-handshake.mjs"
check "fast-mode launchers on Ctrl+C" python3 "$here/launcher-ctrl-c.py" "$mhfe" packaging/mhfe-fast-mode.py
echo "run.sh: worst exit $worst"
exit "$worst"
