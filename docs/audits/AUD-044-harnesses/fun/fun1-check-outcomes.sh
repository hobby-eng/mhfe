#!/usr/bin/env bash
# AUD-044 fun probe 1: what `mhfe check` reports in each case of the length rules, on the unchanged
# command line over reduced-cost Argon2 (harness reduced-cli). Public test phrases only.
set -u
R=../tmp/aud044/fun/mhfe-reduced
P12="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
P24="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
PW="public test password"
enc() { printf '%s\n%s\n%s\n' "$1" "$PW" "$PW" | $R encrypt --stdin "${@:2}" 2>/dev/null; }
C12=$(enc "$P12"); C24=$(enc "$P24")
echo "container of a 12-word original: $C12"
echo "container of a 24-word original: $C24"
chk() { # label, container, password, extra stdin lines, options...
  local label="$1" c="$2" pw="$3" extra="$4"; shift 4
  printf '== %s\n' "$label"
  { printf '%s\n%s\n' "$c" "$pw"; [ -n "$extra" ] && printf '%b' "$extra"; } | $R check --stdin "$@" 2>&1 | grep -v 'Settings\|Isolation\|Secrets\|Time \|Work \|^$\|Rehearse\|░\|█\|MHFE ·'
  echo "exit ${PIPESTATUS[1]}"
}
chk "24-word original, right password, --words auto, no passphrase" "$C24" "$PW" '\n' --words auto
chk "24-word original, WRONG password, --words auto, no passphrase" "$C24" "wrong" '\n' --words auto
chk "12-word original, right password, --words auto" "$C12" "$PW" '\n' --words auto
chk "12-word original, wrong password, --words auto" "$C12" "wrong" '\n' --words auto
chk "12-word original, right, --words 12" "$C12" "$PW" '' --words 12
chk "12-word original, right, --words 15 (other length takes precedence)" "$C12" "$PW" '' --words 15
chk "12-word original, wrong, --words 12" "$C12" "wrong" '' --words 12
chk "24-word original, right, --words 12" "$C24" "$PW" '' --words 12
chk "--words 24 refused" "$C24" "$PW" '' --words 24
# The published wallet-check vector counter-76562-trezor: a 24-word phrase that passes with TREZOR.
PW24="$(python3 -I -c "import json;print(json.load(open('tests/spec/vectors/profiles/wallet-check.json'))['cases'][0]['mnemonic'])")"
CW=$(enc "$PW24")
chk "wallet-check vector, right password, right passphrase, --words auto" "$CW" "$PW" 'TREZOR\n' --words auto
chk "wallet-check vector, right password, no passphrase, --words auto" "$CW" "$PW" '\n' --words auto
chk "wallet-check vector, --address of another wallet with the right passphrase" "$CW" "$PW" 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu\nTREZOR\n' --address
