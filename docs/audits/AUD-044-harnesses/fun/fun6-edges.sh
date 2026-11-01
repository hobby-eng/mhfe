#!/usr/bin/env bash
# AUD-044 fun probe: edge cases of section 12 on the reduced-cost command line, script mode.
set -u
R=../tmp/aud044/fun/mhfe-reduced
PY="python3 -I ../tmp/aud044/fun/bip39.py"
PW="public test password"
F='grep -v Settings\|Isolation\|Secrets\|Time\ \|Work\ \|^$\|░\|█\|MHFE\ ·\|Press\ Ctrl\|Next\ \|More:\|clear\ the\ screen\|Letter\ case'
show() { "$@" 2>&1 | grep -v 'Settings\|Isolation\|Secrets\|Time \|Work \|^$\|░\|█\|MHFE ·\|Press Ctrl\|Next \|More:\|clear the screen\|Letter case\|Note:' | cut -c1-130; }
for bytes in 16 20 24 28; do
  ENT=$(python3 -I -c "print(bytes(range(7,7+$bytes)).hex())")
  P=$($PY $ENT); W=$(echo $P | wc -w)
  echo "#### suite 4, $W words"
  C=$(printf '%s\n%s\n%s\n' "$P" "$PW" "$PW" | $R encrypt --stdin --same-length 2>enc.err); echo "encrypt exit $?, words $(echo $C | wc -w)"
  grep -n 'Format\|Keep\|not detect\|wrong password\|shows\|length' enc.err | cut -c1-110
  echo "-- right"; printf '%s\n%s\n' "$C" "$PW" | show $R decrypt --stdin
  [ "$(printf '%s\n%s\n' "$C" "$PW" | $R decrypt --stdin 2>/dev/null | cut -d' ' -f3-)" = "$P" ] && echo SAME-AS-ORIGINAL
  echo "-- wrong"; printf '%s\n%s\n' "$C" "wrong" | show $R decrypt --stdin
  echo "-- other length stated"; printf '%s\n%s\n' "$C" "$PW" | show $R decrypt --stdin --words 24
  echo "-- --words own"; printf '%s\n%s\n' "$C" "$PW" | show $R decrypt --stdin --words $W
  echo "-- check --words"; printf '%s\n%s\n' "$C" "$PW" | show $R check --stdin --words 12
  echo "-- check auto"; printf '%s\n%s\n\n' "$C" "$PW" | show $R check --stdin --words auto
done
P24=$($PY $(python3 -I -c "print(bytes(range(32)).hex())"))
echo "#### 24 words --same-length"; printf '%s\n%s\n%s\n' "$P24" "$PW" "$PW" | show $R encrypt --stdin --same-length
