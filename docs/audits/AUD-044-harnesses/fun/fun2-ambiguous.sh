#!/usr/bin/env bash
# AUD-044 fun probe 2: every stated length on a container whose state passes two short checks (the
# public ambiguous state of tests/spec, [12, 21]), on the reduced-cost command line.
set -u
R=../tmp/aud044/fun/mhfe-reduced
PY="python3 -I ../tmp/aud044/fun/bip39.py"
P12=$($PY 4d48464520616d62000000004dda455a)
PW="public test password"
C=$(printf '%s\n%s\n%s\n' "$P12" "$PW" "$PW" | $R encrypt --stdin 2>enc.err)
grep -n 'Write down\|By rare\|Keep\|word count' enc.err
for w in "" "--words auto" "--words 12" "--words 15" "--words 21" "--words 24"; do
  echo "== decrypt $w"
  printf '%s\n%s\n' "$C" "$PW" | $R decrypt --stdin $w 2>&1 | grep -v 'Settings\|Isolation\|Secrets\|Time \|Work \|^$\|░\|█\|MHFE ·\|Container  \|Format \|Password \|Press Ctrl\|The seed phrase will\|clear the screen' | cut -c1-100
  echo "exit ${PIPESTATUS[1]}"
done
for w in "--words auto" "--words 12" "--words 15" "--words 21"; do
  echo "== check $w"
  { printf '%s\n%s\n' "$C" "$PW"; [ "$w" = "--words auto" ] && echo; } | $R check --stdin $w 2>&1 | grep -v 'Settings\|Isolation\|Secrets\|Time \|Work \|^$\|░\|█\|MHFE ·\|Container  \|Format \|Password \|Press Ctrl\|Passphrase ' | cut -c1-100
  echo "exit ${PIPESTATUS[1]}"
done
