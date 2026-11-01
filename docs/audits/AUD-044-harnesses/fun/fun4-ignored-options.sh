#!/usr/bin/env bash
# AUD-044 fun probe: options a run cannot use. repair and repair-words reach no Argon2 here, and the
# check runs on the reduced-cost program.
REL=../tmp/aud044/target/release/mhfe
R=../tmp/aud044/fun/mhfe-reduced
C="$(cat ../tmp/aud044/fun/c12.txt)"
PW="public test password"
CARD=$(printf '%s\n' "$C" | $REL repair-words --stdin --count 4 2>/dev/null)
echo "card: $CARD"
D="${C/ /  }"; D="? ${C#* }"
echo "== repair --stdin --pim 99 --mem 99 --scan-gap 7 (limits are 1023 and 21; a PIM of 99 is in range, level 99 is not)"
printf '%s\n%s\n' "$D" "$CARD" | $REL repair --stdin --pim 2000 --mem 99 --scan-gap 7 2>&1 | grep -v 'Note:\|^$\|Isolation\|Secrets\|MHFE ·' | cut -c1-110
echo "exit ${PIPESTATUS[1]}"
echo "== the same refused where the settings are used: decrypt --stdin --pim 2000"
printf '%s\n%s\n' "$C" "$PW" | $R decrypt --stdin --pim 2000 2>&1 | tail -1 | cut -c1-110
echo "exit ${PIPESTATUS[1]}"
for o in "--coin ethereum --words 12" "--path m/0 --words 12" "--coin ethereum --fingerprint" "--path m/0 --fingerprint"; do
  echo "== check --stdin $o"
  printf '%s\n%s\n73c5da0a\n\n' "$C" "$PW" | $R check --stdin $o 2>&1 | tail -1 | cut -c1-110
  echo "exit ${PIPESTATUS[1]}"
done
echo "== check --stdin --coin ethereum (no reference)"
printf '%s\n%s\n' "$C" "$PW" | $R check --stdin --coin ethereum 2>&1 | tail -3 | cut -c1-110
echo "exit ${PIPESTATUS[1]}"
