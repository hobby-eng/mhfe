#!/usr/bin/env bash
# AUD-044 fun probe: a new container whose reader is gone, on the reduced-cost command line.
R=../tmp/aud044/fun/mhfe-reduced
P="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
PW="public test password"
printf '%s\n%s\n%s\n' "$P" "$PW" "$PW" | $R encrypt --stdin 2>err.txt | true
echo "encrypt exit ${PIPESTATUS[1]}"
grep -n 'Error\|Keep\|Next' err.txt | cut -c1-100
rm -f err.txt
