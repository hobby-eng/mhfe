#!/usr/bin/env bash
# AUD-044 fun probe: a result that cannot be written, on the release program; repair-words reaches
# no full-size Argon2.
REL=../tmp/aud044/target/release/mhfe
C="$(cat ../tmp/aud044/fun/c12.txt)"
feed() { printf '%s\n' "$C"; }
echo "== stdout /dev/full"; feed | $REL repair-words --stdin --count 4 > /dev/full 2>err.txt; echo "exit $?"; tail -2 err.txt | cut -c1-120
echo "== stdout closed pipe"; feed | $REL repair-words --stdin --count 4 2>err.txt | true; echo "exit ${PIPESTATUS[1]}"; tail -2 err.txt | cut -c1-120
echo "== stdout closed (>&-)"; feed | $REL repair-words --stdin --count 4 >&- 2>err.txt; echo "exit $?"; tail -2 err.txt | cut -c1-120
echo "== stderr /dev/full"; feed | $REL repair-words --stdin --count 4 2>/dev/full; echo "exit $?"
echo "== stderr closed pipe"; ( feed | $REL repair-words --stdin --count 4 2>&1 >/dev/null | true ); echo "exit ${PIPESTATUS[0]}"
echo "== stderr closed (2>&-)"; feed | $REL repair-words --stdin --count 4 2>&-; echo "exit $?"
