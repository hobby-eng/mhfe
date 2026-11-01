#!/usr/bin/env bash
# AUD-044 fun probe: the program under a limit on threads, on the release program. Only the start
# checks run: self-test and repair-words, which reach no full-size Argon2.
REL=../tmp/aud044/target/release/mhfe
C="slush crime nose carry menu cabbage already cart lock intact focus siren filter crouch buyer toward topple cup holiday avoid mango envelope dream sweet"
echo "== self-test, ulimit -u 1"
bash -c 'ulimit -u 1; exec "$0" self-test' "$REL" 2>&1 | tail -12 | cut -c1-150
echo "exit ${PIPESTATUS[0]}"
echo "== repair-words --stdin --count 4, ulimit -u 1"
printf '%s\n' "$C" | bash -c 'ulimit -u 1; exec "$0" repair-words --stdin --count 4' "$REL" 2>&1 | tail -12 | cut -c1-150
echo "exit ${PIPESTATUS[1]}"
