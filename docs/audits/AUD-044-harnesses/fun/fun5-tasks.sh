#!/usr/bin/env bash
# AUD-044 fun probe: repair-words, which needs no thread, under a limit on tasks on a 16-core computer.
REL=../tmp/aud044/target/release/mhfe
C="$(cat ../tmp/aud044/fun/c12.txt)"
nproc
for T in 4 8 10; do
  printf 'TasksMax=%s: ' $T
  printf '%s\n' "$C" | systemd-run --user --scope --quiet -p TasksMax=$T $REL repair-words --stdin --count 4 2>&1 | grep -v "^$\|Ctrl+C\|More:" | tail -2 | tr '\n' ' ' | cut -c1-130
  echo
done
