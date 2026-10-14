#!/usr/bin/env bash
# AUD-024 harness (reviewed commit b6fca69): fails when a JavaScript file of the browser package
# (web/*.js) has more than 800 lines (CORE-15), whatever max-lines exception it carries, or when
# its largest class spans more than 800 lines. Prints each file's size, its exception and its
# classes' spans. Run from the repository root. Exit 0: every file fits; 1: a file or class does not.
set -euo pipefail
limit=800
status=0
for file in web/*.js; do
  lines=$(wc -l < "$file")
  exception=$(sed -n '1,4p' "$file" | grep -o 'oxlint-disable max-lines -- .*' || true)
  printf '%-24s %5d lines%s\n' "$file" "$lines" "${exception:+  [exception: ${exception#oxlint-disable max-lines -- }...]}"
  if [ "$lines" -gt "$limit" ]; then
    echo "  FAIL: more than $limit lines (CORE-15); an exception is for a file that reads best whole"
    status=1
  fi
  while read -r start name; do
    end=$(awk -v s="$start" 'NR>s && /^}/ {print NR; exit}' "$file")
    span=$((end - start + 1))
    echo "  class $name: lines $start-$end ($span lines)"
    if [ "$span" -gt "$limit" ]; then
      echo "  FAIL: class $name spans more than $limit lines (WEB-02, CORE-15)"
      status=1
    fi
  done < <(awk '/^export class [A-Za-z]+/ {name=$3; print NR, name}' "$file")
done
exit "$status"
