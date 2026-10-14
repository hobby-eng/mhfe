#!/usr/bin/env bash
# AUD-024 probe: sizes, class span, public members and length exceptions of web/client.js and
# web/runtime.js at b6fca69, their growth since 253ca3c^, and how the build joins source files.
set -euo pipefail
rev=b6fca69238344dd2525b06270ee6ff3b055e68c1
echo "HEAD: $(git rev-parse HEAD)"
for r in 253ca3c^ "$rev"; do
  for f in web/client.js web/runtime.js; do
    printf '%-10s %-16s %5d lines\n' "${r:0:8}" "$f" "$(git show "$r:$f" | wc -l)"
  done
done
echo "== per-commit numstat (added deleted) 253ca3c^..$rev"
for c in $(git rev-list --reverse "253ca3c^..$rev"); do
  s=$(git show --numstat --format= "$c" -- web/client.js web/runtime.js)
  if [ -n "$s" ]; then echo "$(git log -1 --format='%h %s' "$c")"; echo "$s"; fi
done
echo "== length exceptions in tracked files (oxlint max-lines, long:, clippy too_many_lines)"
git grep -n -E 'oxlint-disable(-next-line)? max-lines|^\s*(//|#) long: |expect\(\s*clippy::too_many_lines' "$rev" -- ':!docs/audits' ':!scripts/verify-code-rules.mjs' || true
echo "== exception text"
git show "$rev:web/client.js" | sed -n 1,4p
git show "$rev:web/runtime.js" | sed -n 1,4p
echo "== MhfeClient: first line and closing brace"
git show "$rev:web/client.js" | awk '/^export class MhfeClient/{s=NR} s&&/^}/{print "class MhfeClient: lines " s "-" NR " (" NR-s+1 " lines)"; exit}'
echo "== MhfeClient public members (excluding constructor and # private)"
git show "$rev:web/client.js" | awk 'NR>=188 && NR<=1138 && /^  (async )?[a-zA-Z][a-zA-Z0-9]*\(/ {sub(/\(.*/,""); sub(/^  (async )?/,""); if ($0!="constructor") print NR": "$0}'
echo "public members: $(git show "$rev:web/client.js" | awk 'NR>=188 && NR<=1138 && /^  (async )?[a-zA-Z][a-zA-Z0-9]*\(/ && !/constructor/' | wc -l)"
echo "== MhfeClient private members"
git show "$rev:web/client.js" | awk 'NR>=188 && NR<=1138 && /^  (async )?#[a-zA-Z][a-zA-Z0-9]*\(/ {print NR": "$0}'
echo "== runtime.js top-level classes and exported functions/constants"
git show "$rev:web/runtime.js" | grep -n -E '^(export )?(class|function|async function|const) ' 
echo "== build: the worker shipped as one file is joined from seven source files"
git show "$rev:scripts/build-wasm.sh" | sed -n 62,67p
echo "== runtime import that the bundler strips"
git show "$rev:scripts/bundle-browser-classes.mjs" | grep -n 'runtimeImport'
