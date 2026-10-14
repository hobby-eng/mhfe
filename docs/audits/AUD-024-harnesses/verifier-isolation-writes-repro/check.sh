#!/usr/bin/env bash
# AUD-024 verifier harness (reproduction lens), commit b6fca69. Builds preload.c and
# abi2-truncate.c into <scratch>, runs the real mhfe binary with preload.so (standing for code
# inside an isolated command) for `self-test` and for `decrypt` refused for want of a terminal,
# reads the target file back from outside, and applies the ABI 1-2 Landlock mask of
# src/bin/mhfe/protect/landlock.rs to truncate. Exits 1 when any file-system change gets through.
# Usage, from the repository root: check.sh <mhfe binary> <scratch folder>
set -uo pipefail
binary="$1"; scratch="$2"
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$scratch"
cc -O1 -Wall -shared -fPIC -o "$scratch/preload.so" "$here/preload.c" -ldl || exit 2
cc -O1 -Wall -o "$scratch/abi2-truncate" "$here/abi2-truncate.c" || exit 2
failed=0
for command in self-test decrypt; do
  target="$scratch/target-$command-$$.txt"
  printf 'public test content\n' > "$target"; chmod 600 "$target"; touch -d '2026-10-14 00:00:00 UTC' "$target"
  echo "== mhfe $command (stdin /dev/null, NO_COLOR=1); binary sha256 $(sha256sum "$binary" | cut -d' ' -f1)"
  env NO_COLOR=1 AUD024_TARGET="$target" LD_PRELOAD="$scratch/preload.so" "$binary" "$command" < /dev/null 2>&1 | grep -E '^\[aud024-probe\]|Isolation|Error'
  mode="$(stat -c %a "$target")"; size="$(stat -c %s "$target")"; mtime="$(stat -c %Y "$target")"
  echo "after, read from outside: mode $mode, size $size, mtime $mtime"
  for name in user.aud024-path user.aud024-fd; do
    value="$(python3 -c 'import os,sys
try: print(os.getxattr(sys.argv[1], sys.argv[2]).decode())
except OSError as e: print("<none: %s>" % e.strerror)' "$target" "$name")"
    echo "after: xattr $name = $value"
    case "$value" in "<none"*) ;; *) failed=1 ;; esac
  done
  { [ "$mode" != 600 ] || [ "$mtime" = 1000000000 ] || [ "$size" != 20 ] || [ -e "$target.new" ]; } && failed=1
  rm -f "$target" "$target.new"
done
echo "== the Landlock mask of ABI 1-2 against truncate"
"$scratch/abi2-truncate" "$scratch" || failed=1
if [ "$failed" = 1 ]; then echo "FAIL: a file-system change got through the isolation of a secret command"; exit 1; fi
echo "PASS: every file-system change tried was refused"
