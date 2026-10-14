#!/usr/bin/env bash
# AUD-024 verifier harness (commit b6fca69). Runs the real mhfe (argument 1) as a secret command
# started directly, `encrypt --stdin --pim 0 --mem 0`, fed three words that it refuses before any
# Argon2 round, with hook.c preloaded (LD_PRELOAD). The hook acts on the first read of standard
# input, after protect::isolate. Then reads back from outside what reached a scratch file in the
# folder given as argument 2 (a file system with user extended attributes). Exits 1 when any
# change got through, 0 when every one was refused.
set -u
mhfe="$1"
scratch="$2"
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$scratch"
dir="$(mktemp -d "$scratch/aud024-verify-isolation.XXXXXX")"
gcc -shared -fPIC -O1 -Wall -o "$dir/hook.so" "$here/hook.c" -ldl || exit 2
file="$dir/victim.txt"
printf 'public test content\n' > "$file"
chmod 600 "$file"
echo "mhfe sha256: $(sha256sum "$mhfe" | cut -d' ' -f1)"
echo "before: $(stat -c 'mode %a, size %s, mtime %Y' "$file")"
printf 'abandon abandon about\n' | AUD024_PROBE_FILE="$file" LD_PRELOAD="$dir/hook.so" \
  "$mhfe" encrypt --stdin --pim 0 --mem 0 2>&1 | sed 's/\x1b\[[0-9;]*m//g'
echo "mhfe exit status: ${PIPESTATUS[1]}"
echo "after: $(stat -c 'mode %a, size %s, mtime %Y' "$file")"
fail=0
for name in user.aud024-verify-path user.aud024-verify-fd; do
  value="$(python3 -c 'import os,sys
try: print(repr(os.getxattr(sys.argv[1], sys.argv[2]).decode()))
except OSError as e: print("<none:", e.strerror + ">")' "$file" "$name")"
  echo "after: xattr $name = $value"
  case "$value" in "<none"*) ;; *) fail=1 ;; esac
done
[ "$(stat -c %a "$file")" = 600 ] || fail=1
[ "$(stat -c %Y "$file")" = 1000000000 ] && fail=1
[ "$(stat -c %s "$file")" = 20 ] || fail=1
rm -rf "$dir"
if [ "$fail" = 1 ]; then
  echo "FAIL: the isolated secret command changed the file system (extended attribute, mode, time or size)"
  exit 1
fi
echo "PASS: no change reached the file system"
