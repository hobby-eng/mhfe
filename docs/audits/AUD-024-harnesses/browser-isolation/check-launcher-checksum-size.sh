#!/usr/bin/env bash
# AUD-024 browser-isolation check: both fast-mode launchers refuse, with their own message and exit
# code 2, a checksum file far larger than the one line it may hold (CORE-48: input from outside is
# read with an explicit size limit). The file holds the public test page's valid line and then
# 1 MiB of empty lines, which both launchers skip as blank. Each launcher runs with --no-browser
# for at most 5 seconds; serving the page means the file was accepted. Exits 1 when a launcher
# accepts the file or ends without its "✗ Error:" refusal.
#
#   MHFE=<mhfe built from the snapshot> docs/audits/AUD-024-harnesses/browser-isolation/check-launcher-checksum-size.sh
set -u
root="$(cd "$(dirname "$0")/../../../.." && pwd)"
mhfe="${MHFE:-$root/target/release/mhfe}"
# Made absolute here, as each launcher runs in a folder of its own.
mhfe="$(cd "$(dirname "$mhfe")" && pwd)/$(basename "$mhfe")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
printf '<!doctype html><title>tool</title>' > "$work/tool.html"
{ (cd "$work" && sha256sum tool.html); head -c $((1024 * 1024)) /dev/zero | tr '\0' '\n'; } \
  > "$work/mhfe-fast-mode.sha256"
failed=0
for launcher in "mhfe serve" "mhfe-fast-mode.py"; do
  if [ "$launcher" = "mhfe serve" ]; then command=("$mhfe" serve --no-browser tool.html);
  else command=(python3 "$root/packaging/mhfe-fast-mode.py" --no-browser tool.html); fi
  output="$(cd "$work" && NO_COLOR=1 timeout 5 "${command[@]}" 2>&1)"
  code=$?
  if [ "$code" -eq 2 ] && printf '%s' "$output" | grep -q '✗ Error:'; then
    echo "ok   $launcher refuses a checksum file of $(stat -c %s "$work/mhfe-fast-mode.sha256") bytes"
  else
    failed=1
    echo "FAIL $launcher accepts a checksum file of $(stat -c %s "$work/mhfe-fast-mode.sha256") bytes (exit $code):"
    printf '%s\n' "$output" | grep -v '^$' | sed 's/^/     /' | head -6
  fi
done
exit "$failed"
