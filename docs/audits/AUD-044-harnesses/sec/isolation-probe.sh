#!/usr/bin/env bash
# AUD-044 SEC: runs a command with isolation-probe.so and prints what each call got, then whether the
# file it worked on changed.
#   isolation-probe.sh <mhfe> <isolation-probe.so> <folder> [mhfe arguments...]
set -uo pipefail
mhfe="$1"; shim="$2"; dir="$3"; shift 3
log="$dir.log"; : > "$log"
before="$(stat -c '%a %s %Y %Z' "$dir/target")"
PROBE_DIR="$dir" LD_PRELOAD="$shim" "$mhfe" "$@" 9>> "$log" > /dev/null 2>&1 < /dev/null
echo "exit $?"
cat "$log"
after="$(stat -c '%a %s %Y %Z' "$dir/target")"
echo "target before: $before"
echo "target after:  $after"
ls "$dir"
