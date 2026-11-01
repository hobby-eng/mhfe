#!/usr/bin/env bash
# AUD-044 SEC: runs one scenario of drive.py from a work folder, then prints what memscan found and
# the end of what the terminal showed. memscan.so is built from memscan.c, as its header says.
#   scenario.sh <scenario> <mhfe program> <memscan.so> <work folder> [note to count blocks from]
set -uo pipefail
here="$(dirname "$0")"
scenario="$1"; program="$2"; shim="$3"; work="$4"; note="${5:-}"
rm -rf "$work"
timeout 110 python3 -I "$here/drive.py" "$scenario" "$program" "$shim" "$work" | grep -v '^transcript:\|^log:'
if [[ -n "$note" ]]; then
  python3 -I "$here/summarize.py" "$work/memscan.log" "$note"
else
  python3 -I "$here/summarize.py" "$work/memscan.log"
fi
echo "## the end of what the terminal showed"
if [[ -s "$work/transcript.txt" ]]; then tail -n 8 "$work/transcript.txt" | cut -c1-110; fi
