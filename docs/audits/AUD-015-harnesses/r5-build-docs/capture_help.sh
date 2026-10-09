#!/usr/bin/env bash
# AUD-015 R5: prints `mhfe --help`, then `-h` and `--help` of every command, without colour, so that
# the documented options can be compared with the real ones. Usage: capture_help.sh <mhfe binary>
set -euo pipefail
binary="${1:?usage: capture_help.sh <mhfe binary>}"
export NO_COLOR=1
echo "=== mhfe --help"
"$binary" --help
echo "=== mhfe --version"
"$binary" --version
for command in new encrypt decrypt check rekey wallets repair repair-words password self-test \
  serve test-vectors test-benchmark; do
  echo "=== mhfe $command -h"
  "$binary" "$command" -h
  echo "=== mhfe $command --help"
  "$binary" "$command" --help
done
