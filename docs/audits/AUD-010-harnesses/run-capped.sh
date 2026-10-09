#!/usr/bin/env bash
# Runs one full-size Argon2 command for the AUD-010 evidence in its own systemd user unit, capped at
# 3800 MiB with no swap, so that running out of memory ends this command and nothing else on the
# computer (workspace rule for heavy checks; one at a time). It first waits until the computer has
# that much memory free, and records the run through run-logged.sh.
#
#   docs/audits/AUD-010-harnesses/run-capped.sh <name> <command> [arguments...]
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <name> <command> [arguments...]" >&2
  exit 2
fi
name="$1"
shift
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../../.." && pwd)"
# A 2 GiB Argon2id area plus the program and its build: the cap and the free memory it needs.
cap_mib=3800
for _ in $(seq 1 120); do
  available_mib=$(($(awk '/^MemAvailable:/ {print $2}' /proc/meminfo) / 1024))
  ((available_mib >= cap_mib)) && break
  echo "waiting: ${available_mib} MiB free, ${cap_mib} MiB needed" >&2
  sleep 30
done
exec "$here/run-logged.sh" "$name" systemd-run --user --wait --pipe --quiet --collect \
  --unit="mhfe-aud010-$name" -p MemoryMax="${cap_mib}M" -p MemorySwapMax=0 \
  -p OOMScoreAdjust=1000 -p OOMPolicy=continue -p WorkingDirectory="$repo_root" \
  --setenv=CARGO_HOME="${CARGO_HOME:?}" --setenv=RUSTUP_HOME="${RUSTUP_HOME:?}" \
  --setenv=PATH="$PATH" "$@"
