#!/usr/bin/env bash
# Read back the kernel budget before running an unchanged historical browser probe.
set -euo pipefail
unit="${MHFE_BROWSER_AUDIT_UNIT:?Transient unit identity required}"
memory_max="$(systemctl --user show "$unit" --property=MemoryMax --value)"
swap_max="$(systemctl --user show "$unit" --property=MemorySwapMax --value)"
if [[ "$memory_max" != 536870912 || "$swap_max" != 0 ]]; then
  echo "The transient unit has not applied the required 512 MiB/no-swap limit." >&2
  exit 1
fi
systemctl --user show "$unit" --property=MemoryMax --property=MemorySwapMax --property=ControlGroup
set +e
timeout --signal=TERM --kill-after=5s 45s "$@"
status=$?
set -e
systemctl --user show "$unit" --property=MemoryPeak --property=MemoryCurrent
exit "$status"
