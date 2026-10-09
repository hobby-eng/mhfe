#!/usr/bin/env bash
# Run inside the task's transient systemd unit; verify its kernel-enforced limits before work.
set -euo pipefail
unit="${MHFE_AUDIT_UNIT:?Transient unit identity required}"
memory_max="$(systemctl --user show "$unit" --property=MemoryMax --value)"
swap_max="$(systemctl --user show "$unit" --property=MemorySwapMax --value)"
if [[ "$memory_max" != 4294967296 || "$swap_max" != 0 ]]; then
  echo "The transient unit has not applied the required 4 GiB/no-swap limit." >&2
  exit 1
fi
systemctl --user show "$unit" --property=MemoryMax --property=MemorySwapMax --property=ControlGroup
exec "$@"
