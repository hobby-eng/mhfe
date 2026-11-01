#!/usr/bin/env bash
# AUD-044 SEC: what `mhfe encrypt --stdin` says about swap when /proc/swaps is unreadable or lists a
# zram device. Runs the real program inside a user and mount namespace of its own, with standard
# input closed, so that it stops at its first answer, before any Argon2 work.
#
#   docs/audits/AUD-044-harnesses/sec/swap-inventory.sh <path to mhfe>
set -uo pipefail
mhfe="$1"
work="$(mktemp -d "${TMPDIR:-$PWD}/swap-inventory.XXXXXX")"
trap 'rm -rf "$work"' EXIT

run_with_swaps() { # <label> <line of /proc/swaps, or "none" for no readable /proc at all>
  local label="$1" line="$2"
  echo "=== $label"
  printf 'Filename\tType\tSize\tUsed\tPriority\n%s\n' "$line" > "$work/swaps"
  : > "$work/zram0"
  : > "$work/sda9"
  if [[ "$line" == none ]]; then
    unshare -Urm sh -c "mount -t tmpfs none /proc && exec \"$mhfe\" encrypt --stdin" < /dev/null 2>&1
  else
    unshare -Urm sh -c "mount --bind \"$work/swaps\" /proc/swaps && exec \"$mhfe\" encrypt --stdin" \
      < /dev/null 2>&1
  fi | grep -E 'swap|Swap|Isolation  ' | sed "s#$work#<fake>#g"
  echo "(exit ${PIPESTATUS[0]})"
}

# A device whose sysfs entry is a fake one, bound over /sys/class/block: <label> <device> <file>
# <content>, the file relative to the device's folder.
run_with_sysfs() {
  local label="$1" device="$2" file="$3" content="$4"
  echo "=== $label"
  printf 'Filename\tType\tSize\tUsed\tPriority\n%s partition 1024 0 -2\n' "$work/$device" > "$work/swaps"
  : > "$work/$device"
  mkdir -p "$work/block/$device/$(dirname "$file")"
  printf '%s\n' "$content" > "$work/block/$device/$file"
  unshare -Urm sh -c "mount --bind \"$work/swaps\" /proc/swaps && \
    mount --bind \"$work/block\" /sys/class/block && exec \"$mhfe\" encrypt --stdin" \
    < /dev/null 2>&1 | grep -E 'swap|Swap|Isolation  ' | sed "s#$work#<fake>#g"
  echo "(exit ${PIPESTATUS[0]})"
}

run_with_swaps "control: a plain partition" "$work/sda9 partition 1024 0 -2"
run_with_swaps "zram, whose sysfs entry does not exist, so no writeback can be seen" \
  "$work/zram0 partition 1024 0 100"
run_with_swaps "/proc not readable: no inventory at all" none
run_with_sysfs "control: LUKS2, encrypted" dm-90 dm/uuid CRYPT-LUKS2-0123456789abcdef-swap
run_with_sysfs "dm-integrity, no encryption, whose UUID cryptsetup also starts with CRYPT-" dm-91 dm/uuid CRYPT-INTEGRITY-0123456789abcdef-swap
run_with_sysfs "zram with a writeback device, which writes pages to that disk" zram7 backing_dev /dev/sda9
