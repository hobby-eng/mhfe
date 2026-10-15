#!/usr/bin/env bash
# Apply and verify the macOS hardened runtime on a release CLI binary. Ad-hoc signing needs no
# private signing key or network; --timestamp=none keeps signing independent of the build time.
#
#   scripts/harden-macos.sh <binary>
set -euo pipefail

if [[ $# -ne 1 || "$(uname -s)" != Darwin ]]; then
  echo "Usage on macOS: scripts/harden-macos.sh <binary>" >&2
  exit 2
fi

binary="$1"
/usr/bin/codesign --force --sign - --options runtime --timestamp=none "$binary"
/usr/bin/codesign --verify --strict "$binary"
policy="$(/usr/bin/codesign --display --verbose=4 "$binary" 2>&1)"
if ! grep -Eq 'flags=0x[[:xdigit:]]+\([^)]*runtime' <<< "$policy"; then
  echo "The signed binary does not carry the macOS hardened runtime." >&2
  exit 1
fi
