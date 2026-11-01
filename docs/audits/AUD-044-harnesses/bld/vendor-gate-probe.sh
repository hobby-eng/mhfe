#!/usr/bin/env bash
# The vendored-code gate of scripts/check.sh, the same pipeline, on a copy of the folder with one
# added header; then what -I of scripts/build-argon2-wasm.sh does with it, shown with the system cc.
set -euo pipefail
repo=/home/sergio/Documents/bip_tools/mhfe
work=/home/sergio/Documents/bip_tools/tmp/aud044/bld/probes/vendor
rm -rf "$work"; mkdir -p "$work/vendor"
cp -r "$repo/vendor/phc-winner-argon2" "$work/vendor/"
cp "$repo/vendor/phc-winner-argon2.md" "$work/vendor/"
printf '/* added by the probe */\n#error this header shadows the system one\n' > "$work/vendor/phc-winner-argon2/src/stdint.h"
cd "$work"
sed -n '/^```text$/,/^```$/p' vendor/phc-winner-argon2.md | grep -v '^```' |
  (cd vendor/phc-winner-argon2 && sha256sum --check --quiet) && echo "the gate passes with the added file"
cc -Ivendor/phc-winner-argon2/include -Ivendor/phc-winner-argon2/src -E vendor/phc-winner-argon2/src/core.c 2>&1 | grep -m1 -n 'shadows' || true
