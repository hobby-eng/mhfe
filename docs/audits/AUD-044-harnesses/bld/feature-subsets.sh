#!/usr/bin/env bash
# Every subset of the four browser modules through clippy for wasm32, the way scripts/check.sh runs
# each module alone. Cargo.toml says another program can build one with only the modules it needs.
set -uo pipefail
cd /home/sergio/Documents/bip_tools/mhfe
export CARGO_TARGET_DIR=/home/sergio/Documents/bip_tools/tmp/aud044/target
modules=(browser-core browser-repair browser-passwords browser-wallet)
failed=0
for mask in $(seq 0 15); do
  features=()
  for bit in 0 1 2 3; do
    if (( mask >> bit & 1 )); then features+=("${modules[$bit]}"); fi
  done
  list="$(IFS=,; echo "${features[*]:-}")"
  if cargo clippy --locked --lib --target wasm32-unknown-unknown --no-default-features \
    --features "$list" -- -D warnings > /dev/null 2> "/home/sergio/Documents/bip_tools/tmp/aud044/bld/probes/subset-$mask.err"; then
    echo "ok     [$list]"
  else
    echo "FAILED [$list]"; failed=$((failed + 1))
    grep -m3 -E '^(error|warning)' "/home/sergio/Documents/bip_tools/tmp/aud044/bld/probes/subset-$mask.err"
  fi
done
echo "failed: $failed of 16"
