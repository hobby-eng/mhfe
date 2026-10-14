#!/usr/bin/env bash
# AUD-024 build-release harness (CHECK-BLD-001): clippy with -D warnings of the library for
# wasm32-unknown-unknown with every non-empty combination of the four browser features
# (browser-core, browser-repair, browser-passwords, browser-wallet), which docs/API.md and
# docs/BROWSER-PACKAGE.md offer to other programs one by one or together. It exits 1 when any of
# the 15 combinations fails. The library with no browser feature and with the helper feature
# wasm-bindings alone is also linted and reported, without changing the exit code.
#
#   CARGO_TARGET_DIR=<scratch target> docs/audits/AUD-024-harnesses/build-release/feature-combos.sh
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../../../.."
modules=(browser-core browser-repair browser-passwords browser-wallet)
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
lint() {
  cargo clippy --locked --lib --target wasm32-unknown-unknown --no-default-features \
    --features "$1" --quiet -- -D warnings > "$scratch/out" 2>&1
}
failed=0
for ((mask = 1; mask < 16; mask++)); do
  set=()
  for i in 0 1 2 3; do
    if ((mask & (1 << i))); then set+=("${modules[$i]}"); fi
  done
  features="$(IFS=,; echo "${set[*]}")"
  if lint "$features"; then
    echo "PASS [$features]"
  else
    echo "FAIL [$features]"
    sed 's/^/    /' "$scratch/out" | head -40
    failed=1
  fi
done
for features in "" wasm-bindings; do
  if lint "$features"; then
    echo "info: [$features] passes"
  else
    echo "info: [$features] does not pass clippy -D warnings:"
    grep -E '^(error|warning)' "$scratch/out" | sort | uniq -c | sed 's/^/    /'
  fi
done
exit "$failed"
