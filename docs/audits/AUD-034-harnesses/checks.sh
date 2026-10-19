#!/usr/bin/env bash
# Focused Linux acceptance controls for AUD-034; use the repository's pinned toolchain.
set -euo pipefail

if [[ $# -ne 0 || "$(uname -s)" != Linux ]]; then
  echo "Run this public-data control without arguments on Linux." >&2
  exit 2
fi
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root"

# Refuse an empty Cargo filter and preserve the actual command status.
check() {
  local mhfe_test_output mhfe_test_status=0
  mhfe_test_output="$(cargo test --locked "$@")" || mhfe_test_status=$?
  printf '%s\n' "$mhfe_test_output"
  if [[ "$mhfe_test_status" -ne 0 ]]; then
    return "$mhfe_test_status"
  fi
  if ! grep -Eq 'test result: ok\. [1-9][0-9]* passed; 0 failed;' <<< "$mhfe_test_output"; then
    echo "The selected public control ran no passing tests." >&2
    return 1
  fi
}

check --lib engine::dump_protection:: -- --test-threads=1
check --lib concurrent_c_calls_keep_verified_work_area_protection
check --lib matches_rustcrypto_on_many_small_public_inputs
check --bin mhfe standard_input:: -- --test-threads=1
