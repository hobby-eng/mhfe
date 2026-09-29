#!/usr/bin/env bash
# Proves that the cheap Argon2 engine for fast unit tests is absent from what a release ships.
#
# The test engine exists only under #[cfg(test)] and carries a marker text
# (REDUCED_COST_MARKER in src/engine/native.rs). The marker must be present in the library's test
# binary, which shows that the search works, and absent from the release binary and the
# WebAssembly core. Build them first with `cargo build --release` and scripts/build-wasm.sh.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

marker="MHFE-TEST-ONLY-REDUCED-ARGON2-COST"
release_artifacts=(target/release/mhfe target/ssse3/release/mhfe dist/mhfe_core_bg.wasm)

test_binary="$(
  cargo test --locked --lib --no-run --message-format=json 2>/dev/null |
    python3 -c '
import json, sys
for line in sys.stdin:
    message = json.loads(line)
    if message.get("reason") == "compiler-artifact" and message.get("executable") \
            and message["target"]["name"] == "mhfe":
        print(message["executable"])
'
)"
if ! grep -q --binary-files=binary "$marker" "$test_binary"; then
  echo "The marker is missing from the test binary $test_binary, so this check proves nothing." >&2
  exit 1
fi

for artifact in "${release_artifacts[@]}"; do
  if [[ ! -f "$artifact" ]]; then
    echo "Missing $artifact; build the release artifacts first." >&2
    exit 1
  fi
  if grep -q --binary-files=binary "$marker" "$artifact"; then
    echo "$artifact contains the test-only reduced Argon2 engine." >&2
    exit 1
  fi
done
echo "The test-only reduced Argon2 engine is in the test binary and in no release artifact."
