#!/usr/bin/env bash
# AUD-010 probe (docs-build-release): compares the Argon2 builds of the local browser package
# (dist/core/argon2-mt.js and argon2-st.js, built by scripts/build-argon2-wasm.sh with the local
# Emscripten 6.0.10) with those of an earlier canonical Docker archive, once the build constant that
# scripts/build-wasm.sh appends (a blank line and one `const ARGON2_..._BUILD_ID = "...";` line) is
# taken off. The vendored Argon2 C code and build-argon2-wasm.sh must be unchanged since that
# archive's source, which the probe checks with git. Exits 1 when a build differs.
#
#   docs/audits/AUD-010-harnesses/docs-build-release/argon2-vs-canonical.sh \
#     [canonical-output-aud008cached/release/mhfe-v0.5.0-browser.tar.gz] [source commit of it]
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$repo_root"
archive="${1:-canonical-output-aud008cached/release/mhfe-v0.5.0-browser.tar.gz}"
# The archive's BUILD-INFO.txt names its source commit.
source_commit="${2:-$(tar -xzOf "$archive" ./BUILD-INFO.txt | sed -n 's/^source: \([0-9a-f]*\).*/\1/p')}"
echo "Canonical archive $archive, source $source_commit"

inputs=(vendor/phc-winner-argon2 scripts/build-argon2-wasm.sh)
if git diff --quiet "$source_commit" -- "${inputs[@]}"; then
  echo "ok    the Argon2 inputs are unchanged since $source_commit"
else
  echo "FAIL  the Argon2 inputs changed since $source_commit; the comparison proves nothing"
  exit 1
fi

failed=0
for build in argon2-mt.js argon2-st.js; do
  local_sum="$(head -n -2 "dist/core/$build" | sha256sum | cut -d' ' -f1)"
  canonical_sum="$(tar -xzOf "$archive" "./$build" | sha256sum | cut -d' ' -f1)"
  appended="$(tail -n 2 "dist/core/$build" | tr '\n' ' ')"
  if [[ "$local_sum" == "$canonical_sum" ]]; then
    echo "ok    $build: local build without its constant equals the canonical one ($local_sum)"
  else
    echo "FAIL  $build: local $local_sum, canonical $canonical_sum"
    failed=1
  fi
  echo "      appended: $appended"
done
exit "$failed"
