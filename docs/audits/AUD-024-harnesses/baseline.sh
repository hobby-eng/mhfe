#!/usr/bin/env bash
# The baseline checks of audit AUD-024, one after another, each kept by run-logged.sh in the
# evidence folder: the fast checks, the gates and generated tables of a release, the documentation
# build, a fresh browser package with its Node.js, single-module and real-browser checks, the
# terminal suite's fast cases, the CLI/browser parity, the fast-mode launcher, the independent
# checkers' fast modes and the advisory scans. Full-size Argon2 work (the vector replays, the
# terminal suite's --full cases, the independent checkers' full runs) and the canonical Docker
# build are not run. A failed check does not stop the others; the script exits 1 if any failed.
#
#   docs/audits/AUD-024-harnesses/baseline.sh <evidence folder>
#
# Needs the toolchains of AGENTS.md, Emscripten 6.0.12 in ../workingspace/emsdk, the hash-pinned
# Python packages of scripts/independent-suite3-requirements.txt on PYTHONPATH (for
# generate-cell-widths.py and the independent checkers) and network access for cargo audit and
# pnpm audit only.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root"
evidence="$(cd "$1" && pwd)"
run="docs/audits/AUD-024-harnesses/run-logged.sh"
failed=0
check() {
  "$run" "$evidence" "$@" || failed=1
}

# The builds use the fixed names of packaging/remap-builder-paths.sh, as scripts/check.sh does.
. packaging/remap-builder-paths.sh
remap_builder_paths "$repo_root"

check b01-check-fast scripts/check-fast.sh
check b02-vendored-argon2-self-test node scripts/verify-vendored-argon2.mjs --self-test
check b03-vendored-argon2 node scripts/verify-vendored-argon2.mjs
check b04-cargo-fetch cargo fetch --locked
check b05-licences-self-test python3 scripts/third-party-licenses.py --self-test
check b06-licences python3 scripts/third-party-licenses.py --check
check b07-published-rounds python3 scripts/generate-published-rounds.py --check
check b08-cell-widths python3 scripts/generate-cell-widths.py --check
check b09-cargo-doc env RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
check b10-release-build cargo build --locked --release
target_dir="$(cargo metadata --locked --no-deps --format-version 1 |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"
check b11-terminal-suite-fast python3 scripts/verify-hidden-input.py "$target_dir/release/mhfe"
check b12-build-wasm bash -c '. ../workingspace/emsdk/emsdk_env.sh > /dev/null 2>&1 && scripts/build-wasm.sh'
(cd dist && find . -type f -print0 | sort -z | xargs -0 sha256sum) > "$evidence/dist-SHA256SUMS"
check b13-argon2-wasm node scripts/verify-argon2-wasm.mjs
check b14-browser-package node scripts/verify-browser-package.mjs
check b15-single-modules node scripts/verify-single-modules.mjs
check b16-cli-browser-parity node scripts/verify-cli-browser-parity.mjs "$target_dir/release/mhfe"
check b17-fast-mode-script python3 scripts/verify-fast-mode-script.py
check b18-release-artifacts scripts/check-release-artifacts.sh
check b19-archive-packing scripts/verify-archive-packing.sh
check b20-browsers node scripts/verify-browsers.mjs
check b21-independent-passwords python3 scripts/independent-suite3.py passwords \
  tests/fixtures/validation-cases.json
check b22-independent-suite4-validation python3 scripts/independent-suite4.py validation \
  tests/fixtures/suite4-vectors/validation-cases.json
check b23-independent-suite3-trusted-keys bash -c 'cd tests/fixtures/suite3-vectors &&
  python3 ../../../scripts/independent-suite3.py vector --trust-argon2-keys $(cut -d" " -f3 SHA256SUMS)'
check b24-independent-suite4-trusted-keys bash -c 'cd tests/fixtures/suite4-vectors &&
  python3 ../../../scripts/independent-suite4.py vector --trust-argon2-keys $(cut -d" " -f3 SHA256SUMS)'
check b25-cargo-audit cargo audit
check b26-pnpm-audit pnpm audit
exit "$failed"
