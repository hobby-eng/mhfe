#!/usr/bin/env bash
# AUD-015 baseline: the checks of scripts/check.sh that fit the owner's hold on long runs, one at a
# time, each through run.py so that its log and record stay in docs/audits/AUD-015-evidence/.
# Not run here: scripts/verify-browsers.mjs (full browser suite), the full-size vector replays
# (tests/suite3_vectors.rs ignored tests, mhfe self-test --vectors), the canonical Docker build.
# Exits non-zero when any check failed; every check runs regardless.
set -uo pipefail
cd "$(dirname "$0")/../../.."
run() { python3 docs/audits/AUD-015-harnesses/run.py "$@" || failed=1; }
failed=0
workspace_root="$(cd .. && pwd)"
export CARGO_HOME="$workspace_root/workingspace/cargo"
export RUSTUP_HOME="$workspace_root/workingspace/rustup"
export PATH="$CARGO_HOME/bin:$PATH"
. packaging/remap-builder-paths.sh
remap_builder_paths "$PWD"
run vendor-argon2-hashes bash -c "sed -n '/^\`\`\`text\$/,/^\`\`\`\$/p' vendor/phc-winner-argon2.md | grep -v '^\`\`\`' | (cd vendor/phc-winner-argon2 && sha256sum --check)"
run third-party-licenses python3 scripts/third-party-licenses.py --check
run published-rounds python3 scripts/generate-published-rounds.py --check
run cargo-fmt cargo fmt --check
run no-copies-self-test node scripts/verify-no-copies.mjs --self-test
run no-copies node scripts/verify-no-copies.mjs
run clippy-native cargo clippy --locked --all-targets --all-features -- -D warnings
run clippy-wasm cargo clippy --locked --lib --target wasm32-unknown-unknown --features wasm -- -D warnings
for module in browser-core browser-repair browser-passwords browser-wallet; do
  run "clippy-$module" cargo clippy --locked --lib --target wasm32-unknown-unknown --no-default-features --features "$module" -- -D warnings
done
run cargo-test cargo test --locked
run cargo-doc env RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
run release-build cargo build --locked --release
run self-test target/release/mhfe self-test
run hidden-input python3 scripts/verify-hidden-input.py target/release/mhfe
run dist-hashes-before bash -c "find dist -type f | sort | xargs sha256sum"
run build-wasm bash -c '. "$1" >/dev/null 2>&1 && scripts/build-wasm.sh' _ "$workspace_root/workingspace/emsdk/emsdk_env.sh"
run dist-hashes-after bash -c "find dist -type f | sort | xargs sha256sum"
run dist-unchanged cmp docs/audits/AUD-015-evidence/dist-hashes-before.log docs/audits/AUD-015-evidence/dist-hashes-after.log
run argon2-wasm node scripts/verify-argon2-wasm.mjs
run browser-package node scripts/verify-browser-package.mjs
run cli-browser-parity node scripts/verify-cli-browser-parity.mjs target/release/mhfe
run fast-mode-script python3 scripts/verify-fast-mode-script.py
run release-artifacts scripts/check-release-artifacts.sh
run prettier-docs npx prettier --check README.md SECURITY.md AGENTS.md docs/API.md docs/BROWSER-PACKAGE.md docs/releases/v0.5.1.md
exit "$failed"
