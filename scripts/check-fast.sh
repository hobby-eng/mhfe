#!/usr/bin/env bash
# The fast checks of the repository: what CI runs on every push and pull request (CI-04) and what
# a change passes before it is called done (CORE-43). Formatting, the copy gate, clippy for the
# native program and for every WebAssembly build, the fast tests and Prettier, in a few minutes.
# scripts/check.sh runs them first, then the slow checks of a release.
#
# Needs the pinned Rust toolchain and Node.js with the tools of `npm ci --ignore-scripts`.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
# The builds use the fixed names of packaging/remap-builder-paths.sh, as every build of
# scripts/check.sh does, so that neither rebuilds what the other built.
. packaging/remap-builder-paths.sh
remap_builder_paths "$repo_root"

cargo fmt --check
# No code copied from one place to another in the library, the tool, the bindings or the page
# classes: each rule lives in one function that every front end calls (CORE-10).
node scripts/verify-no-copies.mjs --self-test
node scripts/verify-no-copies.mjs
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --lib --target wasm32-unknown-unknown --features wasm -- -D warnings
# Each browser module builds alone, so that another program can take one part without the rest.
for module in browser-core browser-repair browser-passwords browser-wallet; do
  cargo clippy --locked --lib --target wasm32-unknown-unknown --no-default-features \
    --features "$module" -- -D warnings
done
# On x86-64 the tests run both the SSE2 and the SSSE3 copy of the Argon2 core.
cargo test --locked
# The workspace style for JavaScript, Markdown, JSON and YAML: double quotes, 100 columns.
npm run --silent format:check
echo "The fast checks passed."
