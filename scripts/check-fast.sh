#!/usr/bin/env bash
# The fast checks of the repository: what CI runs on every push and pull request (CI-04) and what
# a change passes before it is called done (CORE-43). Formatting, the copy and code-rules gates,
# the pinned versions, clippy for the native program and for every WebAssembly build, the fast
# tests, the browser package's types, the lint and Prettier, in a few minutes.
# scripts/check.sh runs them first, then the slow checks of a release.
#
# Needs the pinned Rust toolchain and Node.js with the tools of `pnpm install --frozen-lockfile`.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
# The builds use the fixed names of packaging/remap-builder-paths.sh, as every build of
# scripts/check.sh does, so that neither rebuilds what the other built.
. packaging/remap-builder-paths.sh
remap_builder_paths "$repo_root"

cargo fmt --check
# No code copied from one place to another in the library, the tool, the bindings, the page
# classes, the tests or the scripts: each rule lives in one function that its callers call
# (CORE-10).
node scripts/verify-no-copies.mjs --self-test
node scripts/verify-no-copies.mjs
# The guide's rules the other gates cannot see: the length of Rust, Python and shell files, script
# headers, hashed Python requirements, exact versions, one lockfile, doc comments on the browser
# package's exports and reasons on lint exceptions.
node scripts/verify-code-rules.mjs --self-test
node scripts/verify-code-rules.mjs
# Every copy of a pinned version or provenance value (mhfe's version, the Argon2 commit, Emscripten,
# wasm-bindgen, Node.js, Rust) equal to its source.
node scripts/verify-pinned-versions.mjs --self-test
node scripts/verify-pinned-versions.mjs
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --lib --target wasm32-unknown-unknown --features wasm -- -D warnings
# Each browser module builds alone, so that another program can take one part without the rest.
for module in browser-core browser-repair browser-passwords browser-wallet; do
  cargo clippy --locked --lib --target wasm32-unknown-unknown --no-default-features \
    --features "$module" -- -D warnings
done
# On x86-64 the tests run both the SSE2 and the SSSE3 copy of the Argon2 core.
cargo test --locked
# The browser package's plain JavaScript against its declarations, under the strict flags (TS-13).
pnpm run --silent check:types
# oxlint with type information over the browser package and the scripts: the guide's TypeScript
# rules, the length of files and functions (CORE-15) and oxlint's correctness category.
pnpm run --silent lint
# The workspace style for JavaScript, Markdown, JSON and YAML: double quotes, 100 columns.
pnpm run --silent format:check
echo "The fast checks passed."
