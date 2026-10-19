#!/usr/bin/env bash
# The fast checks of the repository: what CI runs on every push and pull request (CI-04) and what
# a change passes before it is called done (CORE-43). Formatting, the copy and code-rules gates,
# the pinned versions, the Docker stages, clippy for the native program and for every WebAssembly
# build, the fast tests, the browser package's types, the lint and Prettier, in a few minutes.
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
# The copy gate reads Rust sources/tests, browser classes and the JavaScript of scripts.
# Python and shell are reviewed separately; each rule has one source (CORE-10).
# Check the shared reader in a bounded worker before any gate uses it on repository files.
node scripts/verify-rust-strings.mjs
node scripts/verify-no-copies.mjs --self-test
node scripts/verify-no-copies.mjs
# The guide's rules the other gates cannot see: the length of Rust, Python and shell files, script
# headers, hashed Python requirements, exact versions, one lockfile, doc comments on the browser
# package's exports and reasons on lint exceptions.
node scripts/verify-code-rules.mjs --self-test
node scripts/verify-code-rules.mjs
node scripts/verify-error-contracts.mjs --self-test
node scripts/verify-error-contracts.mjs
node scripts/verify-cli-questions.mjs --self-test
node scripts/verify-cli-questions.mjs
python3 scripts/verify-audit-records.py --self-test
python3 scripts/verify-audit-records.py --metadata-only
node scripts/verify-python-checks.mjs
python3 -m scripts.terminal_suite.session
# The retained module graph's low-level boundary criterion (AUD-024-ARC022), excluding the
# separately tracked error and self-check dependencies.
node scripts/verify-module-boundaries.mjs --self-test
node scripts/verify-module-boundaries.mjs
python3 docs/audits/AUD-024-harnesses/verify-module-edges/decisive_edges.py
node scripts/verify-blame-revs.mjs --self-test
node scripts/verify-blame-revs.mjs --syntax-only
node scripts/verify-release-checksums.mjs --self-test
node scripts/cargo-output.mjs --self-test
python3 scripts/verify-macos-packages.py --self-test
node scripts/verify-packaged-readme.mjs --self-test
node scripts/verify-browser-wait.mjs
node scripts/verify-browser-source.mjs
node scripts/verify-builder-remapping.mjs
node scripts/verify-wasm-binding-path.mjs
node scripts/verify-network-code.mjs --self-test
node scripts/verify-network-code.mjs
node scripts/verify-single-modules.mjs --self-test
# Every copy of a pinned version or provenance value (mhfe's version, the Argon2 commit, Emscripten,
# wasm-bindgen, Node.js, Rust) equal to its source.
node scripts/verify-pinned-versions.mjs --self-test
node scripts/verify-pinned-versions.mjs
# Every stage of the canonical build copies the modules and scripts its scripts need.
node scripts/verify-docker-stages.mjs --self-test
node scripts/mark-wasm-stack.mjs --self-test
node scripts/verify-docker-stages.mjs
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
