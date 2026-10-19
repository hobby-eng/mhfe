#!/usr/bin/env bash
# Targeted request-deadline regression and behavior-preservation checks.
set -euo pipefail

cargo test --locked --bin mhfe serve::tests:: -- --test-threads=2
cargo clippy --locked --bin mhfe --tests --all-features -- -D warnings
python3 scripts/verify-fast-mode-script.py Routing Server
cargo fmt --check
node scripts/verify-code-rules.mjs
node scripts/verify-no-copies.mjs
pnpm exec prettier --check docs/DEVELOPMENT.md docs/releases/unreleased.md
