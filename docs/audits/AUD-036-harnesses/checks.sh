#!/usr/bin/env bash
# Scoped local fixture checks; real Windows/macOS execution remains a separate native CI check.
set -euo pipefail

cargo fmt --check
node scripts/verify-code-rules.mjs
node scripts/verify-no-copies.mjs
pnpm exec prettier --check docs/DEVELOPMENT.md docs/releases/unreleased.md
python3 docs/audits/AUD-036-harnesses/fixture-signing.py
