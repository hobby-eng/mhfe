#!/usr/bin/env bash
# AUD-017 R4 probe: the copy gate of scripts/check.sh (scripts/verify-no-copies.mjs) passes on the
# tree. Exits 1 when it reports copies, which would fail check.sh, ci.yml and so release.yml.
# Usage, from the repository root: docs/audits/AUD-017-harnesses/r4-build-docs/no_copies_gate.sh
set -euo pipefail
node scripts/verify-no-copies.mjs --self-test
node scripts/verify-no-copies.mjs
