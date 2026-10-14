#!/usr/bin/env bash
# AUD-024, role guide-tooling-other: runs checks.py next to it from the repository root.
#   docs/audits/AUD-024-harnesses/guide-tooling-other/run.sh [path to mhfe]
# Exits 1 while any of its checks finds its defect, 0 once none does.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$repo_root"
PYTHONDONTWRITEBYTECODE=1 python3 "$(dirname "${BASH_SOURCE[0]}")/checks.py" "$@"
