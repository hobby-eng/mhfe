#!/usr/bin/env bash
# AUD-023 baseline: the repository's own gates, run once, one after another, each under a kernel
# memory limit, with a log and a record per step in docs/audits/AUD-023-evidence/. Full-cost
# vector replays are left out on the owner's instruction (they take about an hour each).
#
#   docs/audits/AUD-023-harnesses/baseline.sh [step ...]
#
# Steps: check (scripts/check.sh), browsers (scripts/verify-browsers.mjs), canonical (an uncached
# scripts/build-reproducible.sh). Without arguments all three run in this order. Every step holds
# the shared lock file named by AUD023_LOCK, so that no other heavy job of the audit runs beside
# it. Exit code 0 only when every step passed.
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root"
workspace="$(dirname "$repo_root")"
evidence="docs/audits/AUD-023-evidence"
lock="${AUD023_LOCK:-$workspace/tmp/claude/aud023/heavy.lock}"
# A step may use up to this much memory; the machine keeps the rest for everything else.
memory_max="${AUD023_MEMORY_MAX:-6G}"
mkdir -p "$evidence" "$(dirname "$lock")"

export CARGO_HOME="$workspace/workingspace/cargo"
export RUSTUP_HOME="$workspace/workingspace/rustup"
export PATH="$CARGO_HOME/bin:$HOME/.local/bin:$PATH"
# shellcheck disable=SC1091
source "$workspace/workingspace/emsdk/emsdk_env.sh" >/dev/null 2>&1

run_step() {
  local name="$1"
  shift
  local log="$evidence/baseline-$name.log"
  local started ended code
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  flock "$lock" systemd-run --user --scope --quiet -p MemoryMax="$memory_max" -p MemorySwapMax=0 \
    --setenv=PATH="$PATH" "$@" >"$log" 2>&1
  code=$?
  ended="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  python3 - "$evidence/baseline-$name.command.json" "$name" "$started" "$ended" "$code" "$log" "$*" <<'PY'
import hashlib, json, sys
path, name, started, ended, code, log, command = sys.argv[1:]
digest = hashlib.sha256(open(log, "rb").read()).hexdigest()
json.dump({"step": name, "command": command, "startedUtc": started, "endedUtc": ended,
           "exitCode": int(code), "log": log, "logSha256": digest}, open(path, "w"), indent=2)
PY
  echo "$name exit $code"
  return "$code"
}

steps=("$@")
[[ ${#steps[@]} -eq 0 ]] && steps=(check browsers canonical)
failed=0
for step in "${steps[@]}"; do
  case "$step" in
    check) run_step check bash scripts/check.sh || failed=1 ;;
    browsers) run_step browsers node scripts/verify-browsers.mjs || failed=1 ;;
    canonical)
      REPRODUCIBLE_NO_CACHE=1 run_step canonical env REPRODUCIBLE_NO_CACHE=1 \
        bash scripts/build-reproducible.sh canonical-output-aud023 || failed=1
      ;;
    *)
      echo "unknown step: $step" >&2
      failed=1
      ;;
  esac
done
exit "$failed"
