#!/usr/bin/env bash
# Runs one command for the AUD-010 evidence and records it: the output in
# docs/audits/AUD-010-evidence/<name>.log and <name>.command.json with the exact command, the UTC
# start and end, the exit code and the log's SHA-256. Exits with the command's own exit code.
#
#   docs/audits/AUD-010-harnesses/run-logged.sh <name> <command> [arguments...]
set -uo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <name> <command> [arguments...]" >&2
  exit 2
fi
name="$1"
shift
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
evidence="$repo_root/docs/audits/AUD-010-evidence"
mkdir -p "$evidence"
log="$evidence/$name.log"
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
(cd "$repo_root" && "$@") >"$log" 2>&1
code=$?
ended="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
digest="$(sha256sum "$log" | cut -d' ' -f1)"
python3 - "$evidence/$name.command.json" "$started" "$ended" "$code" "$digest" "$@" <<'PY'
import json, sys
path, started, ended, code, digest, *command = sys.argv[1:]
record = {"command": command, "startedUtc": started, "endedUtc": ended,
          "exitCode": int(code), "logSha256": digest}
with open(path, "w", encoding="utf-8") as out:
    json.dump(record, out, indent=2)
    out.write("\n")
PY
exit "$code"
