#!/usr/bin/env bash
# AUD-024, role gap-1 (commit b6fca69): AUD-023-ARC017's required verification asks that a removed
# response timeout of the Python launcher makes a test fail. Copies what
# scripts/verify-fast-mode-script.py reads into a scratch tree, makes answer() in
# packaging/mhfe-fast-mode.py set no timeout, and runs the launcher's response-deadline test alone
# for at most LIMIT seconds.
#
#   docs/audits/AUD-024-harnesses/gap-1-aud023-required-verification-and-remediation-diff/arc017_response_deadline_hang.sh \
#     <scratch folder> [limit in seconds, 60]
#
# Exit 0 when the test fails within the limit; 1 when it passes or is still running at the limit.
set -uo pipefail
scratch="$1"; limit="${2:-60}"
root="$scratch/arc017-mutant"
rm -rf "$root"; mkdir -p "$root/scripts" "$root/src/bin"
cp -r packaging "$root/"; cp scripts/verify-fast-mode-script.py "$root/scripts/"
cp -r src/bin/mhfe "$root/src/bin/"; cp Cargo.lock "$root/"
sed -i 's/^        connection.settimeout(RESPONSE_DEADLINE)$/        connection.settimeout(None)  # MUTANT (AUD-024)/' \
  "$root/packaging/mhfe-fast-mode.py"
grep -q "MUTANT (AUD-024)" "$root/packaging/mhfe-fast-mode.py" || { echo "mutation not applied"; exit 2; }
cd "$root"
start=$(date +%s)
PYTHONDONTWRITEBYTECODE=1 timeout "$limit" python3 scripts/verify-fast-mode-script.py \
  Server.test_a_client_that_does_not_read_is_dropped_at_the_response_deadline > out.txt 2>&1
code=$?
echo "exit $code after $(( $(date +%s) - start )) s"
case "$code" in
  0) echo "NOT GUARDED: the test passes without the response timeout"; exit 1 ;;
  124) echo "NOT GUARDED: the test is still running after ${limit} s (it waits for ever)"; exit 1 ;;
  *) echo "GUARDED: the test fails"; exit 0 ;;
esac
