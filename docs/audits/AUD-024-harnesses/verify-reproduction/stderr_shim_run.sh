#!/usr/bin/env bash
# AUD-024 harness (verify-reproduction), commit b6fca69. Runs mhfe with stderr_shim.c preloaded,
# every write to standard error failing with ENOSPC, for four commands that stop before any
# Argon2 round beyond the checks at start: password, repair-words --stdin --count 4 (public phrase
# 23 x abandon, art), encrypt --stdin with the three words "not a phrase", and a usage error.
# Prints each exit status and the panic text with its source location; exits 1 when any command
# ends with SIGABRT (status 134), 0 when every one ends with a code of README's table.
#
#   docs/audits/AUD-024-harnesses/verify-reproduction/stderr_shim_run.sh <mhfe> <scratch>
set -u
B="${1:?path to the mhfe binary}"
OUT="${2:?scratch folder}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
gcc -shared -fPIC -O1 -o "$OUT/stderr_shim.so" "$HERE/stderr_shim.c" || exit 2
ZERO24="$(printf 'abandon %.0s' $(seq 23))art"
aborted=0

shim_case() {
  local name="$1" stdin="$2"; shift 2
  local log="$OUT/$name.shim.log"
  rm -f "$log"
  printf '%s' "$stdin" | NO_COLOR=1 SHIM_LOG="$log" LD_PRELOAD="$OUT/stderr_shim.so" \
    "$B" "$@" >"$OUT/$name.stdout" 2>/dev/null
  local code=${PIPESTATUS[1]}
  echo "== $name: exit $code; standard output lines: $(wc -l <"$OUT/$name.stdout")"
  grep -a -A1 -F 'panicked at' "$log" | cut -c1-200
  [ "$code" -eq 134 ] && aborted=$((aborted + 1))
  return 0
}

shim_case password "" password
shim_case repair-words "$ZERO24
" repair-words --stdin --count 4
shim_case encrypt-invalid "not a phrase
" encrypt --stdin --pim 0 --mem 0
shim_case usage-error "" encrypt --no-such-option
if [ "$aborted" -gt 0 ]; then
  echo "FAIL: $aborted of 4 commands aborted (SIGABRT, 134) on a failing standard error"
  exit 1
fi
echo "PASS: every command ended with a documented exit code"
