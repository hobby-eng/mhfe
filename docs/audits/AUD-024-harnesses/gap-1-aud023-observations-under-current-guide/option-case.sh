#!/usr/bin/env bash
# AUD-024 harness: option values in another letter case. Each accepted case then stops at the
# empty standard input ("Standard input ended before this answer") or at the missing terminal,
# before any round; each refused one stops at the parser. Exits 1 when some options accept
# another case while others refuse it.
#
#   docs/audits/AUD-024-harnesses/gap-1-aud023-observations-under-current-guide/option-case.sh <mhfe>
set -uo pipefail
binary="$1"
accepted=0
refused=0
run() {
  local output code
  output="$(NO_COLOR=1 "$binary" "$@" </dev/null 2>&1)"
  code=$?
  if grep -q "Invalid value" <<<"$output"; then
    refused=$((refused + 1))
    echo "REFUSED  mhfe $* (exit $code): $(grep -m1 'Invalid value' <<<"$output")"
  else
    accepted=$((accepted + 1))
    echo "ACCEPTED mhfe $* (exit $code): $(tail -n 2 <<<"$output" | tr '\n' ' ')"
  fi
}
run check --stdin --words AUTO
run check --stdin --address --coin Bitcoin
run check --stdin --address --coin " BITCOIN "
run check --stdin --words auto --passphrase-used YES
run rekey --confirm CHECK --words 12
run encrypt --stdin --new-password Words
run encrypt --stdin --same-length YES
if [[ $accepted -gt 0 && $refused -gt 0 ]]; then
  echo "FAIL: $accepted values in another case accepted, $refused refused: no one rule"
  exit 1
fi
echo "PASS: every option treats another letter case alike"
