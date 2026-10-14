#!/usr/bin/env bash
# AUD-024 verifier (verify-gives-costs-width): width of the "Search" fact (style::fact_before_work)
# that mhfe check --stdin --address --path prints before the BIP39 passphrase is read. Standard
# input ends at the passphrase, so the command is refused (exit 2) before any Argon2 round; the
# address space is limited to 1 GiB as a guard. Public vector nonzero-24 only.
set -u
mhfe="$1"
root="$2"
container="$(python3 -c "import json;print(json.load(open('$root/tests/fixtures/suite3-vectors/nonzero-24.json'))['container'])")"
path="m/2147483647'/2147483647'/2147483647'/2147483647'/2147483647/0"
out="$(printf '%s\n%s\n%s\n' "$container" "audit probe password 2026" "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" \
  | NO_COLOR=1 timeout 20 prlimit --as=1073741824 "$mhfe" check --stdin --pim 0 --mem 0 --address --coin bitcoin --path "$path" 2>&1 >/dev/null)"
code=$?
echo "exit code: $code"
printf '%s\n' "$out" | while IFS= read -r line; do printf '%3d %s\n' "$(printf '%s' "$line" | wc -m)" "$line"; done
widest="$(printf '%s\n' "$out" | grep '^  Search' | while IFS= read -r l; do printf '%s' "$l" | wc -m; done | sort -n | tail -1)"
echo "Search line: ${widest:-none} columns (TEXT_WIDTH 78)"
[ -n "$widest" ] && [ "$widest" -gt 78 ] && { echo "OVER WIDTH"; exit 1; }
exit 0
