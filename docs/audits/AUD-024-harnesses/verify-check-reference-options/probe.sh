#!/usr/bin/env bash
# AUD-024 verifier: `mhfe check` takes --coin and --path beside --fingerprint, --words N and
# --words auto --stdin, and never uses them. Every case stops before any Argon2 round: at a bad
# fingerprint, or at the 2 GiB reservation, which the address-space cap below refuses.
# Exits 1 when any misplaced --coin/--path is accepted (the defect), 0 when each is refused.
#
#   docs/audits/AUD-024-harnesses/verify-check-reference-options/probe.sh <path to mhfe>
set -u
mhfe="${1:?usage: probe.sh <path to mhfe>}"
export NO_COLOR=1
ulimit -v 1000000   # about 1 GB: the 2 GiB work area cannot be reserved, so no round can start
p12="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
p24="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
failed=0
run() { # <label> <stdin text> <args...>
  local label="$1" text="$2"; shift 2
  local output code
  output="$(printf '%s' "$text" | timeout 60 "$mhfe" check "$@" 2>&1)"; code=$?
  echo "=== $label: mhfe check $* -> exit $code"
  printf '%s\n' "$output" | sed 's/^/    /'
  LAST_OUTPUT="$output"; LAST_CODE=$code
}
expect_refused() { # the misplaced option must be a usage error before the title
  if [ "$LAST_CODE" -eq 2 ] && ! printf '%s' "$LAST_OUTPUT" | grep -q "MHFE · Rehearse"; then
    echo "    -> refused before anything is asked"
  else
    echo "    -> ACCEPTED (defect): the command started with the option unused"
    failed=1
  fi
}
# 1. Fingerprint with --coin and --path: the fingerprint is asked; no coin, no address search.
run "fingerprint" "$p12"$'\nx\nzz\n' --stdin --fingerprint --coin ethereum --path "m/84'/0'/0'/0/5"
expect_refused
# 2. Built-in check of 12 words with --coin and --path: no reference is asked at all.
run "built-in check" "$p24"$'\nx\n' --stdin --words 12 --coin ethereum --path "m/0/1"
expect_refused
# 3. Own checks in a script: the passphrase line is read; coin and path are never reachable.
run "own checks, script" "$p24"$'\nx\n\n' --stdin --words auto --coin ethereum --path "m/0/1"
expect_refused
# Controls.
run "control: --coin alone" "" --coin ethereum
run "control: --address with --fingerprint" "" --address --fingerprint
run "control: --address uses --coin" "$p12"$'\nx\nzz\n' --stdin --address --coin ethereum --path "m/44'/60'/0'/0/0"
exit "$failed"
