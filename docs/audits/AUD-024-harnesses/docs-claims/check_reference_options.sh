#!/usr/bin/env bash
# AUD-024 docs-claims: `mhfe check --coin` and `--path` are documented as "With --address" (their
# helps) and clap refuses `--coin` alone, so they must also be refused beside --fingerprint or
# --words N instead of being ignored. Each case gives a one-word container on standard input, so
# that a command which accepts its options stops at the container, before any Argon2 round.
# Exits 1 when any case is accepted (the defect), 0 when every case is refused as a usage error.
#
#   docs/audits/AUD-024-harnesses/docs-claims/check_reference_options.sh <path to mhfe>
set -u
mhfe="${1:?usage: check_reference_options.sh <path to mhfe>}"
export NO_COLOR=1
ulimit -v 1500000
failed=0
for args in "--fingerprint --coin ethereum" "--fingerprint --path m/84'/0'/0'/0/5" \
            "--words 12 --coin ethereum" "--words 12 --path m/84'/0'/0'/0/5"; do
  # shellcheck disable=SC2086
  output="$(printf 'abandon\n' | timeout 30 "$mhfe" check --stdin $args 2>&1)"
  code=$?
  if [ "$code" -eq 2 ] && printf '%s' "$output" | grep -q -- "--address" &&
     ! printf '%s' "$output" | grep -q "MHFE · Rehearse"; then
    echo "refused as expected: check --stdin $args"
  else
    echo "ACCEPTED (defect): check --stdin $args -> exit $code"
    printf '%s\n' "$output" | sed 's/^/    /'
    failed=1
  fi
done
# Control: --coin without any reference is refused by clap today.
output="$(timeout 30 "$mhfe" check --coin ethereum < /dev/null 2>&1)"
echo "control, check --coin ethereum alone -> exit $?:"
printf '%s\n' "$output" | sed 's/^/    /'
exit "$failed"
