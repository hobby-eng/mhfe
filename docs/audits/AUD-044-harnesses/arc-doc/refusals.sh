#!/usr/bin/env bash
# Commands of the README that are refused before any Argon2 round, each with its exit code.
# Usage: refusals.sh <path to mhfe>. Public test data only.
set -uo pipefail

mhfe="$1"
export NO_COLOR=1
container="donate stove tower picnic iron rescue trick shrimp roof rib home cigar bag pledge also nerve cycle famous provide heart ahead chunk caution peace"

show() {
  local input="$1"
  shift
  printf '%s' "$input" | "$mhfe" "$@" >out.txt 2>err.txt
  local code=$?
  printf 'exit %s: mhfe %s\n' "$code" "$*"
  grep -E 'Error' -A2 err.txt | cut -c1-110 | head -4
}

work="$(mktemp -d ./refusals.XXXXXX)"
cd "$work" || exit 1
show '' encrypt --mem 21 --stdin
show '' encrypt --mem 22 --stdin
show '' encrypt --pim 1024 --stdin
show '' encrypt --repair-words 3 --stdin
show "$container"$'\n' repair-words --count 3 --stdin
show '' password --words 33
show '' password --chars 65
show '' check --stdin
show '' new
show '' wallets
cd .. && rm -rf "$work"
