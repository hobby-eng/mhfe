#!/usr/bin/env bash
# AUD-024, adversarial verifier "verify-help-constants", commit b6fca69. Renders the helps of a
# built mhfe (no Argon2 runs: clap prints the help before any command starts) and lists the help
# lines that state, as typed text, a value the library defines as a constant, together with the
# source line at HEAD that types it. Exits 1 when at least one such line is found, 0 otherwise,
# 2 on a setup error.
#
#   docs/audits/AUD-024-harnesses/verify-help-constants/typed-values.sh <path to mhfe>
set -euo pipefail

mhfe="$1"
[ -x "$mhfe" ] || { echo "setup: $mhfe is not executable"; exit 2; }
echo "HEAD: $(git rev-parse HEAD)"
echo "binary: $("$mhfe" --version)"

render() { NO_COLOR=1 COLUMNS=100 "$mhfe" "$@" 2>&1 | tr -s ' \n' ' '; }

found=0
# label | command arguments | typed text in the help | source file:pattern at HEAD
while IFS='|' read -r label args typed file pattern; do
  [ -n "$label" ] || continue
  # shellcheck disable=SC2086
  text="$(render $args)"
  if grep -qF -- "$typed" <<<"$text"; then
    where="$(git grep -n -F -- "$pattern" HEAD -- "$file" | head -1 | cut -d: -f2-3)"
    echo "TYPED: $label: mhfe $args shows \"$typed\" ($where)"
    found=$((found + 1))
  else
    echo "not found: $label"
  fi
done <<'LIST'
rekey --new-pim (MAX_PIM)|rekey -h|PIM of the new container, 0 to 1023 (default 0)|src/bin/mhfe/rekey.rs|PIM of the new container, 0 to 1023
rekey --new-pim long help (MAX_PIM)|rekey --help|--new-pim <N> PIM of the new container, 0 to 1023 (default 0)|src/bin/mhfe/rekey.rs|PIM of the new container, 0 to 1023
rekey --new-mem (MAX_MEMORY_LEVEL, memory_text(0))|rekey -h|New memory level, 0 to 21 (default 0: 2 GiB)|src/bin/mhfe/rekey.rs|New memory level, 0 to 21
rekey --words (WORD_COUNTS)|rekey -h|Words of the seed phrase: 12 to 24, or auto|src/bin/mhfe/rekey.rs|Words of the seed phrase: 12 to 24
--new-password (DEFAULT_WORDS, DRAWN_WORDS, DEFAULT_CHARACTERS)|encrypt --help|words: five dice words, about 64.6 bits. check-word: five words and a check word|src/bin/mhfe/made_password.rs|words: five dice words
--new-password (DEFAULT_CHARACTERS)|encrypt --help|chars: sixteen random characters, about|src/bin/mhfe/made_password.rs|sixteen random characters, about
decrypt rounds (ROUNDS)|decrypt --help|Runs 12 rounds, 1 to 2 minutes|src/bin/mhfe/decrypt.rs|Runs 12 rounds
encrypt rounds (ENCRYPTION_ROUNDS, ROUNDS)|encrypt --help|Encryption runs 24 rounds: 12 to encrypt, then 12|src/bin/mhfe/encrypt.rs|Encryption runs 24 rounds
encrypt note rounds (ROUNDS)|encrypt --help|after the first 12 rounds|src/bin/mhfe/encrypt.rs|after the first 12 rounds
check rounds (ROUNDS)|check --help|Runs the same 12 rounds as a recovery|src/bin/mhfe/check.rs|Runs the same 12 rounds
self-test --vectors rounds (ROUNDS)|self-test --help|12 rounds each|src/bin/mhfe/self_test.rs|12 rounds each
encrypt about lengths (BUILT_IN_CHECK_WORD_COUNTS)|encrypt --help|or for a 12- to 21-word phrase|src/bin/mhfe/encrypt.rs|valid BIP39 phrase: 24 words by default, or for a 12- to
check about lengths (BUILT_IN_CHECK_WORD_COUNTS)|check --help|or, for a 12- to 21-word original seed phrase|src/bin/mhfe/check.rs|for a 12- to
rekey --confirm lengths (BUILT_IN_CHECK_WORD_COUNTS)|rekey --help|for a 12- to 21-word length stated with --words|src/bin/mhfe/rekey.rs|check, for a 12- to 21-word length
encrypt examples memory (memory_text(1), memory_text(0))|encrypt -h|3 GiB of memory instead of 2 GiB|src/bin/mhfe/encrypt.rs|3 GiB of memory instead of 2 GiB
self-test --vectors short help (vectors_cost)|self-test -h|Also run the published vectors at full cost: minutes, 2 GiB|src/bin/mhfe/self_test.rs|minutes, 2 GiB
repair-words example (RECOMMENDED_REPAIR_WORDS)|repair-words -h|Four repair words, the recommended number|src/bin/mhfe/container_repair.rs|Four repair words, the recommended number
password about (eff::LIST_SIZE)|password --help|EFF large word list of 7,776 words|src/bin/mhfe/diceware.rs|7,776 words
top-level examples (memory_text(1), DEFAULT_WORDS)|--help|Encrypt with twice the passes and 3 GiB|src/bin/mhfe/main.rs|twice the passes and 3 GiB
top-level examples (DEFAULT_WORDS)|--help|Make a strong password of five dice words|src/bin/mhfe/main.rs|five dice words
LIST
echo "$found help texts type a value that a library constant defines"
[ "$found" -eq 0 ]
