#!/usr/bin/env bash
# AUD-015 R1: byte provenance of the cryptographic inputs, without running any of them.
#   1. the vendored Argon2 files against the SHA-256 list in vendor/phc-winner-argon2.md, and no
#      file there that the list omits;
#   2. the EFF list against the specification's SHA-256;
#   3. the suite 3 and suite 4 fixtures in tests/fixtures against the specification's vectors
#      (../mhfe_spec/vectors), byte for byte, and the specification's own SHA256SUMS;
#   4. src/mhfe/published_rounds.rs against its generator (scripts/generate-published-rounds.py
#      --check), the table the startup self-check replays.
# Run from the repository root. Exits non-zero on the first difference.
set -euo pipefail
spec=../mhfe_spec/vectors

listed=$(sed -n '/^```text$/,/^```$/p' vendor/phc-winner-argon2.md | grep -v '^```')
(cd vendor/phc-winner-argon2 && sha256sum --check --quiet) <<<"$listed"
diff <(awk '{print $2}' <<<"$listed" | sort) \
  <(cd vendor/phc-winner-argon2 && find . -type f | sed 's|^\./||' | sort)
echo "vendored Argon2: $(wc -l <<<"$listed") files match vendor/phc-winner-argon2.md, none unlisted"

echo "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e  vendor/eff-large-wordlist/eff_large_wordlist.txt" |
  sha256sum --check --quiet
echo "EFF list: matches the specification's SHA-256"

for suite in suite3 suite4; do
  (cd "$spec/$suite" && sha256sum --check --quiet SHA256SUMS)
  count=0
  for file in "$spec/$suite"/*.json; do
    # Suite 3's fast cases sit one level up in tests/fixtures; compared below.
    [[ $suite == suite3 && $(basename "$file") == validation-cases.json ]] && continue
    cmp "$file" "tests/fixtures/$suite-vectors/$(basename "$file")"
    count=$((count + 1))
  done
  echo "$suite: $count specification files equal tests/fixtures/$suite-vectors, SHA256SUMS ok"
done
cmp "$spec/suite3/validation-cases.json" tests/fixtures/validation-cases.json
echo "suite3 validation-cases.json equals tests/fixtures/validation-cases.json"

python3 scripts/generate-published-rounds.py --check
echo "src/mhfe/published_rounds.rs is its generator's output"
