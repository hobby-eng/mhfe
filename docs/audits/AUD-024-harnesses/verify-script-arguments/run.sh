#!/usr/bin/env bash
# AUD-024 harness, commit b6fca69: the check and generator scripts refuse a command line outside
# their usage instead of running another check, or none, and passing. Run from the repository
# root; see README.md beside it. Prints PASS or FAIL per case and exits 1 if any case failed.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
failed=0

# Expects the command to end with a non-zero exit code (a refusal).
expect_refusal() {
  local name="$1"
  shift
  if "$@" > "$scratch/out" 2>&1; then
    echo "FAIL $name: exit 0, the command line was not refused"
    failed=1
  else
    echo "PASS $name: refused (exit $?)"
  fi
}

# 1. verify-browser-package.mjs is not run (it writes target/build-id-check/): a static trace of its
#    command line, which fails while a misspelled --full is read as "no full-size run" and nothing
#    in the script refuses an argument.
if node "$here/full-flag-trace.mjs" > "$scratch/out" 2>&1; then
  echo "PASS verify-browser-package-misspelled-full: the script refuses arguments"
else
  echo "FAIL verify-browser-package-misspelled-full: $(tail -1 "$scratch/out")"
  failed=1
fi

# 2. A script without options given one (needs dist/ from scripts/build-wasm.sh; 256 MiB at most).
expect_refusal verify-argon2-wasm-unknown-option node scripts/verify-argon2-wasm.mjs --full

# 3. The independent checkers given no file to check (no Argon2 runs).
expect_refusal suite3-vector-no-file python3 scripts/independent-suite3.py vector
expect_refusal suite3-passwords-no-file python3 scripts/independent-suite3.py passwords
expect_refusal suite4-vector-no-file python3 scripts/independent-suite4.py vector
expect_refusal suite4-validation-no-file python3 scripts/independent-suite4.py validation

# 4. generate-cell-widths.py with a misspelled --check, run as a copy in a scratch tree so that the
#    tracked table is never written: it must refuse and leave a changed table as it was.
mkdir -p "$scratch/copy/scripts" "$scratch/copy/src/bin/mhfe"
cp scripts/generate-cell-widths.py "$scratch/copy/scripts/"
cp src/bin/mhfe/cell_widths.rs "$scratch/copy/src/bin/mhfe/"
printf '// a change the check must report\n' >> "$scratch/copy/src/bin/mhfe/cell_widths.rs"
cp "$scratch/copy/src/bin/mhfe/cell_widths.rs" "$scratch/changed.rs"
if python3 "$scratch/copy/scripts/generate-cell-widths.py" --chek > "$scratch/out" 2>&1; then
  code=0
else
  code=$?
fi
if [[ "$code" -ne 0 ]] && cmp -s "$scratch/copy/src/bin/mhfe/cell_widths.rs" "$scratch/changed.rs"
then
  echo "PASS generate-cell-widths-misspelled-check: refused (exit $code), table left as it was"
else
  echo "FAIL generate-cell-widths-misspelled-check: exit $code; $(tail -1 "$scratch/out")"
  failed=1
fi

exit "$failed"
