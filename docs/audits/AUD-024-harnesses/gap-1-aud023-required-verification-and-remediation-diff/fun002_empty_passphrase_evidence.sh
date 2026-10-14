#!/usr/bin/env bash
# AUD-024, role gap-1 (commit b6fca69): AUD-023-FUN002's required verification asks that "the
# empty-passphrase 16-bit pass keeps its evidence". Builds a copy of the commit whose check
# evidence (evidence_of in src/rehearsal.rs) drops a pass of the 16-bit check made with the empty
# passphrase, then runs the library and command-line unit tests.
#
#   docs/audits/AUD-024-harnesses/gap-1-aud023-required-verification-and-remediation-diff/fun002_empty_passphrase_evidence.sh \
#     <scratch folder> <cargo target folder of its own> [commit]
#
# Exit 0 when a test fails on the mutant (the behaviour is guarded); 1 when every test passes;
# 2 on a setup error. No Argon2 at full size: the unit tests use a reduced cost.
set -uo pipefail
scratch="$1"; target="$2"; commit="${3:-b6fca69}"
tree="$scratch/fun002-mutant"
rm -rf "$tree"; mkdir -p "$tree"
git archive "$commit" | tar -x -C "$tree" || exit 2
python3 - "$tree/src/rehearsal.rs" <<'PY' || exit 2
import sys
path = sys.argv[1]
text = open(path).read()
old = '        other => Some(detection.source_check(other.passphrase().unwrap_or(""))?),\n'
assert text.count(old) == 1, "the evidence line was not found"
new = ('        // MUTANT (AUD-024): a pass with the empty passphrase is dropped.\n'
       '        other => Some(\n'
       '            !other.passphrase().unwrap_or("").is_empty()\n'
       '                && detection.source_check(other.passphrase().unwrap_or(""))?,\n'
       '        ),\n')
open(path, "w").write(text.replace(old, new))
PY
cd "$tree"
export CARGO_TARGET_DIR="$target"
cargo test --locked --lib 2>&1 | grep -E "^test result|FAILED|panicked"
lib=${PIPESTATUS[0]}
cargo test --locked --bin mhfe 2>&1 | grep -E "^test result|FAILED|panicked"
bin=${PIPESTATUS[0]}
if [ "$lib" -ne 0 ] || [ "$bin" -ne 0 ]; then echo "GUARDED: a test fails on the mutant"; exit 0; fi
echo "NOT GUARDED: every library and command-line test passes on the mutant"; exit 1
