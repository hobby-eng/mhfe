#!/usr/bin/env bash
# The read-only facts behind the arc-doc findings of AUD-044, each from a command that can be run
# again at the commit. Run from the repository root; changes nothing.
set -uo pipefail

guide="${1:?usage: facts.sh <multi-chain-wallet-tools folder>}"

section() { printf '\n=== %s\n' "$1"; }
code_lines() { grep -cvE '^\s*(//.*)?$'; }

section "Commit"
git rev-parse HEAD

section "Commits and records the tree cites"
git cat-file -t ff8365c5ef3007525ec5f71f374465aa47c630fd 2>&1 | head -1
git cat-file -t f6067310e5acae95b02b5bc96d78007426c8d15a
ls docs/audits | grep -E '^audit-.*\.md$' | tail -1
git grep -n 'AUD-043' -- ':!docs/audits' ':!tests/spec'
git grep -n -E 'G10|self-check plan|the plan' -- src ':!src/mhfe/published_rounds.rs' | grep -v 'g10::' | cut -c1-90

section "Lines of code (CORE-15), Rust files up to their test module"
for entry in src/wasm_api/core.rs:0 src/wallet.rs:1186 src/wallet/known_answers.rs:1041 \
  src/bin/mhfe/check.rs:1010; do
  file="${entry%%:*}"
  start="${entry##*:}"
  if [ "$start" = 0 ]; then
    printf '%s %s\n' "$file" "$(code_lines <"$file")"
  else
    printf '%s %s\n' "$file" "$(head -n $((start - 1)) "$file" | code_lines)"
  fi
done
python3 -I - <<'PY'
import pathlib
import re

text = pathlib.Path("web/client.js").read_text()
body = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
print("web/client.js", sum(1 for line in body.splitlines()
                           if line.strip() and not line.strip().startswith("//")))
text = pathlib.Path("scripts/verify-hidden-input.py").read_text()
body = re.sub(r'"""[\s\S]*?"""', "", text)
print("scripts/verify-hidden-input.py", sum(1 for line in body.splitlines()
                                            if line.strip() and not line.strip().startswith("#")))
PY
git grep -n -E '^(//|#|/\*).{0,4}long: ' -- src web scripts xtask || echo "no 'long:' exception"
grep -n 'code-rules' xtask/src/main.rs || echo "no code-rules task"

section "Unicode version of the password rule, v0.6.0 and now, and the draft notes"
git show v0.6.0:README.md | grep -n 'Unicode 17' | head -2 | cut -c1-90
grep -n 'Unicode 18' README.md | head -1 | cut -c1-90
grep -n 'Unicode' docs/releases/unreleased.md | cut -c1-90
grep -n -E 'xtask|Node|dprint' docs/releases/unreleased.md || echo "no word of xtask, Node or dprint"

section "Procedure files against docs/audits/procedure-changes.json"
sha256sum "$guide/docs/FULL_AUDIT_GUIDE.md" "$guide/docs/audits/AUDIT_STANDARD.md" \
  "$guide/docs/audit-report.schema.json" | sed 's/  .*\//  /'
grep -c '"file"' docs/audits/procedure-changes.json
printf 'record files that pin AUDIT_STANDARD 9128a5e2: %s\n' \
  "$(git grep -l 9128a5e243ec5de8 -- 'docs/audits/audit-*' | wc -l)"
printf 'record files that pin the schema d47df012: %s\n' \
  "$(git grep -l d47df012 -- 'docs/audits/audit-*' | wc -l)"
grep -n '"file"' "$guide/docs/audits/procedure-changes.json" | cut -c1-70

section "Words the glossaries avoid"
git grep -n -w -E 'boundary|boundaries' -- src SECURITY.md | grep -v -E 'strength.rs|[Tt]rust boundar' | cut -c1-90
git grep -n -i -E 'expected values?\b' -- src tests/validation_cases.rs | cut -c1-90
git grep -n -i -E '16-bit source check' -- src web docs/API.md docs/BROWSER-PACKAGE.md | wc -l
git grep -n -i -E 'encrypted phrase' -- src docs/BROWSER-PACKAGE.md | cut -c1-90

section "Dead or test-only items"
git grep -n 'packageVersion' -- web | cut -c1-80
git grep -n 'LockProbe' -- src ':!src/memory.rs' | cut -c1-80
git grep -n -E '\b(check_container|recover_confirmed|require_passed)\b|\.warnings\(\)' -- src | cut -c1-80

section "Provenance of 73c5da0a in the comments"
git grep -n -E 'published by BIP-0084|published value|BIP32 test vectors\)|published vectors of BIP44' -- src | cut -c1-100
