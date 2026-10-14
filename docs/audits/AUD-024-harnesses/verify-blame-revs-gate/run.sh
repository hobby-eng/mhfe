#!/usr/bin/env bash
# AUD-024 verifier harness (commit b6fca69): does the .git-blame-ignore-revs check of
# scripts/check.sh refuse exactly what git blame refuses? It runs the check's own loop, taken from
# scripts/check.sh with only the file name replaced, and git blame (with --ignore-revs-file and
# with blame.ignoreRevsFile) on scratch lists. Exits 1 when the check and git blame disagree.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
scratch="${AUD024_SCRATCH:-$(mktemp -d)}"
mkdir -p "$scratch"
start="$(grep -nx 'while read -r hash; do' scripts/check.sh | cut -d: -f1)"
end="$(grep -nxF "done < <(grep -Ev '^(#|\$)' .git-blame-ignore-revs)" scripts/check.sh | cut -d: -f1)"
if [ -z "$start" ] || [ -z "$end" ]; then echo "the loop of scripts/check.sh was not found"; exit 2; fi
loop="$(sed -n "${start},${end}p" scripts/check.sh)"
echo "HEAD $(git rev-parse HEAD); $(git --version); scripts/check.sh:$start-$end"
body="${loop//.git-blame-ignore-revs/\"\$1\"}"

gate() { bash -c "set -euo pipefail; $body" gate "$1" >/dev/null 2>&1; }
blame() { git blame --ignore-revs-file "$1" -- README.md >/dev/null 2>"$scratch/err" &&
  git -c blame.ignoreRevsFile="$1" blame -- README.md >/dev/null 2>>"$scratch/err"; }

full=f6067310e5acae95b02b5bc96d78007426c8d15a
failed=0
check() { # name, file
  local g=refuses b=refuses
  gate "$2" && g=accepts
  blame "$2" && b=accepts
  if [ "$g" = "$b" ]; then echo "PASS   $1: check $g, git blame $b"
  else echo "DEFECT $1: check $g, git blame $b ($(head -1 "$scratch/err" | sed "s|$scratch|<scratch>|g"))"; failed=1; fi
}
mk() { printf '%b' "$2" > "$scratch/$1"; echo "$scratch/$1"; }
check "full hash"             "$(mk full "# c\n\n$full\n")"
check "abbreviated 12 digits" "$(mk abbr12 "${full:0:12}\n")"
check "abbreviated 7 digits"  "$(mk abbr7 "${full:0:7}\n")"
check "ref name HEAD~3"       "$(mk ref "HEAD~3\n")"
check "tag name v0.6.0"       "$(mk tag "v0.6.0\n")"
check "full hash, # comment"  "$(mk trailing "$full # the Prettier reformat\n")"
check "full hash, CRLF"       "$(mk crlf "$full\r\n")"
check "indented # comment"    "$(mk indent "  # c\n$full\n")"
rm -f "$scratch/missing"
check "missing file"          "$scratch/missing"
exit "$failed"
