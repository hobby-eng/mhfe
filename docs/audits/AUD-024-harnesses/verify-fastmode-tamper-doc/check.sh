#!/usr/bin/env bash
# AUD-024 harness (commit b6fca69): the browser guide must not present the page's
# mhfe-fast-mode.sha256 as protection against deliberate tampering, because both fast-mode
# launchers verify and serve a replaced page whose checksum file was rewritten beside it.
# Usage, from the repository root:
#   docs/audits/AUD-024-harnesses/verify-fastmode-tamper-doc/check.sh <mhfe binary> <work folder>
# Exit 0: the guide makes no such claim. Exit 1: it does (the defect). Exit 2: a precondition failed.
set -u
mhfe="$1"; work="$2"; repo="$(pwd)"
[ -f "$repo/docs/BROWSER-PACKAGE.md" ] || { echo "run from the repository root"; exit 2; }
rm -rf "$work"; mkdir -p "$work"; cd "$work"
printf '<!doctype html><title>replaced</title><script>/* replaced code */</script>\n' > tool.html
sha256sum tool.html > mhfe-fast-mode.sha256
for launcher in rust python; do
  if [ "$launcher" = rust ]; then cmd=("$mhfe" serve --no-browser tool.html)
  else cmd=(python3 "$repo/packaging/mhfe-fast-mode.py" --no-browser tool.html); fi
  out="$(NO_COLOR=1 timeout 3 "${cmd[@]}" </dev/null 2>&1)"
  case "$out" in
    *"SHA-256 of tool.html verified"*"Fast mode is running"*)
      echo "$launcher launcher: replaced page with rewritten checksum file verified and served";;
    *) echo "$launcher launcher: did not serve the replaced page (precondition changed):"; echo "$out"; exit 2;;
  esac
done
bullet="$(awk '/^- Deliberate tampering/{p=1; print; next} p&&(/^- /||/^$/){exit} p' "$repo/docs/BROWSER-PACKAGE.md")"
printf 'BROWSER-PACKAGE.md bullet:\n%s\n' "$bullet"
if printf '%s' "$bullet" | tr '\n' ' ' | grep -q 'Tampering is for.*mhfe-fast-mode\.sha256'; then
  echo "FAIL: the guide lists mhfe-fast-mode.sha256 as tamper protection; SECURITY.md says it is not"
  exit 1
fi
echo "PASS"
