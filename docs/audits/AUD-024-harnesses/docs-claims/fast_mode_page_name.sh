#!/usr/bin/env bash
# AUD-024 docs-claims: a checksum file in the format that `mhfe serve --help`, SECURITY.md and
# docs/BROWSER-PACKAGE.md describe (the page's SHA-256, two spaces and its file name) must either
# be served or be refused with the real reason. Both launchers refuse a page whose name does not
# end in lower-case ".html" with the message that the file must hold that format. Exits 1 when a
# launcher gives the format message for a well-formed line (the defect), 0 otherwise.
#
#   docs/audits/AUD-024-harnesses/docs-claims/fast_mode_page_name.sh <path to mhfe>
# Run from the repository root (it uses packaging/mhfe-fast-mode.py). With --no-browser, a launcher
# that accepts the page serves on 127.0.0.1 until the 5 s timeout ends it.
set -u
mhfe="${1:?usage: fast_mode_page_name.sh <path to mhfe>}"
export NO_COLOR=1
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failed=0
for name in tool.htm Tool.HTML; do
  dir="$work/$name.d"
  mkdir -p "$dir"
  printf '<!doctype html><title>t</title>' > "$dir/$name"
  (cd "$dir" && sha256sum "$name" > mhfe-fast-mode.sha256)
  for launcher in "$mhfe serve" "python3 packaging/mhfe-fast-mode.py"; do
    # shellcheck disable=SC2086
    output="$(timeout 5 $launcher --no-browser "$dir/$name" < /dev/null 2>&1)"
    if printf '%s' "$output" | grep -q "must hold"; then
      echo "FORMAT MESSAGE for a well-formed line (defect): $launcher, page $name"
      printf '%s\n' "$output" | sed 's/^/    /'
      failed=1
    else
      echo "served or refused for its real reason: $launcher, page $name"
    fi
  done
done
exit "$failed"
