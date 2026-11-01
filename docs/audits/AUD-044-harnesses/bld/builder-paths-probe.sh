#!/usr/bin/env bash
# scripts/check-release-artifacts.sh --builder-paths on a file that names the home directory, readable
# and then unreadable; and the line of scripts/package-release.sh that writes SHA256SUMS, with one
# archive that sha256sum cannot read. Everything is under tmp/aud044/bld/probes/paths.
set -uo pipefail
repo=/home/sergio/Documents/bip_tools/mhfe
work=/home/sergio/Documents/bip_tools/tmp/aud044/bld/probes/paths
rm -rf "$work"; mkdir -p "$work"
printf 'x%s/secret/path\n' "$HOME" > "$work/names-home.bin"
"$repo/scripts/check-release-artifacts.sh" --builder-paths "$work/names-home.bin"; echo "readable: exit $?"
chmod 000 "$work/names-home.bin"
"$repo/scripts/check-release-artifacts.sh" --builder-paths "$work/names-home.bin"; echo "unreadable: exit $?"
chmod 600 "$work/names-home.bin"
output="$work/out"; mkdir -p "$output"
printf 'a\n' > "$output/mhfe-a.tar.gz"; printf 'b\n' > "$output/mhfe-b.tar.gz"; chmod 000 "$output/mhfe-b.tar.gz"
line="$(grep -n 'sha256sum -- \*.tar.gz' "$repo/scripts/package-release.sh" | cut -d: -f2-)"
echo "the line: $line"
eval "$line"; echo "exit $?"; echo "SHA256SUMS holds:"; cat "$output/SHA256SUMS"
chmod 600 "$output/mhfe-b.tar.gz"
