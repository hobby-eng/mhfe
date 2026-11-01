#!/usr/bin/env bash
# Runs pack_zip of scripts/package-release.sh, taken from the script at this commit, on small folders
# under tmp/aud044/bld/probes/zip: (1) the same content with the file modes of a checkout under umask
# 077 and under 022, (2) a repack into an output folder that already holds an archive.
set -euo pipefail
repo=/home/sergio/Documents/bip_tools/mhfe
work=/home/sergio/Documents/bip_tools/tmp/aud044/bld/probes/zip
rm -rf "$work"; mkdir -p "$work"
pack_zip_body="$(sed -n '/^pack_zip() {/,/^}/p' "$repo/scripts/package-release.sh")"
eval "$pack_zip_body"
archives=()
make_folder() {
  mkdir -p "$1/licenses"
  printf 'readme\n' > "$1/README.md"; printf 'lic\n' > "$1/licenses/argon2-LICENSE"
  chmod "$2" "$1/README.md" "$1/licenses/argon2-LICENSE"
}
echo "== modes: the same bytes, a checkout with 0644 against one with 0600"
output="$work/a"; mkdir -p "$output"; make_folder "$work/f644" 0644; pack_zip "$work/f644" same.zip
output="$work/b"; mkdir -p "$output"; make_folder "$work/f600" 0600; pack_zip "$work/f600" same.zip
sha256sum "$work/a/same.zip" "$work/b/same.zip"
python3 -I - "$work/a/same.zip" "$work/b/same.zip" <<'PY'
import sys, zipfile
for path in sys.argv[1:]:
    with zipfile.ZipFile(path) as z:
        print(path.split("/")[-2], [(i.filename, oct(i.external_attr >> 16)) for i in z.infolist()])
PY
echo "== repack: an older archive in the output folder"
output="$work/c"; mkdir -p "$output"
make_folder "$work/old" 0644; printf 'obsolete\n' > "$work/old/mhfe-old.exe"; pack_zip "$work/old" repack.zip
make_folder "$work/new" 0644; pack_zip "$work/new" repack.zip
unzip -Z1 "$output/repack.zip"
