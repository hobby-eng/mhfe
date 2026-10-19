#!/usr/bin/env bash
# Checks that a release archive's bytes depend on its content alone (AUD-023-BLD002): the same files
# packed by packaging/pack-archives.sh, the code scripts/package-release.sh packs every archive
# with, give the same tar.gz and the same zip whatever permission bits a checkout gave them under
# umask 022, 002, 027 or 077, and each archive lists them with the bits of a checkout under umask
# 022. Both the canonical and macOS tar packers are checked. Needs GNU tar, gzip, zip and Python 3.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
tar_command="$(command -v gtar || command -v tar)"
. packaging/pack-archives.sh

mkdir -p target
scratch="$(mktemp -d "$repo_root/target/archive-packing.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

# A staging folder as a checkout under `umask` gives it: two documents, a licence in a subfolder, a
# launcher that git marks executable and a program the build made executable. Each archive kind
# gets a folder of its own, named after it, since packing fixes the bits of the folder it packs.
stage() {
  local umask="$1" folder="$scratch/stage-$1-$2"
  (
    umask "$umask"
    mkdir -p "$folder/licenses"
    printf 'The project overview.\n' > "$folder/README.md"
    printf 'A licence text.\n' > "$folder/licenses/LICENSE"
    printf 'mhfe 1.0\n' > "$folder/BUILD-INFO.txt"
    printf '#!/bin/sh\n' > "$folder/mhfe-launch.sh"
    printf 'a program\n' > "$folder/mhfe"
    chmod "$(printf '%o' $((0777 & ~8#$umask)))" "$folder/mhfe-launch.sh"
  )
  # The program is copied in by the container, whose umask is 022.
  chmod 0755 "$folder/mhfe"
  echo "$folder"
}

failed=0
reference=""
for umask in 022 002 027 077; do
  pack_tar "$(stage "$umask" tar)" "$scratch/$umask.tar.gz"
  pack_tar_portable "$(stage "$umask" portable)" "$scratch/$umask-portable.tar.gz"
  pack_zip "$(stage "$umask" zip)" "$scratch/$umask.zip"
  sums="$(cd "$scratch" && sha256sum "$umask.tar.gz" "$umask-portable.tar.gz" "$umask.zip" |
    cut -d ' ' -f 1 | tr '\n' ' ')"
  if [[ -z "$reference" ]]; then
    reference="$sums"
  elif [[ "$sums" != "$reference" ]]; then
    echo "A checkout under umask $umask gives other archive bytes than under umask 022." >&2
    failed=1
  fi
done

# The bits each archive lists: 0644 for a file, 0755 for a program, a launcher and a folder.
python3 scripts/verify-archive-permissions.py "$scratch/022.tar.gz" "$scratch/022.zip" || failed=1
python3 scripts/verify-archive-permissions.py "$scratch/022-portable.tar.gz" "$scratch/022.zip" || failed=1

mkdir -p "$scratch/repack"
printf 'Old content.\n' > "$scratch/repack/current.txt"
printf 'Obsolete content.\n' > "$scratch/repack/obsolete.txt"
pack_zip "$scratch/repack" "$scratch/repacked.zip"
rm "$scratch/repack/obsolete.txt"
printf 'Changed content.\n' > "$scratch/repack/current.txt"
printf 'Added content.\n' > "$scratch/repack/added.txt"
pack_zip "$scratch/repack" "$scratch/repacked.zip"
pack_zip "$scratch/repack" "$scratch/fresh.zip"
cmp "$scratch/repacked.zip" "$scratch/fresh.zip" || failed=1
python3 - "$scratch/repacked.zip" <<'PY' || failed=1
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as archive:
    expected = {
        'added.txt': b'Added content.\n',
        'current.txt': b'Changed content.\n',
    }
    if archive.namelist() != list(expected):
        raise SystemExit('The repacked ZIP has stale or unexpected entries')
    for name, content in expected.items():
        if archive.read(name) != content:
            raise SystemExit('The repacked ZIP has incorrect content')
PY

cp "$scratch/repacked.zip" "$scratch/previous.zip"
if (
  zip() {
    printf 'A partial failed archive.\n' > "$3"
    return 77
  }
  pack_zip "$scratch/repack" "$scratch/repacked.zip"
); then
  echo "The packer accepted a failed ZIP command." >&2
  failed=1
fi
cmp "$scratch/repacked.zip" "$scratch/previous.zip" || {
  echo "A failed ZIP command replaced the previous archive." >&2
  failed=1
}

if ((failed)); then
  exit 1
fi
echo "Archives packed from checkouts under umask 022, 002, 027 and 077 are identical."
echo "ZIP repacking replaces stale entries and preserves the previous archive on failure."
