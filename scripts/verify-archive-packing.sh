#!/usr/bin/env bash
# Checks that a release archive's bytes depend on its content alone (AUD-023-BLD002): the same files
# packed by packaging/pack-archives.sh, the code scripts/package-release.sh packs every archive
# with, give the same tar.gz and the same zip whatever permission bits a checkout gave them under
# umask 022, 002, 027 or 077, and each archive lists them with the bits of a checkout under umask
# 022. Needs GNU tar, gzip, zip and Python 3.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
tar_command="$(command -v gtar || command -v tar)"
. packaging/pack-archives.sh

scratch="$(mktemp -d)"
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
  pack_zip "$(stage "$umask" zip)" "$scratch/$umask.zip"
  sums="$(cd "$scratch" && sha256sum "$umask.tar.gz" "$umask.zip" | cut -d ' ' -f 1 | tr '\n' ' ')"
  if [[ -z "$reference" ]]; then
    reference="$sums"
  elif [[ "$sums" != "$reference" ]]; then
    echo "A checkout under umask $umask gives other archive bytes than under umask 022." >&2
    failed=1
  fi
done

# The bits each archive lists: 0644 for a file, 0755 for a program, a launcher and a folder.
python3 - "$scratch/022.tar.gz" "$scratch/022.zip" <<'PY' || failed=1
import sys
import tarfile
import zipfile

EXECUTABLE = {"mhfe", "mhfe-launch.sh"}
found = {}
with tarfile.open(sys.argv[1]) as packed:
    for member in packed.getmembers():
        found[("tar", member.name.removeprefix("./"))] = member.mode
with zipfile.ZipFile(sys.argv[2]) as packed:
    for member in packed.infolist():
        found[("zip", member.filename.removeprefix("./"))] = (member.external_attr >> 16) & 0o7777
wrong = [
    f"{kind} {name or '.'}: {mode:o}"
    for (kind, name), mode in sorted(found.items())
    if mode != (0o755 if name in EXECUTABLE or name in ("", ".", "licenses") else 0o644)
]
if wrong or len(found) < 10:
    print(f"The archives list other permission bits: {wrong or found}", file=sys.stderr)
    sys.exit(1)
PY

if ((failed)); then
  exit 1
fi
echo "Archives packed from checkouts under umask 022, 002, 027 and 077 are identical."
