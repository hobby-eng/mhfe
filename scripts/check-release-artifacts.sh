#!/usr/bin/env bash
# Checks what a release ships.
#
#   scripts/check-release-artifacts.sh
#
# proves that the cheap Argon2 engine for fast unit tests is absent from the release binary and the
# browser package's WebAssembly, and that neither names a directory of the builder. The test engine
# exists only under #[cfg(test)] and carries a marker text (REDUCED_COST_MARKER in
# src/engine/native.rs). The marker must be present in the library's test binary, which shows that
# the search works, and absent from <cargo target directory>/release/mhfe and
# dist/runtime/mhfe.wasm. Build them first as scripts/check.sh does: `cargo build --release` after
# remap_builder_paths of packaging/remap-builder-paths.sh, and scripts/build-wasm.sh, which remaps
# the same directories to the same names itself.
#
#   scripts/check-release-artifacts.sh --builder-paths <file> ...
#
# checks only that no file names a directory of the builder: the repository, CARGO_HOME,
# RUSTUP_HOME or the home directory. scripts/package-release.sh runs it on every program and
# WebAssembly it packs.
#
#   scripts/check-release-artifacts.sh --archives <archive> ...
#
# checks packed release archives instead: each must carry LICENSE and THIRD_PARTY_NOTICES.md, byte
# for byte as in this checkout. scripts/package-release.sh runs it on every archive it packs.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
. packaging/remap-builder-paths.sh

# Fails when a file names a directory of this builder. rustc writes the source path of every panic
# location into a program, and only the remapping of packaging/remap-builder-paths.sh keeps the
# builder's account name and directory layout out of a release.
refuse_builder_paths() {
  local file directory count failed=0
  for file in "$@"; do
    if [[ ! -f "$file" ]]; then
      echo "Missing $file; build the release artifacts first." >&2
      return 1
    fi
    while IFS= read -r directory; do
      # grep finds nothing in a clean file and then fails, which is the expected case.
      count="$(grep -a -o -F -- "$directory/" "$file" | wc -l || true)"
      if ((count > 0)); then
        echo "$file names $((count)) paths under $directory, a directory of this builder. Build" \
          "it with the paths remapped (packaging/remap-builder-paths.sh)." >&2
        failed=1
      fi
    done < <(builder_directories "$repo_root")
  done
  return "$failed"
}

if [[ "${1:-}" == "--builder-paths" ]]; then
  shift
  if [[ $# -eq 0 ]]; then
    echo "--builder-paths needs at least one file." >&2
    exit 1
  fi
  refuse_builder_paths "$@"
  echo "No file names a directory of this builder: $# checked."
  exit 0
fi

if [[ "${1:-}" == "--archives" ]]; then
  shift
  if [[ $# -eq 0 ]]; then
    echo "--archives needs at least one archive." >&2
    exit 1
  fi
  # Python's tarfile and zipfile read both archive kinds the same way on every build machine.
  python3 - "$@" <<'PY'
import pathlib
import sys
import tarfile
import zipfile

REQUIRED = ("LICENSE", "THIRD_PARTY_NOTICES.md")


def members(archive):
    """The archive's files, by path without a leading "./"."""
    if archive.endswith(".zip"):
        with zipfile.ZipFile(archive) as packed:
            return {name.removeprefix("./"): packed.read(name) for name in packed.namelist()}
    with tarfile.open(archive) as packed:
        return {
            member.name.removeprefix("./"): packed.extractfile(member).read()
            for member in packed.getmembers()
            if member.isfile()
        }


failed = False
for archive in sys.argv[1:]:
    files = members(archive)
    for name in REQUIRED:
        if files.get(name) != pathlib.Path(name).read_bytes():
            print(f"{archive} lacks {name} or holds another version of it.", file=sys.stderr)
            failed = True
if failed:
    sys.exit(1)
print(f"Every archive carries the licence files: {len(sys.argv) - 1} checked.")
PY
  exit 0
fi

marker="MHFE-TEST-ONLY-REDUCED-ARGON2-COST"
# CARGO_TARGET_DIR may move the release binary out of target/.
target_dir="$(
  cargo metadata --locked --no-deps --format-version 1 |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'
)"
release_artifacts=("$target_dir/release/mhfe" dist/runtime/mhfe.wasm)

test_binary="$(
  cargo test --locked --lib --no-run --message-format=json 2>/dev/null |
    python3 -c '
import json, sys
for line in sys.stdin:
    message = json.loads(line)
    if message.get("reason") == "compiler-artifact" and message.get("executable") \
            and message["target"]["name"] == "mhfe":
        print(message["executable"])
'
)"
if ! grep -q --binary-files=binary "$marker" "$test_binary"; then
  echo "The marker is missing from the test binary $test_binary, so this check proves nothing." >&2
  exit 1
fi

for artifact in "${release_artifacts[@]}"; do
  if [[ ! -f "$artifact" ]]; then
    echo "Missing $artifact; build the release artifacts first." >&2
    exit 1
  fi
  if grep -q --binary-files=binary "$marker" "$artifact"; then
    echo "$artifact contains the test-only reduced Argon2 engine." >&2
    exit 1
  fi
done
refuse_builder_paths "${release_artifacts[@]}"
echo "The test-only reduced Argon2 engine is in the test binary and in no release artifact, and no"
echo "release artifact names a directory of this builder."
