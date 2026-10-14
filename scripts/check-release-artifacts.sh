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
# checks packed release archives instead: each must carry LICENSE-MIT, LICENSE-APACHE and
# THIRD_PARTY_NOTICES.md, byte for byte as in this checkout, and its notices must list every crate
# of the Rust standard library that its programs name. scripts/package-release.sh runs it on every
# archive it packs.
#
# The release program and WebAssembly, and every archive, are refused when they name a crate of
# the standard library that THIRD_PARTY_NOTICES.md does not list
# (`scripts/third-party-licenses.py --binaries`, AUD-023-BLD003).
set -euo pipefail

# Refuse an unknown mode before builds, reads or archive work.
refuse_arguments() {
  echo "Usage: scripts/check-release-artifacts.sh [--builder-paths|--archives <file> ...]" >&2
  exit 2
}
case "${1:-}" in
  "")
    if [[ $# -ne 0 ]]; then
      refuse_arguments
    fi
    ;;
  --builder-paths|--archives)
    if [[ $# -lt 2 ]]; then
      refuse_arguments
    fi
    ;;
  *)
    refuse_arguments
    ;;
esac

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
      # A no-match status is expected; an unreadable file must fail the integrity gate.
      local grep_status=0 matches
      matches="$(grep -a -o -F -- "$directory/" "$file")" || grep_status=$?
      if ((grep_status > 1)); then
        echo "Could not read $file while checking builder paths." >&2
        return 1
      fi
      count=0
      if [[ -n "$matches" ]]; then
        count="$(printf '%s\n' "$matches" | wc -l)"
      fi
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
  python3 scripts/third-party-licenses.py --archives "$@"
  exit 0
fi

marker="MHFE-TEST-ONLY-REDUCED-ARGON2-COST"
# CARGO_TARGET_DIR may move the release binary out of target/.
target_dir="$(
  node scripts/cargo-output.mjs target-directory
)"
release_artifacts=("$target_dir/release/mhfe" dist/runtime/mhfe.wasm)

test_binary="$(
  cargo test --locked --lib --no-run --message-format=json |
    node scripts/cargo-output.mjs test-binary
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
python3 scripts/third-party-licenses.py --binaries "${release_artifacts[@]}"
echo "The test-only reduced Argon2 engine is in the test binary and in no release artifact, and no"
echo "release artifact names a directory of this builder."
