#!/usr/bin/env bash
# Packs release archives with fixed timestamps, owners and file order, so that two builds of the
# same source give identical bytes.
#
#   scripts/package-release.sh <version> <output folder> [package ...]
#
# Packages: linux-x86_64, linux-aarch64, windows-x86_64, macos-x86_64, macos-aarch64, browser.
# Without a list it packs the four that packaging/Dockerfile.reproducible builds. It builds each
# command-line tool itself (`cargo build --release [--target ...]`) with the builder's directories
# remapped as packaging/remap-builder-paths.sh describes, the same flags as the Dockerfile's, so
# that a program the Dockerfile built is up to date. Build the browser package first with
# scripts/build-wasm.sh, which remaps the same way. A program or WebAssembly that still names a
# directory of the builder is refused. Needs GNU tar, gzip, zip and sha256sum.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

version="$1"
output="$(mkdir -p "$2" && cd "$2" && pwd)"
shift 2
packages=("$@")
if [[ ${#packages[@]} -eq 0 ]]; then
  packages=(linux-x86_64 linux-aarch64 windows-x86_64 browser)
fi
. packaging/remap-builder-paths.sh
remap_builder_paths "$repo_root"
# CARGO_TARGET_DIR may move the programs out of target/.
target_dir="$(
  cargo metadata --locked --no-deps --format-version 1 |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'
)"
tar_command="$(command -v gtar || command -v tar)"
archives=()
staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT

# Documents and licence texts that every archive carries. An archive that brings its own
# README.md, as the browser package does with its integration guide and the SHA-256 of its
# files, keeps it and gets the project overview as README-mhfe.md.
# The commit and the state of the working copy: given by scripts/build-reproducible.sh inside the
# container, which has no .git, or read from git here (the macOS release jobs).
source_commit="${SOURCE_COMMIT:-$(git rev-parse HEAD)}"
source_state="${SOURCE_STATE:-}"
if [[ -z "$source_state" ]]; then
  source_state=clean
  if [[ -n "$(git status --porcelain)" ]]; then
    source_state=modified
  fi
fi

add_common_files() {
  local folder="$1"
  if [[ -e "$folder/README.md" ]]; then
    cp README.md "$folder/README-mhfe.md"
  else
    cp README.md "$folder/"
  fi
  cp LICENSE THIRD_PARTY_NOTICES.md "$folder/"
  mkdir -p "$folder/licenses"
  cp vendor/phc-winner-argon2/LICENSE "$folder/licenses/argon2-LICENSE"
  cp vendor/eff-large-wordlist.md "$folder/licenses/eff-large-wordlist.md"
  {
    echo "mhfe $version"
    echo "source: $source_commit ($source_state)"
    rustc --version --verbose
    wasm-bindgen --version 2>/dev/null || true
    echo "Argon2: vendor/phc-winner-argon2 at f57e61e19229e23c4445b85494dbf7c07de721cb"
  } > "$folder/BUILD-INFO.txt"
}

pack_tar() {
  local folder="$1" archive="$2"
  "$tar_command" --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    --mode='u+rwX,go+rX,go-w' \
    -C "$folder" -cf - . | gzip -n > "$output/$archive"
  archives+=("$output/$archive")
}

pack_zip() {
  local folder="$1" archive="$2"
  # zip stores local times from 1980 on; UTC and one fixed time make it reproducible.
  (
    cd "$folder"
    export TZ=UTC
    find . -exec touch -d '1980-01-01 00:00:00' {} +
    find . -type f | LC_ALL=C sort | zip -X -q "$output/$archive" -@
  )
  archives+=("$output/$archive")
}

# Builds the command-line tool for `triple`, or for this computer without one, and packs it.
cli_package() {
  local name="$1" triple="$2" launcher="$3" program="${4:-mhfe}"
  local folder="$staging/$name" binary
  if [[ -n "$triple" ]]; then
    cargo build --locked --release --target "$triple"
    binary="$target_dir/$triple/release/$program"
  else
    cargo build --locked --release
    binary="$target_dir/release/$program"
  fi
  scripts/check-release-artifacts.sh --builder-paths "$binary"
  mkdir -p "$folder"
  cp "$binary" "$folder/"
  cp "$launcher" "$folder/"
  add_common_files "$folder"
  if [[ "$name" == windows-* ]]; then
    pack_zip "$folder" "mhfe-$version-$name.zip"
  else
    pack_tar "$folder" "mhfe-$version-$name.tar.gz"
  fi
}

for package in "${packages[@]}"; do
  case "$package" in
    # Linux on x86-64 is the computer's own target, as in the Dockerfile's container.
    linux-x86_64) cli_package "$package" "" packaging/mhfe-launch.sh ;;
    linux-aarch64)
      cli_package "$package" aarch64-unknown-linux-gnu packaging/mhfe-launch.sh
      ;;
    windows-x86_64)
      cli_package "$package" x86_64-pc-windows-gnu packaging/mhfe-launch.bat mhfe.exe
      ;;
    macos-x86_64)
      cli_package "$package" x86_64-apple-darwin packaging/mhfe-launch.command
      ;;
    macos-aarch64)
      cli_package "$package" aarch64-apple-darwin packaging/mhfe-launch.command
      ;;
    browser)
      scripts/check-release-artifacts.sh --builder-paths dist/runtime/mhfe.wasm
      folder="$staging/browser"
      mkdir -p "$folder"
      cp -R dist/. "$folder/"
      add_common_files "$folder"
      # The package's own README lists the SHA-256 of every file; check that it is still there
      # and that the files in the archive match it.
      (cd "$folder" && sed -n '/^## SHA-256 of this build$/,$p' README.md | grep -E '^[0-9a-f]{64}  ' |
        sha256sum --check --quiet --strict -)
      echo "Emscripten 6.0.12" >> "$folder/BUILD-INFO.txt"
      pack_tar "$folder" "mhfe-$version-browser.tar.gz"
      ;;
    *)
      echo "Unknown package $package" >&2
      exit 1
      ;;
  esac
done

# Every archive must carry the licence files: LICENSE and THIRD_PARTY_NOTICES.md with its crate list.
scripts/check-release-artifacts.sh --archives "${archives[@]}"

(cd "$output" && sha256sum -- *.tar.gz *.zip 2>/dev/null > SHA256SUMS || true)
echo "Release archives in $output:"
cat "$output/SHA256SUMS"
