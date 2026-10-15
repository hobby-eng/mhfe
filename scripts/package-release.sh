#!/usr/bin/env bash
# Packs release archives with fixed timestamps, owners, permission bits and file order
# (packaging/pack-archives.sh), so that two builds of the same source give identical bytes.
#
#   scripts/package-release.sh <version> <output folder> [package ...]
#
# Packages: linux-x86_64, linux-aarch64, windows-x86_64, macos-x86_64, macos-aarch64, browser.
# Without a list it packs the four that packaging/Dockerfile.reproducible builds. It builds each
# command-line tool itself (`cargo build --release [--target ...]`) with the builder's directories
# remapped as packaging/remap-builder-paths.sh describes, the same flags as the Dockerfile's, so
# that a program the Dockerfile built is up to date. Build the browser package first with
# scripts/build-wasm.sh, which remaps the same way. A program or WebAssembly that still names a
# directory of the builder is refused. Needs GNU tar and gzip (Python 3 on macOS), zip and
# sha256sum.
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
. packaging/pack-archives.sh
# CARGO_TARGET_DIR may move the programs out of target/.
target_dir="$(node scripts/cargo-output.mjs target-directory)"
tar_command="$(command -v gtar || command -v tar)"
archives=()
staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT

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

# The provenance lines of BUILD-INFO.txt, read from their sources: the vendored Argon2 commit as
# vendor/phc-winner-argon2.md records it, and the Emscripten version that
# scripts/build-argon2-wasm.sh, which made the browser package's Argon2 builds, accepts alone.
argon2_commit="$(sed -nE 's/^\| Commit +\| `([0-9a-f]{40})`.*$/\1/p' vendor/phc-winner-argon2.md)"
emscripten_version="$(
  sed -nE 's/^expected_emscripten="([^"]+)"$/\1/p' scripts/build-argon2-wasm.sh
)"
if [[ -z "$argon2_commit" || -z "$emscripten_version" ]]; then
  echo "Cannot read the Argon2 commit or the Emscripten version from their sources." >&2
  exit 1
fi

# Documents and licence texts that every archive carries. An archive that brings its own
# README.md, as the browser package does with its integration guide and the SHA-256 of its
# files, keeps it and gets the project overview as README-mhfe.md.
add_common_files() {
  local folder="$1"
  if [[ -e "$folder/README.md" ]]; then
    cp README.md "$folder/README-mhfe.md"
  else
    cp README.md "$folder/"
  fi
  cp LICENSE-MIT LICENSE-APACHE THIRD_PARTY_NOTICES.md "$folder/"
  mkdir -p "$folder/assets"
  cp assets/mhfe-mascot.png "$folder/assets/"
  mkdir -p "$folder/licenses"
  cp vendor/phc-winner-argon2/LICENSE "$folder/licenses/argon2-LICENSE"
  cp vendor/eff-large-wordlist.md "$folder/licenses/eff-large-wordlist.md"
  {
    echo "mhfe $version"
    echo "source: $source_commit ($source_state)"
    rustc --version --verbose
    wasm-bindgen --version 2>/dev/null || true
    echo "Argon2: vendor/phc-winner-argon2 at $argon2_commit"
    if [[ "$(uname -s)" == Darwin ]]; then
      echo "macOS packaging: Python tarfile/PAX and gzip (mtime 0)"
      python3 -c 'import sys, zlib; print("Python:", sys.version); print("zlib:", zlib.ZLIB_RUNTIME_VERSION)'
      echo "Apple SDK: $(xcrun --show-sdk-version)"
      cc --version | sed -n '1p'
    fi
  } > "$folder/BUILD-INFO.txt"
  node scripts/verify-packaged-readme.mjs "$folder"
}

# Packs `folder` into the archive named `archive` in the output folder, by its kind, with the
# permission bits, times, owners and order fixed by packaging/pack-archives.sh.
pack() {
  local folder="$1" archive="$2"
  if [[ "$archive" == *.zip ]]; then
    pack_zip "$folder" "$output/$archive"
  else
    pack_tar "$folder" "$output/$archive"
  fi
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
  if [[ "$triple" == *-apple-darwin ]]; then
    scripts/harden-macos.sh "$binary"
  fi
  scripts/check-release-artifacts.sh --builder-paths "$binary"
  mkdir -p "$folder"
  cp "$binary" "$folder/"
  cp "$launcher" "$folder/"
  add_common_files "$folder"
  if [[ "$name" == windows-* ]]; then
    cp vendor/mingw-w64-runtime-COPYRIGHT "$folder/licenses/mingw-w64-COPYRIGHT"
  fi
  local kind=tar.gz
  if [[ "$name" == windows-* ]]; then
    kind=zip
  fi
  pack "$folder" "mhfe-$version-$name.$kind"
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
      echo "Emscripten $emscripten_version" >> "$folder/BUILD-INFO.txt"
      pack "$folder" "mhfe-$version-browser.tar.gz"
      ;;
    *)
      echo "Unknown package $package" >&2
      exit 1
      ;;
  esac
done

# Every archive must carry the licence files: LICENSE-MIT, LICENSE-APACHE and THIRD_PARTY_NOTICES.md
# with its crate list.
scripts/check-release-artifacts.sh --archives "${archives[@]}"

(cd "$output" && sha256sum -- "${archives[@]##*/}" > SHA256SUMS)
echo "Release archives in $output:"
cat "$output/SHA256SUMS"
