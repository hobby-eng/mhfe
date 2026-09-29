#!/usr/bin/env bash
# Packs release archives with fixed timestamps, owners and file order, so that two builds of the
# same source give identical bytes.
#
#   scripts/package-release.sh <version> <output folder> [package ...]
#
# Packages: linux-x86_64, linux-aarch64, windows-x86_64, macos-x86_64, macos-aarch64, browser,
# and linux-x86_64-ssse3, windows-x86_64-ssse3, macos-x86_64-ssse3, built with `--features ssse3
# --target-dir target/ssse3`. Without a list it packs the six that Dockerfile.reproducible builds. Build first: the
# command-line tools with `cargo build --release [--target ...]`, the browser package with
# scripts/build-wasm.sh. Needs GNU tar, gzip, zip and sha256sum.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

version="$1"
output="$(mkdir -p "$2" && cd "$2" && pwd)"
shift 2
packages=("$@")
if [[ ${#packages[@]} -eq 0 ]]; then
  packages=(linux-x86_64 linux-x86_64-ssse3 linux-aarch64 windows-x86_64 windows-x86_64-ssse3 browser)
fi
tar_command="$(command -v gtar || command -v tar)"
staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT

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
  cp LICENSE THIRD_PARTY_NOTICES.md "$folder/"
  mkdir -p "$folder/licenses"
  cp vendor/phc-winner-argon2/LICENSE "$folder/licenses/argon2-LICENSE"
  cp vendor/eff-large-wordlist.md "$folder/licenses/eff-large-wordlist.md"
  {
    echo "mhfe $version"
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
}

cli_package() {
  local name="$1" binary="$2" launcher="$3"
  local folder="$staging/$name"
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
    linux-x86_64) cli_package "$package" target/release/mhfe packaging/mhfe-fast-mode.sh ;;
    linux-aarch64)
      cli_package "$package" target/aarch64-unknown-linux-gnu/release/mhfe packaging/mhfe-fast-mode.sh
      ;;
    windows-x86_64)
      cli_package "$package" target/x86_64-pc-windows-gnu/release/mhfe.exe packaging/mhfe-fast-mode.bat
      ;;
    macos-x86_64)
      cli_package "$package" target/x86_64-apple-darwin/release/mhfe packaging/mhfe-fast-mode.command
      ;;
    linux-x86_64-ssse3) cli_package "$package" target/ssse3/release/mhfe packaging/mhfe-fast-mode.sh ;;
    windows-x86_64-ssse3)
      cli_package "$package" target/ssse3/x86_64-pc-windows-gnu/release/mhfe.exe \
        packaging/mhfe-fast-mode.bat
      ;;
    macos-x86_64-ssse3)
      cli_package "$package" target/ssse3/x86_64-apple-darwin/release/mhfe \
        packaging/mhfe-fast-mode.command
      ;;
    macos-aarch64)
      cli_package "$package" target/aarch64-apple-darwin/release/mhfe packaging/mhfe-fast-mode.command
      ;;
    browser)
      folder="$staging/browser"
      mkdir -p "$folder"
      cp -R dist/. "$folder/"
      add_common_files "$folder"
      # The package's own README lists the SHA-256 of every file; check that it is still there
      # and that the files in the archive match it.
      (cd "$folder" && sed -n '/^## SHA-256 of this build$/,$p' README.md | grep -E '^[0-9a-f]{64}  ' |
        sha256sum --check --quiet --strict -)
      echo "Emscripten 6.0.10" >> "$folder/BUILD-INFO.txt"
      pack_tar "$folder" "mhfe-$version-browser.tar.gz"
      ;;
    *)
      echo "Unknown package $package" >&2
      exit 1
      ;;
  esac
done

(cd "$output" && sha256sum -- *.tar.gz *.zip 2>/dev/null > SHA256SUMS || true)
echo "Release archives in $output:"
cat "$output/SHA256SUMS"
