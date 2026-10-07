# Sourced, not run, by every build of a program or WebAssembly that a release ships or that
# scripts/check-release-artifacts.sh checks: packaging/Dockerfile.reproducible,
# scripts/package-release.sh, scripts/check.sh and scripts/build-wasm.sh; and by
# scripts/check-release-artifacts.sh itself for the list of directories it refuses. Shell code that
# both dash, the /bin/sh of the Dockerfile, and bash run.
#
# rustc writes the source path of every panic location into a binary or WebAssembly. For the
# crates of the Cargo registry that path lies under CARGO_HOME, so a build would carry the
# builder's account name and directory layout, and a local build would never give the bytes of the
# canonical one. remap_builder_paths makes rustc write these directories under fixed relative
# names instead, the same on every computer and for every target, native programs and the
# WebAssembly alike:
#
#   the repository  ->  mhfe     (the crate's own files are relative already)
#   CARGO_HOME      ->  cargo    (the sources of every dependency: cargo/registry/src/...)
#   RUSTUP_HOME     ->  rustup   (the toolchain, should a path of it appear)
#
# The names are relative, so that no remapped path looks like a directory of some builder;
# scripts/verify-browser-package.mjs refuses a WebAssembly with any absolute source path other than
# rustc's own. rustc names its standard library /rustc/<commit>/ itself. Cargo's trim-paths would
# make such paths relative on its own, but Cargo 1.99.0 still refuses it as unstable.

# The release targets whose rustflags get the remapping, the computer's own target among them for
# a build without --target.
REMAPPED_TARGETS="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-pc-windows-gnu
x86_64-apple-darwin aarch64-apple-darwin wasm32-unknown-unknown"

# The directories of this builder that no release file may name, one per line and without a
# trailing slash: the repository given as $1, CARGO_HOME, RUSTUP_HOME and the home directory.
builder_directories() {
  local directory
  for directory in "$1" "${CARGO_HOME:-${HOME%/}/.cargo}" "${RUSTUP_HOME:-${HOME%/}/.rustup}" \
    "$HOME"; do
    directory="${directory%/}"
    # An empty or root home, as in some containers, names no builder.
    if [ -n "$directory" ]; then
      printf '%s\n' "$directory"
    fi
  done
}

# Adds the remapping for the repository at $1 to CARGO_TARGET_<TRIPLE>_RUSTFLAGS of every release
# target, after the flags already there, such as the MinGW timestamp flag of the Windows build.
# Calling it twice adds nothing, so that a second build sees the same flags and has nothing to redo.
remap_builder_paths() {
  # Cargo takes the first of RUSTFLAGS, CARGO_ENCODED_RUSTFLAGS and the per-target flags that is
  # set, so either of the first two would silently drop the remapping.
  if [ -n "${RUSTFLAGS:-}" ] || [ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]; then
    echo "RUSTFLAGS or CARGO_ENCODED_RUSTFLAGS is set and would replace the remapping of the" \
      "builder's directories; unset it for a release build." >&2
    return 1
  fi
  local cargo_home="${CARGO_HOME:-${HOME%/}/.cargo}"
  local rustup_home="${RUSTUP_HOME:-${HOME%/}/.rustup}"
  local flags="" remapping triple variable current
  # rustc applies the last prefix that matches, so the repository comes first: a CARGO_HOME inside
  # it is still remapped as CARGO_HOME.
  for remapping in "${1%/}=mhfe" "${cargo_home%/}=cargo" "${rustup_home%/}=rustup"; do
    # Cargo splits per-target rustflags at whitespace.
    case "$remapping" in
      *" "* | *"	"*)
        echo "Cannot remap a directory whose name has a space: $remapping" >&2
        return 1
        ;;
    esac
    flags="${flags:+$flags }--remap-path-prefix=$remapping"
  done
  for triple in $REMAPPED_TARGETS; do
    variable="CARGO_TARGET_$(printf '%s' "$triple" | tr 'a-z-' 'A-Z_')_RUSTFLAGS"
    eval "current=\${$variable:-}"
    case " $current " in
      *" $flags "*) ;;
      *) eval "export $variable=\"\${current:+\$current }\$flags\"" ;;
    esac
  done
}
