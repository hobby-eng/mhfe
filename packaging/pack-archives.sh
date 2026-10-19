# Sourced, not run, by scripts/package-release.sh, which packs every release archive with it, and
# by scripts/verify-archive-packing.sh, which checks it. Uses Python 3 on macOS; elsewhere GNU tar
# (as $tar_command) and gzip. ZIP archives need zip.
#
# An archive's bytes must depend on its content alone, never on the builder: file order, times and
# owners are fixed, and so are the permission bits. Docker's COPY keeps the bits of the checkout,
# which git writes through the umask of whoever checked it out, so under umask 077 every file would
# arrive as 0600 and the archives would differ from a build under umask 022 (AUD-023-BLD002).
# Every file is therefore given the same bits before it is packed, by one rule for both kinds of
# archive: readable by all and writable by the owner alone, executable by all where it is
# executable at all, as a checkout under umask 022 gives them.
#
# no set -euo pipefail: sourced, not run; the scripts that source it set it themselves.
ARCHIVE_MODES="u+rwX,go+rX,go-w"

# Packs the content of `folder` into the gzip-compressed tar archive `archive`.
pack_tar() {
  local folder="$1" archive="$2"
  chmod -R "$ARCHIVE_MODES" "$folder"
  if [[ "$(uname -s)" == Darwin ]]; then
    pack_tar_portable "$folder" "$archive"
    return
  fi
  "$tar_command" --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
    -C "$folder" -cf - . | gzip -n > "$archive"
}

# The macOS runner already provides Python: no Homebrew install may alter an attested build job.
# repo_root is the checkout of the caller that sourced this file.
pack_tar_portable() {
  python3 "$repo_root/packaging/pack-tar.py" "$1" "$2"
}

# Packs the content of `folder` into the zip archive `archive`, an absolute path.
pack_zip() (
  local folder="$1" archive="$2"
  local temporary
  if [[ -d "$archive" ]]; then
    echo "The ZIP destination must be a file, not a directory." >&2
    return 1
  fi
  temporary="$(mktemp -d "${archive}.XXXXXX")" || return
  trap 'rm -f -- "$temporary/archive.zip"; rmdir -- "$temporary"' EXIT
  chmod -R "$ARCHIVE_MODES" "$folder" || return
  # zip stores local times from 1980 on; UTC and one fixed time make it reproducible.
  # A fresh archive drops obsolete entries; replacing it only after success preserves an old one.
  (
    cd "$folder" || exit
    export TZ=UTC
    find . -exec touch -d '1980-01-01 00:00:00' {} + || exit
    find . -type f | LC_ALL=C sort | zip -X -q "$temporary/archive.zip" -@
  ) || return
  mv -f -- "$temporary/archive.zip" "$archive"
)
