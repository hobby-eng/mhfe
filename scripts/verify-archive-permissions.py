"""Check the normalized modes of the archive-packing gate's synthetic
tar/zip files.

TOOL-01: Python's standard library supplies readers for both archive
formats.
Usage: python3 scripts/verify-archive-permissions.py <tar.gz> <zip>
"""
import sys
import tarfile
import zipfile

EXECUTABLE = {"mhfe", "mhfe-launch.sh"}
DIRECTORIES = {"", ".", "licenses"}
MINIMUM_MEMBERS = 10  # The packing fixture's files and folders in both formats.


def check_modes(tar_path, zip_path):
    """Both formats store the fixture's normalized file and directory
    modes.
    """
    found = {}
    with tarfile.open(tar_path) as packed:
        for member in packed.getmembers():
            found[("tar", member.name.removeprefix("./"))] = member.mode
    with zipfile.ZipFile(zip_path) as packed:
        for member in packed.infolist():
            found[("zip", member.filename.removeprefix("./"))] = (
                member.external_attr >> 16) & 0o7777
    wrong = [
        f"{kind} {name or '.'}: {mode:o}"
        for (kind, name), mode in sorted(found.items())
        if mode != (0o755 if name in EXECUTABLE or name in DIRECTORIES else 0o644)
    ]
    if wrong or len(found) < MINIMUM_MEMBERS:
        print(f"The archives list other permission bits: {wrong or found}", file=sys.stderr)
        return 1
    return 0


def main(arguments):
    """Refuse argument mistakes before opening any archive."""
    if len(arguments) != 2 or any(arg.startswith("--") for arg in arguments):
        print(__doc__.splitlines()[-1], file=sys.stderr)
        return 2
    return check_modes(*arguments)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
