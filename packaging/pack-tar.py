"""Pack a directory deterministically with macOS's existing Python 3.

TOOL-01: Python's standard library supplies tar/gzip writers absent from
Node's standard library; no package manager runs in the macOS build.
Usage: python3 packaging/pack-tar.py <source-directory> <archive.tar.gz>
"""

import gzip
from pathlib import Path
import sys
import tarfile


def pack(source, destination):
    """Fix order, modes, timestamps and ownership before compression."""
    children = sorted(source.rglob("*"), key=lambda path: path.relative_to(source).as_posix())
    paths = [source, *children]
    with destination.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
                for path in paths:
                    name = "." if path == source else "./" + path.relative_to(source).as_posix()
                    item = archive.gettarinfo(str(path), arcname=name)
                    if not (item.isfile() or item.isdir()):
                        raise ValueError(f"Release input is not a file or directory: {name}")
                    item.uid = item.gid = item.mtime = 0
                    item.uname = item.gname = ""
                    item.mode = 0o755 if item.isdir() or item.mode & 0o111 else 0o644
                    item.pax_headers = {}
                    if item.isfile():
                        with path.open("rb") as content:
                            archive.addfile(item, content)
                    else:
                        archive.addfile(item)


def main(arguments):
    """Reject argument mistakes before creating an output file."""
    if len(arguments) != 2 or any(arg.startswith("--") for arg in arguments):
        print(__doc__.splitlines()[-1], file=sys.stderr)
        return 2
    source, destination = map(Path, arguments)
    inside = destination.resolve().is_relative_to(source.resolve())
    if not source.is_dir() or inside:
        print("The source must be a directory; put the archive outside it.", file=sys.stderr)
        return 2
    pack(source, destination)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
