"""MinGW runtime notice rules shared by the binary/archive licence gate.

TOOL-01: the parent licence checker uses Python's archive readers.
This is a support module of third-party-licenses.py, not an entry point.
"""

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "vendor/mingw-w64-runtime-COPYRIGHT"
SOURCE_SHA256 = "af23297b7d17e8e31817a5d58088de6fdafe34705bb5a7d1d330f08711b31314"
ARCHIVE_PATH = "licenses/mingw-w64-COPYRIGHT"
HEADING = "## MinGW-w64 runtime (Windows)"
# The diagnostic belongs to crt/pseudo-reloc.c, linked into the Windows
# executable even when no relocations fail at runtime.
RUNTIME_MARKER = b"Mingw-w64 runtime failure:"


def source_problems():
    """Bind the source to the pinned package's complete text."""
    if not SOURCE.is_file() or hashlib.sha256(SOURCE.read_bytes()).hexdigest() != SOURCE_SHA256:
        return [f"{SOURCE.name}: missing or changed MinGW runtime copyright source"]
    installed = Path("/usr/share/doc/mingw-w64-x86-64-dev/copyright")
    if installed.is_file() and installed.read_bytes() != SOURCE.read_bytes():
        return ["The installed MinGW runtime copyright differs from the retained source."]
    return []


def problems(files, notices, source, carried=None):
    """Checkout notices cannot fill an archive's gaps."""
    programs = [name for name, data in files.items() if RUNTIME_MARKER in data]
    if not programs:
        return []
    found = []
    if HEADING not in notices:
        found.append(f"{source}: MinGW runtime code lacks its notice ({', '.join(programs)})")
    if carried is not None and carried.get(ARCHIVE_PATH) != SOURCE.read_bytes():
        found.append(f"{source}: missing or altered {ARCHIVE_PATH}")
    return found


def self_test():
    """Distinguish missing, altered and complete notices."""
    files = {"mhfe.exe": RUNTIME_MARKER}
    cases = [
        ("", {}, 2),
        (HEADING, {}, 1),
        (HEADING, {ARCHIVE_PATH: b"changed"}, 1),
        (HEADING, {ARCHIVE_PATH: SOURCE.read_bytes()}, 0),
    ]
    for notices, carried, expected in cases:
        found = problems(files, notices, "synthetic archive", carried)
        if len(found) != expected:
            raise ValueError(f"MinGW notice self-test: expected {expected} refusals, got {found}")
    if problems({"mhfe": b"ELF synthetic program"}, "", "non-MinGW archive", {}):
        raise ValueError("MinGW notices were required for a non-MinGW binary")
