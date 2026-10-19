"""
Compare canonical payloads without extracting or executing archive
members.

TOOL-01: Python supplies the standard-library gzip/tar/ZIP readers.
The literal catalog records AUD-027's reviewed package, not future
releases.
"""

import datetime
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import tomllib
import zipfile

# Audit inspection budgets include tar headers and padding, not just
# payloads.
ARCHIVE_BYTES = 64 * 1024**2
MEMBER_LIMIT = 256
TEXT_BYTES = 4 * 1024**2
BROWSER_FILES = frozenset("""
README.md modules.json core/argon2-mt.js core/argon2-st.js core/client.d.ts
core/client.js core/mhfe-fast-mode.py passwords/passwords.d.ts
passwords/passwords.js repair/repair.d.ts repair/repair.js runtime/mhfe.wasm
runtime/runtime.d.ts runtime/runtime.js runtime/worker.js wallet/wallet.d.ts
wallet/wallet.js
""".split())
LICENSES = {
    "LICENSE-MIT": "LICENSE-MIT", "LICENSE-APACHE": "LICENSE-APACHE",
    "THIRD_PARTY_NOTICES.md": "THIRD_PARTY_NOTICES.md",
    "licenses/mingw-w64-COPYRIGHT": "vendor/mingw-w64-runtime-COPYRIGHT",
}
BROWSER_COMMON = {
    "LICENSE-MIT": "LICENSE-MIT", "LICENSE-APACHE": "LICENSE-APACHE",
    "THIRD_PARTY_NOTICES.md": "THIRD_PARTY_NOTICES.md",
    "README-mhfe.md": "README.md",
    "assets/mhfe-mascot.png": "assets/mhfe-mascot.png",
    "licenses/argon2-LICENSE": "vendor/phc-winner-argon2/LICENSE",
    "licenses/eff-large-wordlist.md": "vendor/eff-large-wordlist.md",
}


def require(condition, message):
    """Keep acceptance checks active even under Python optimization."""
    if not condition:
        raise ValueError(message)


def file_sha(path):
    """
    Hash files incrementally, including the executable-containing ZIP.
    """
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def member_name(name):
    """
    Refuse alternate or unsafe spellings before catalog comparisons.
    """
    name = name.removeprefix("./").removesuffix("/")
    path = PurePosixPath(name)
    require(not path.is_absolute() and ".." not in path.parts
            and "\\" not in name and "\x00" not in name,
            "An archive has an unsafe member path.")
    require(name in {"", "."} or path.as_posix() == name,
            "An archive has a noncanonical member path.")
    return name


def browser_receipt(path):
    """
    Bound decompression before parsing tar headers or reading members.
    """
    current = {p.relative_to("dist").as_posix(): p
               for p in Path("dist").rglob("*") if p.is_file()}
    require(set(current) == BROWSER_FILES,
            "The local browser catalog differs.")
    with gzip.open(path, "rb") as stream:
        data = stream.read(ARCHIVE_BYTES + 1)
    require(len(data) <= ARCHIVE_BYTES,
            "The tar exceeds the inspection budget.")
    result, names, files = {}, set(), set()
    expected = BROWSER_FILES | BROWSER_COMMON.keys() | {"BUILD-INFO.txt"}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        for member in archive:
            require(len(names) < MEMBER_LIMIT, "Too many browser entries.")
            name = member_name(member.name)
            require(name not in names, "The browser archive repeats a member.")
            names.add(name)
            require(member.isfile() or member.isdir(),
                    "The browser archive has a link or unsupported member.")
            if member.isdir():
                continue
            require(name in expected, "An unexpected browser file exists.")
            require(0 <= member.size <= ARCHIVE_BYTES,
                    "A browser file exceeds the inspection budget.")
            with archive.extractfile(member) as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            files.add(name)
            if name == "BUILD-INFO.txt":
                require(member.size <= TEXT_BYTES,
                        "Browser build info is too large.")
            elif name in BROWSER_FILES:
                require(digest == file_sha(current[name]),
                        "A browser payload differs.")
                result[name] = digest
            else:
                require(digest == file_sha(Path(BROWSER_COMMON[name])),
                        "A browser common file differs.")
    require(files == expected, "A browser payload is missing.")
    return result


def windows_receipt(path):
    """
    Refuse duplicate names and bound every text read before decoding.
    """
    require(path.stat().st_size <= ARCHIVE_BYTES, "The ZIP is too large.")
    result, names = {}, set()
    with zipfile.ZipFile(path) as archive:
        require(len(archive.infolist()) <= MEMBER_LIMIT,
                "Too many Windows package entries.")
        for entry in archive.infolist():
            name = member_name(entry.filename)
            require(name not in names, "The Windows archive repeats a member.")
            names.add(name)
            require(not stat.S_ISLNK(entry.external_attr >> 16),
                    "The Windows archive contains a symbolic link.")
        for name in [*LICENSES, "BUILD-INFO.txt"]:
            require(name in names, "A required Windows text is missing.")
            entry = archive.getinfo(name)
            require(not entry.is_dir() and entry.file_size <= TEXT_BYTES,
                    "A Windows text exceeds the inspection budget.")
            data = archive.read(entry)
            if name == "BUILD-INFO.txt":
                build_info = data.decode("utf-8")
            else:
                digest = hashlib.sha256(data).hexdigest()
                require(digest == file_sha(Path(LICENSES[name])),
                        "A licence differs.")
                result[name] = digest
    return result, build_info


def main():
    """
    Write a source-compared receipt for the AUD-027 package catalog.
    """
    if len(sys.argv) != 2:
        raise SystemExit(
            "usage: canonical-receipt.py <canonical release folder>")
    folder = Path(sys.argv[1])
    manifest = tomllib.loads(Path("Cargo.toml").read_text())
    version = manifest["package"]["version"]
    browser = browser_receipt(folder / f"mhfe-v{version}-browser.tar.gz")
    licenses, build_info = windows_receipt(
        folder / f"mhfe-v{version}-windows-x86_64.zip")
    print(json.dumps({
        "recordedUtc": datetime.datetime.now(
            datetime.timezone.utc).isoformat(),
        "archives": {p.name: file_sha(p) for p in sorted(folder.iterdir())
                     if p.is_file()},
        "browserFiles": browser, "browserFileCount": len(browser),
        "windowsLicenseMatches": licenses, "windowsBuildInfo": build_info,
    }, indent=2))


if __name__ == "__main__":
    main()
