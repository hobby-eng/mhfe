"""Check actual macOS packages without changing their signatures.

TOOL-01: Python's standard library reads tar/gzip and drives the
existing Python packer without an archive dependency for Node.js.
Usage: python3 scripts/verify-macos-packages.py <version> <folder>
       python3 scripts/verify-macos-packages.py --self-test
"""

import copy
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parent.parent
# Bound malformed archives before creating files. A small CLI, documents
# and licence texts fit these verification limits.
MAX_FILES = 256
MAX_BYTES = 64 * 1024 * 1024
TOOL_TIMEOUT = 60
PACKAGES = (("macos-aarch64", "arm64"), ("macos-x86_64", "x86_64"))
REQUIRED = {
    "mhfe", "mhfe-launch.command", "README.md", "BUILD-INFO.txt",
    "LICENSE-MIT", "LICENSE-APACHE", "THIRD_PARTY_NOTICES.md",
    "assets/mhfe-mascot.png", "licenses/argon2-LICENSE",
    "licenses/eff-large-wordlist.md",
}


def unpack(archive, destination):
    """Extract canonical files/directories with bounded work."""
    names = set()
    files = set()
    size = 0
    with tarfile.open(archive, "r:gz") as source:
        for item in source:
            if len(names) >= MAX_FILES or item.name in names:
                raise ValueError("Too many or duplicate archive members")
            names.add(item.name)
            path = PurePosixPath(item.name)
            relative = path.as_posix()
            canonical = "." if relative == "." else "./" + relative
            if (item.name != canonical or path.is_absolute()
                    or ".." in path.parts or "\\" in item.name):
                raise ValueError("Non-canonical archive path")
            if not (item.isfile() or item.isdir()):
                raise ValueError("Archive member is not a file/directory")
            executable = relative in {"mhfe", "mhfe-launch.command"}
            mode = 0o755 if item.isdir() or executable else 0o644
            if ((item.uid, item.gid, item.mtime, item.uname, item.gname)
                    != (0, 0, 0, "", "") or item.mode != mode):
                raise ValueError("Archive ownership, time or mode differs")
            size += item.size
            if size > MAX_BYTES:
                raise ValueError("Archive payload exceeds its limit")
            target = destination / relative
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                if relative == ".":
                    raise ValueError("The archive root must be a directory")
                target.parent.mkdir(parents=True, exist_ok=True)
                content = source.extractfile(item)
                if content is None:
                    raise ValueError("Archive content is missing")
                with content, target.open("xb") as output:
                    while block := content.read(64 * 1024):
                        output.write(block)
                files.add(relative)
            target.chmod(mode)
    if "." not in names or not REQUIRED.issubset(files):
        raise ValueError("Archive lacks its root or required release files")


def digest(path):
    """Identify exact compressed archive bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def repack(payload, destination):
    """Use the release packer's sole implementation."""
    subprocess.run([
        sys.executable, str(ROOT / "packaging/pack-tar.py"),
        str(payload), str(destination),
    ], check=True)


def require_architecture(actual, expected):
    """Require exactly the named architecture."""
    if actual.split() != [expected]:
        raise ValueError("The binary does not match its package architecture")


def check_architecture(binary, expected):
    """Read the actual architecture without executing the binary."""
    # Apple's "Building a universal macOS binary" uses lipo -archs.
    actual = subprocess.check_output(
        ["/usr/bin/lipo", "-archs", str(binary)], text=True,
        timeout=TOOL_TIMEOUT,
    )
    require_architecture(actual, expected)


def check_archive(archive, version, source, architecture, scratch):
    """Check provenance, hardened signature and identical repacking."""
    payload = scratch / archive.name
    payload.mkdir()
    unpack(archive, payload)
    info = (payload / "BUILD-INFO.txt").read_text(encoding="utf-8")
    if not info.startswith(f"mhfe {version}\nsource: {source}\n"):
        raise ValueError("Archive source/version differs from the checkout")
    # Independent expectations for package-release.sh's provenance.
    prefixes = ("macOS packaging: Python tarfile/PAX and gzip (mtime 0)",
                "Python: ", "zlib: ", "Apple SDK: ", "Apple clang version ")
    for prefix in prefixes:
        if not any(line.startswith(prefix) for line in info.splitlines()):
            raise ValueError(f"Missing macOS build provenance: {prefix}")
    hardened = ROOT / "scripts/harden-macos.sh"
    binary = payload / "mhfe"
    check_architecture(binary, architecture)
    other = next(arch for _, arch in PACKAGES if arch != architecture)
    try:
        check_architecture(binary, other)
    except ValueError:
        pass
    else:
        raise ValueError("The architecture verifier accepted the other target")
    subprocess.run([str(hardened), "--verify", str(binary)], check=True,
                   timeout=TOOL_TIMEOUT)
    packed = scratch / "repacked.tar.gz"
    repack(payload, packed)
    if digest(packed) != digest(archive):
        raise ValueError("Repacking the actual payload changes archive bytes")
    # Checkout metadata changes must preserve archive bytes. Keep only
    # executable intent, as a checkout under a restrictive umask would.
    for item in [payload, *payload.rglob("*")]:
        executable = item.is_dir() or item.stat().st_mode & 0o111
        item.chmod(0o700 if executable else 0o600)
        os.utime(item, (123456789, 123456789))
    repack(payload, packed)
    if digest(packed) != digest(archive):
        raise ValueError("Checkout metadata changes the packed payload")
    # Challenge signature verification on an unsigned binary copy.
    subprocess.run(["/usr/bin/codesign", "--remove-signature", str(binary)],
                   check=True, timeout=TOOL_TIMEOUT)
    refused = subprocess.run([str(hardened), "--verify", str(binary)],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             check=False, timeout=TOOL_TIMEOUT)
    if refused.returncode == 0:
        raise ValueError("The runtime verifier accepted an unsigned binary")
    print(f"Verified {archive.name}: {digest(archive)}")


def self_test():
    """Exercise acceptance and metadata/path/link/duplicate refusals."""
    for _, expected in PACKAGES:
        require_architecture(expected + "\n", expected)
        for wrong in ("", "arm64 x86_64", "arm64 arm64", "unknown"):
            try:
                require_architecture(wrong, expected)
            except ValueError:
                continue
            raise AssertionError("An invalid architecture list passed")
        other = next(arch for _, arch in PACKAGES if arch != expected)
        try:
            require_architecture(other, expected)
        except ValueError:
            pass
        else:
            raise AssertionError("The other architecture passed")
    with tempfile.TemporaryDirectory(prefix="canonical-output-macos-control-",
                                     dir=ROOT) as folder:
        scratch = Path(folder)
        payload = scratch / "payload"
        payload.mkdir()
        for name in REQUIRED:
            path = payload / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"public fixture\n")
            executable = name in {"mhfe", "mhfe-launch.command"}
            path.chmod(0o755 if executable else 0o644)
        archive = scratch / "positive.tar.gz"
        repack(payload, archive)
        accepted = scratch / "accepted"
        accepted.mkdir()
        unpack(archive, accepted)
        packed = scratch / "repacked.tar.gz"
        repack(accepted, packed)
        if digest(archive) != digest(packed):
            raise AssertionError("The positive fixture did not repack")
        with tarfile.open(archive) as source:
            entries = []
            for item in source:
                content = source.extractfile(item) if item.isfile() else None
                entries.append((item, content.read() if content else b""))
        # Each negative changes one property of a valid archive.
        problems = ("path", "duplicate", "link", "mode", "time", "missing")
        for problem in problems:
            broken = scratch / f"{problem}.tar.gz"
            with tarfile.open(broken, "w:gz") as output:
                for original, content in entries:
                    # Older hosted Python lacks TarInfo.replace.
                    item = copy.copy(original)
                    if item.name == "./mhfe":
                        if problem == "missing":
                            continue
                        if problem == "path":
                            item.name = "../escape"
                        elif problem == "link":
                            item.type = tarfile.SYMTYPE
                            item.linkname, item.size = "outside", 0
                        elif problem == "mode":
                            item.mode = 0o777
                        elif problem == "time":
                            item.mtime = 1
                    stream = io.BytesIO(content) if item.isfile() else None
                    output.addfile(item, stream)
                    if problem == "duplicate" and item.name == "./mhfe":
                        output.addfile(item, io.BytesIO(content))
            destination = scratch / problem
            destination.mkdir()
            try:
                unpack(broken, destination)
            except ValueError:
                continue
            raise AssertionError(f"The archive verifier accepted {problem}")
    print("The macOS archive controls pass; native signatures not exercised.")


def main(arguments):
    """Keep controls portable; require macOS for actual acceptance."""
    if arguments == ["--self-test"]:
        self_test()
        return 0
    if len(arguments) != 2 or sys.platform != "darwin":
        print("\n".join(__doc__.splitlines()[-2:]), file=sys.stderr)
        return 2
    version, folder = arguments
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                     text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT,
                                    text=True)
    source = f"{commit} ({'modified' if dirty else 'clean'})"
    with tempfile.TemporaryDirectory(prefix="canonical-output-macos-check-",
                                     dir=ROOT) as temporary:
        for package, architecture in PACKAGES:
            archive = Path(folder) / f"mhfe-{version}-{package}.tar.gz"
            check_archive(archive, version, source, architecture,
                          Path(temporary))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
