#!/usr/bin/env python3
"""Read the AUD-008 canonical archives without extracting or rebuilding them."""

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-008-evidence"
OUTPUTS = ("canonical-output-aud008cached", "canonical-output-aud008uncached")
MARKER = b"MHFE-TEST-ONLY-REDUCED-ARGON2-COST"
EXPECTED_COMMIT = "01978aa01f86cbec7dbc9fb9afd131dfa1a1d650"
BROWSER_FILES = {
    "mhfe_core_bg.wasm",
    "mhfe-worker.js",
    "argon2-mt.js",
    "argon2-st.js",
    "client.js",
    "client.d.ts",
    "mhfe-fast-mode.py",
}
COMMON_FILES = {
    "README.md",
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "BUILD-INFO.txt",
    "licenses/argon2-LICENSE",
    "licenses/eff-large-wordlist.md",
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def archive_files(path):
    files = {}
    metadata = []
    errors = []
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            members = [(member.filename, archive.read(member), member) for member in archive.infolist()]
        for raw_name, data, member in members:
            name = raw_name.removeprefix("./")
            metadata.append({"path": name, "timestamp": member.date_time, "flags": member.flag_bits})
            if member.date_time != (1980, 1, 1, 0, 0, 0):
                errors.append(f"noncanonical ZIP timestamp: {name}")
            if member.is_dir():
                continue
            if name in files:
                errors.append(f"duplicate archive member: {name}")
            files[name] = data
    else:
        with tarfile.open(path) as archive:
            for member in archive.getmembers():
                name = member.name.removeprefix("./")
                metadata.append({"path": name, "mtime": member.mtime, "uid": member.uid,
                                 "gid": member.gid, "mode": oct(member.mode)})
                if member.mtime != 0 or member.uid != 0 or member.gid != 0:
                    errors.append(f"noncanonical tar metadata: {name}")
                if not member.isfile() and not member.isdir():
                    errors.append(f"non-file/non-directory tar member: {name}")
                if not member.isfile():
                    continue
                if name in files:
                    errors.append(f"duplicate archive member: {name}")
                files[name] = archive.extractfile(member).read()
    for name in files:
        if PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:
            errors.append(f"unsafe member path: {name}")
    return files, metadata, errors


def inspect_archive(path, expected_hash, version):
    content = path.read_bytes()
    files, metadata, errors = archive_files(path)
    actual_hash = sha256(content)
    if actual_hash != expected_hash:
        errors.append("archive checksum differs from build manifest")
    browser = "-browser." in path.name
    expected_files = COMMON_FILES | (BROWSER_FILES | {"README-mhfe.md"} if browser else
                                    {"mhfe.exe", "mhfe-launch.bat"} if path.suffix == ".zip" else
                                    {"mhfe", "mhfe-launch.sh"})
    if set(files) != expected_files:
        errors.append(f"file allowlist mismatch: {sorted(set(files) ^ expected_files)}")
    for packaged, source in {
        "LICENSE": "LICENSE",
        "THIRD_PARTY_NOTICES.md": "THIRD_PARTY_NOTICES.md",
        "licenses/argon2-LICENSE": "vendor/phc-winner-argon2/LICENSE",
        "licenses/eff-large-wordlist.md": "vendor/eff-large-wordlist.md",
        "README-mhfe.md" if browser else "README.md": "README.md",
    }.items():
        if files.get(packaged) != (ROOT / source).read_bytes():
            errors.append(f"packaged document differs from audited source: {packaged}")
    launcher = "mhfe-fast-mode.py" if browser else "mhfe-launch.bat" if path.suffix == ".zip" else "mhfe-launch.sh"
    if files.get(launcher) != (ROOT / "packaging" / launcher).read_bytes():
        errors.append(f"packaged launcher differs from audited source: {launcher}")
    build_info = files.get("BUILD-INFO.txt", b"").decode()
    for text in (f"mhfe v{version}\n", f"source: {EXPECTED_COMMIT} (modified)\n", "rustc 1.99.0"):
        if text not in build_info:
            errors.append(f"missing expected build metadata: {text.strip()}")
    marked_files = sorted(name for name, value in files.items() if MARKER in value)
    if marked_files:
        errors.append(f"test-only cost marker present: {marked_files}")
    browser_hashes = {}
    if browser:
        readme = files["README.md"]
        if not readme.startswith((ROOT / "docs/BROWSER-PACKAGE.md").read_bytes()):
            errors.append("browser package instructions differ from audited source")
        browser_hashes = dict((name, digest) for digest, name in re.findall(
            r"^([0-9a-f]{64})  (\S+)$", readme.decode(), re.M))
        if set(browser_hashes) != BROWSER_FILES:
            errors.append("browser README checksum coverage differs from runtime allowlist")
        for name, digest in browser_hashes.items():
            if sha256(files[name]) != digest:
                errors.append(f"browser README checksum mismatch: {name}")
    return {
        "archive": str(path.relative_to(ROOT)),
        "bytes": len(content),
        "sha256": actual_hash,
        "expectedSha256": expected_hash,
        "files": {name: sha256(value) for name, value in sorted(files.items())},
        "archiveMetadata": metadata,
        "buildInfo": build_info,
        "testCostMarkerFiles": marked_files,
        "browserRuntimeHashEntries": browser_hashes,
        "errors": errors,
    }


def main():
    version = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]["version"]
    snapshot = json.loads((EVIDENCE / "snapshot.json").read_text())["mhfe"]
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    sources = {name: sha256((ROOT / name).read_bytes()) for name in snapshot["files"]}
    changed = [name for name in sources if sources[name] != snapshot["files"][name]]
    errors = []
    if commit != EXPECTED_COMMIT:
        errors.append("reviewed HEAD changed")
    # Concurrent report writing is permitted; these bytes cannot affect shipped packages.
    product_changes = [name for name in changed if not name.startswith("docs/audits/")]
    if product_changes:
        errors.append(f"snapshot product bytes changed: {product_changes}")
    results = {}
    for output in OUTPUTS:
        release = ROOT / output / "release"
        manifest = dict((name, digest) for digest, name in re.findall(
            r"^([0-9a-f]{64})  (\S+)$", (release / "SHA256SUMS").read_text(), re.M))
        expected_names = {f"mhfe-v{version}-{package}{suffix}" for package, suffix in (
            ("browser", ".tar.gz"), ("linux-x86_64", ".tar.gz"),
            ("linux-aarch64", ".tar.gz"), ("windows-x86_64", ".zip"))}
        if set(manifest) != expected_names:
            errors.append(f"release manifest coverage mismatch: {output}")
        if {path.name for path in release.iterdir()} != expected_names | {"SHA256SUMS"}:
            errors.append(f"release directory contains unexpected/missing files: {output}")
        results[output] = [inspect_archive(release / name, digest, version)
                           for name, digest in sorted(manifest.items())]
        for result in results[output]:
            errors.extend(f"{result['archive']}: {error}" for error in result["errors"])
    cached = {Path(item["archive"]).name: item["sha256"] for item in results[OUTPUTS[0]]}
    uncached = {Path(item["archive"]).name: item["sha256"] for item in results[OUTPUTS[1]]}
    if cached != uncached:
        errors.append("cached and uncached archive bytes differ")
    record = {
        "auditId": "AUD-008", "reviewedCommit": commit, "version": version,
        "sourceFingerprint": snapshot["sourceFingerprint"],
        "concurrentAuditRecordChanges": [name for name in changed if name.startswith("docs/audits/")],
        "productSourceChanges": product_changes, "archives": results,
        "cachedUncachedArchiveBytesEqual": cached == uncached,
        "canonicalHashes": cached, "errors": errors,
        "limitations": ["Coordinator builds reused; reviewer independently hashed/read their outputs.",
                        "No macOS archives or remote signatures/attestations were supplied.",
                        "No full-size vector replay, build or archive extraction was performed."]}
    (EVIDENCE / "devops-artifacts.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"archivesChecked": sum(map(len, results.values())),
                      "canonicalHashes": cached, "cachedUncachedArchiveBytesEqual": cached == uncached,
                      "productSourceChanges": product_changes, "errors": errors}, indent=2))
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
