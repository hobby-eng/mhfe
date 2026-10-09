#!/usr/bin/env python3
"""Check vendored bytes, Cargo package checksums and exact pins without fetching sources."""
import hashlib
import json
import os
import re
import sys
import tarfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
failures = []
vendor = (ROOT / "vendor/phc-winner-argon2.md").read_text().split("```text\n", 1)[1].split("```", 1)[0]
vendor_count = 0
for line in vendor.splitlines():
    expected, path = line.split(maxsplit=1)
    got = hashlib.sha256((ROOT / "vendor/phc-winner-argon2" / path).read_bytes()).hexdigest()
    vendor_count += 1
    if got != expected:
        failures.append("Vendored bytes differ: " + path)
manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
tables = [manifest.get("dependencies", {}), manifest.get("build-dependencies", {}), manifest.get("dev-dependencies", {})]
for target in manifest.get("target", {}).values():
    tables.extend([target.get("dependencies", {}), target.get("dev-dependencies", {})])
for table in tables:
    for name, spec in table.items():
        version = spec if isinstance(spec, str) else spec.get("version", "")
        if not re.fullmatch(r"=\d+\.\d+\.\d+", version):
            failures.append("Dependency not exactly pinned: " + name)
lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
cargo_home = Path(os.environ["CARGO_HOME"])
source_count = 0
file_count = 0
missing = []
for package in lock["package"]:
    if "checksum" not in package:
        continue
    package_name = f"{package['name']}-{package['version']}"
    paths = list((cargo_home / "registry/cache").glob(f"*/{package_name}.crate"))
    if not paths:
        missing.append(package["name"] + "-" + package["version"])
        continue
    checksum = hashlib.sha256(paths[0].read_bytes()).hexdigest()
    source_count += 1
    if checksum != package["checksum"]:
        failures.append("Cargo cache checksum differs: " + package["name"])
    sources = list((cargo_home / "registry/src").glob(f"*/{package_name}"))
    if not sources:
        missing.append("unpacked " + package_name)
        continue
    with tarfile.open(paths[0], "r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            relative = Path(member.name).relative_to(package_name)
            source = sources[0] / relative
            archived = archive.extractfile(member).read()
            file_count += 1
            if not source.is_file() or source.read_bytes() != archived:
                failures.append("Unpacked source differs: " + member.name)
print(f"Vendored manifest: {vendor_count} files match.")
print(f"Exact manifest pins: {sum(len(table) for table in tables)} declarations checked.")
print(f"Cargo archive checksums: {source_count}; unpacked source files: {file_count}; not cached: {len(missing)}.")
print("Not cached:", missing)
print("Failures:", failures)
# Missing target-only sources are an explicit coverage gap, not evidence of tampering.
sys.exit(bool(failures))
