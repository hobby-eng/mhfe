#!/usr/bin/env python3
"""Inspect canonical archives and compare bytes to local outputs without extracting files."""

import hashlib
import json
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT / "canonical-output-aud018/release"
EVIDENCE = ROOT / "docs/audits/AUD-018-evidence"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    sums = (OUTPUT / "SHA256SUMS").read_text().splitlines()
    expected_names = {
        "mhfe-v0.5.1-linux-x86_64.tar.gz", "mhfe-v0.5.1-linux-aarch64.tar.gz",
        "mhfe-v0.5.1-windows-x86_64.zip", "mhfe-v0.5.1-browser.tar.gz",
    }
    listed = {line.split(maxsplit=1)[1] for line in sums}
    assert listed == expected_names and len(sums) == len(expected_names), listed
    assert {path.name for path in OUTPUT.iterdir() if path.is_file()} == expected_names | {"SHA256SUMS"}
    archives = []
    comparisons = {}
    for line in sums:
        expected, name = line.split(maxsplit=1)
        path = OUTPUT / name
        data = path.read_bytes()
        assert sha(data) == expected, name
        if name.endswith(".zip"):
            with zipfile.ZipFile(path) as packed:
                files = {name.removeprefix("./"): packed.read(name) for name in packed.namelist() if not name.endswith("/")}
        else:
            with tarfile.open(path) as packed:
                files = {item.name.removeprefix("./"): packed.extractfile(item).read() for item in packed.getmembers() if item.isfile()}
        for required in ["LICENSE", "THIRD_PARTY_NOTICES.md"]:
            assert files[required] == (ROOT / required).read_bytes(), (name, required)
        info = files["BUILD-INFO.txt"].decode()
        assert "mhfe v0.5.1" in info and "3c60594479302827fe40975b04fd07f9f6fd4b3b (modified)" in info
        archives.append({"name": name, "bytes": len(data), "sha256": expected, "licenseBytesMatch": True, "buildInfo": info})
        if "linux-x86_64" in name:
            comparisons["native"] = {"hostSha256": sha((ROOT / "target/release/mhfe").read_bytes()), "canonicalSha256": sha(files["mhfe"])}
        if name.endswith("browser.tar.gz"):
            comparisons["wasm"] = {"hostSha256": sha((ROOT / "dist/runtime/mhfe.wasm").read_bytes()), "canonicalSha256": sha(files["runtime/mhfe.wasm"])}
            comparisons["browserManifest"] = {"hostSha256": sha((ROOT / "dist/modules.json").read_bytes()), "canonicalSha256": sha(files["modules.json"])}
            comparisons["canonicalBrowserBuildId"] = json.loads(files["modules.json"])["buildId"]
            # This package publishes exact per-file sums independently of the archive checksum.
            readme = files["README.md"].decode().split("## SHA-256 of this build", 1)[1]
            checked = 0
            for entry in readme.splitlines():
                if len(entry) > 66 and all(c in "0123456789abcdef" for c in entry[:64]) and entry[64:66] == "  ":
                    digest, relative = entry.split("  ", 1)
                    assert sha(files[relative]) == digest, relative
                    checked += 1
            assert checked > 0
            comparisons["browserInternalChecksumsVerified"] = checked
    for key in ["native", "wasm", "browserManifest"]:
        comparisons[key]["equal"] = comparisons[key]["hostSha256"] == comparisons[key]["canonicalSha256"]
    record = {"archives": archives, "comparisons": comparisons, "interpretation": "A host/container difference is not a failed canonical rebuild: host native compilers differ. No independent second uncached container build was performed; do not claim bit-for-bit reproducibility from this inspection alone."}
    (EVIDENCE / "artifacts.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"archivesVerified": len(archives), "comparisons": comparisons}))


if __name__ == "__main__":
    main()
