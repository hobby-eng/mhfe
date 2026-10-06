#!/usr/bin/env python3
"""Check AUD-008 canonical assets and compare two independently built sets."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-008-evidence"
MARKER = b"MHFE-TEST-ONLY-REDUCED-ARGON2-COST"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def assets(folder):
    sums = {}
    for line in (folder / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        assert Path(name).name == name, name
        assert sha((folder / name).read_bytes()) == digest, name
        sums[name] = digest
    assert len(sums) == 4
    assert set(sums) == {p.name for p in folder.iterdir() if p.suffix in (".gz", ".zip")}
    return sums


def members(path):
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            return {n: archive.read(n) for n in archive.namelist() if not n.endswith("/")}
    with tarfile.open(path) as archive:
        return {m.name.removeprefix("./"): archive.extractfile(m).read()
                for m in archive.getmembers() if m.isfile()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path, nargs="?")
    args = parser.parse_args()
    first = assets(args.first)
    snapshot = json.loads((EVIDENCE / "snapshot.json").read_text())["mhfe"]
    checked = []
    for name in sorted(first):
        files = members(args.first / name)
        for document in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
            assert files[document] == (ROOT / document).read_bytes(), (name, document)
        info = files["BUILD-INFO.txt"].decode()
        assert "mhfe v0.5.0" in info and snapshot["commit"] + " (modified)" in info, name
        executables = {p: sha(b) for p, b in files.items()
                       if p == "mhfe" or p.endswith((".exe", ".wasm"))}
        assert executables, name
        for path in executables:
            assert MARKER not in files[path], (name, path)
        if "linux-x86_64" in name:
            native = EVIDENCE / "canonical-native-mhfe"
            native.write_bytes(files["mhfe"])
            native.chmod(0o700)
            version = subprocess.check_output([str(native), "--version"], text=True).strip()
            assert version == "mhfe 0.5.0", version
        if "browser" in name:
            for filename in ("mhfe_core_bg.wasm", "client.js", "client.d.ts", "mhfe-worker.js", "argon2-mt.js", "argon2-st.js"):
                assert filename in files, filename
            # The package README embeds the digest of every supplied runtime file.
            readme = files["README.md"].decode()
            for filename in ("mhfe_core_bg.wasm", "client.js", "client.d.ts", "mhfe-worker.js", "argon2-mt.js", "argon2-st.js"):
                assert sha(files[filename]) in readme, filename
        checked.append({"archive": name, "sha256": first[name], "executableHashes": executables})
    result = {"archives": checked, "count": len(checked), "sourceCommit": snapshot["commit"],
              "sourceState": "modified", "sourceFingerprint": snapshot["sourceFingerprint"]}
    if args.second:
        second = assets(args.second)
        assert first == second, "Cached and uncached archive bytes differ."
        result["cachedAndUncachedMatch"] = True
    (EVIDENCE / ("artifacts-compared.json" if args.second else "artifacts-cached.json")).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
