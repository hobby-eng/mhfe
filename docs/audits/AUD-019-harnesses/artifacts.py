#!/usr/bin/env python3
"""Bind six candidate archives to CI checksums, local canonical bytes and reviewed source."""

import hashlib
import json
import re
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


class ReleaseArchives:
    COMMIT = "66f142566464255e331763966b00ea1681c2dabd"
    VERSION = "v0.6.0"
    PACKAGES = ("linux-x86_64", "linux-aarch64", "windows-x86_64", "browser", "macos-x86_64", "macos-aarch64")

    def __init__(self):
        self._root = Path(__file__).resolve().parents[3]
        self._evidence = self._root / "docs/audits/AUD-019-evidence"

    @staticmethod
    def digest(data):
        return hashlib.sha256(data).hexdigest()

    def members(self, archive):
        files = {}
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as packed:
                records = [(item.filename, packed.read(item)) for item in packed.infolist() if not item.is_dir()]
        else:
            with tarfile.open(archive) as packed:
                if any(not (item.isfile() or item.isdir()) for item in packed.getmembers()):
                    raise SystemExit("Unexpected non-regular release archive member")
                records = [(item.name, packed.extractfile(item).read()) for item in packed.getmembers() if item.isfile()]
        for name, data in records:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or str(path) in files:
                raise SystemExit("Unsafe or duplicate release archive member")
            files[str(path)] = data
        return files

    def run(self):
        candidate = self._root / "canonical-output-signing-v0.6.0"
        local = self._root / "canonical-output-v0.6.0/release"
        names = {f"mhfe-{self.VERSION}-{package}.{'zip' if package.startswith('windows') else 'tar.gz'}" for package in self.PACKAGES}
        entries = [line.split() for line in (candidate / "SHA256SUMS").read_text().splitlines()]
        assert len(entries) == len(names) and {name for _, name in entries} == names
        assert {path.name for path in candidate.iterdir()} <= names | {"SHA256SUMS", "SHA256SUMS.asc", "RELEASE-SIGNING-KEY.asc"}
        ci = {}
        for line in (self._evidence / "remote-release-publish.log").read_text().splitlines():
            match = re.search(r"([a-f0-9]{64})  (mhfe-v0\.6\.0-\S+)\s*$", line)
            if match:
                assert match.group(2) not in ci or ci[match.group(2)] == match.group(1)
                ci[match.group(2)] = match.group(1)
        assert set(ci) == names
        outputs = []
        comparisons = {}
        for expected, name in entries:
            data = (candidate / name).read_bytes()
            actual = self.digest(data)
            assert actual == expected == ci[name], name
            files = self.members(candidate / name)
            for required in ("LICENSE", "THIRD_PARTY_NOTICES.md"):
                assert files[required] == (self._root / required).read_bytes(), (name, required)
            info = files["BUILD-INFO.txt"].decode()
            assert f"mhfe {self.VERSION}" in info and f"{self.COMMIT} (clean)" in info, info
            matched = None
            if (local / name).exists():
                matched = data == (local / name).read_bytes()
                assert matched, name
                comparisons[name] = actual
            if name.endswith("browser.tar.gz"):
                manifest = json.loads(files["modules.json"])
                assert manifest["version"] == "0.6.0"
                readme = files["README.md"].decode().split("## SHA-256 of this build", 1)[1]
                sums = [line.split("  ", 1) for line in readme.splitlines() if re.match(r"^[a-f0-9]{64}  ", line)]
                assert sums
                for checksum, relative in sums:
                    assert self.digest(files[relative]) == checksum, relative
                comparisons["browserBuildId"] = manifest["buildId"]
                comparisons["browserInternalChecksumCount"] = len(sums)
                comparisons["hostBrowserManifestEqual"] = files["modules.json"] == (self._root / "dist/modules.json").read_bytes()
                comparisons["hostBrowserWasmEqual"] = files["runtime/mhfe.wasm"] == (self._root / "dist/runtime/mhfe.wasm").read_bytes()
            if "linux-x86_64" in name:
                binary = self._evidence / "candidate-mhfe"
                binary.write_bytes(files["mhfe"])
                binary.chmod(0o700)
                comparisons["canonicalNativeSha256"] = self.digest(files["mhfe"])
                comparisons["hostNativeSha256"] = self.digest((self._root / "target/release/mhfe").read_bytes())
            outputs.append({"file": name, "bytes": len(data), "sha256": actual, "ciChecksumMatch": True, "localCanonicalByteMatch": matched, "members": sorted(files), "buildInfo": info})
        assert len([key for key in comparisons if key in names]) == 4
        record = {"archives": outputs, "comparisons": comparisons, "checksumFileSha256": self.digest((candidate / "SHA256SUMS").read_bytes()), "signaturePresent": (candidate / "SHA256SUMS.asc").exists(), "limits": "Local candidate bytes match uploaded CI checksums and cryptographic attestations. Current private draft inventory cannot be inferred solely from these files."}
        (self._evidence / "artifacts.json").write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps({"verifiedArchives": len(outputs), "comparisons": comparisons, "signaturePresent": record["signaturePresent"]}))


if __name__ == "__main__":
    ReleaseArchives().run()
