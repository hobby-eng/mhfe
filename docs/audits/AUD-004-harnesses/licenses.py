"""Inspect the licenses of linked crates and the actual locally packaged archives."""
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[3]
metadata = json.loads(subprocess.check_output([
    "cargo", "metadata", "--locked", "--offline", "--format-version", "1",
    "--filter-platform", "x86_64-unknown-linux-gnu",
], cwd=ROOT))
package = next(p for p in metadata["packages"] if p["name"] == "bech32")
source = Path(package["manifest_path"]).parent
license_file = next(p for p in source.iterdir() if p.name.startswith("LICENSE"))
license_text = license_file.read_text()
print("bech32", package["version"], "license:", package["license"])
print("Upstream license:", license_file)
print(license_text)
# bech32 is called by production wallet address parsing and encoding, not just a dev dependency.
assert "bech32::segwit" in (ROOT / "src/wallet.rs").read_text()
archives = sorted((ROOT / "docs/audits/AUD-004-evidence/packages").glob("*.tar.gz"))
assert len(archives) == 3
missing = []
for archive in archives:
    with tarfile.open(archive) as tar:
        texts = []
        for member in tar.getmembers():
            if member.isfile() and (member.name.endswith((".md", ".txt")) or "LICENSE" in member.name):
                texts.append(tar.extractfile(member).read().decode(errors="replace"))
        combined = "\n".join(texts)
        notice = license_text.splitlines()[0]
        present = notice in combined
        print(archive.name, "contains bech32 copyright notice:", present)
        if not present:
            missing.append(archive.name)
assert not missing, f"Linked bech32 MIT notice absent from distribution documents: {missing}"
