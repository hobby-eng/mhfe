"""Read public GitHub metadata; verify the vendored files without cloning any repository."""

import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
commit = "f57e61e19229e23c4445b85494dbf7c07de721cb"
tree = json.loads(subprocess.check_output([
    "gh", "api", f"repos/P-H-C/phc-winner-argon2/git/trees/{commit}?recursive=1",
], text=True))
assert not tree["truncated"]
blobs = {item["path"]: item["sha"] for item in tree["tree"] if item["type"] == "blob"}
vendor = ROOT / "vendor/phc-winner-argon2"
count = 0
for path in sorted(vendor.rglob("*")):
    if not path.is_file():
        continue
    data = path.read_bytes()
    expected = blobs[str(path.relative_to(vendor))]
    assert hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest() == expected
    count += 1
print(f"{count} vendored files equal upstream Git objects at {commit}.")
reporting = json.loads(subprocess.check_output([
    "gh", "api", "repos/hobby-eng/mhfe/private-vulnerability-reporting",
], text=True))
print("Private vulnerability reporting:", json.dumps(reporting))
assert reporting["enabled"]
