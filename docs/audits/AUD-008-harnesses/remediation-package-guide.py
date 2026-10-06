#!/usr/bin/env python3
"""Check the freshly built browser guide without fetching remote resources."""

import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
guide = (ROOT / "docs/BROWSER-PACKAGE.md").read_text()
package = (ROOT / "dist/README.md").read_text()
assert package.startswith(guide), "Package does not contain the current integration guide"
links = re.findall(r"\]\(([^)]+)\)", package)
source_prefix = "https://github.com/hobby-eng/mhfe/blob/main/"
assert links, "No packaged guide links checked"
for target in links:
    if target.startswith(source_prefix):
        assert (ROOT / target.removeprefix(source_prefix)).is_file(), target
    elif not target.startswith(("https://", "http://", "#")):
        assert (ROOT / "dist" / target.split("#", 1)[0]).exists(), target
assert "measurements/README.md" not in links, "Broken relative link retained"
hashes = re.findall(r"^([0-9a-f]{64})  (\S+)$", package, re.M)
assert len(hashes) == 7, "Missing browser runtime checksum records"
for expected, name in hashes:
    assert hashlib.sha256((ROOT / "dist" / name).read_bytes()).hexdigest() == expected, name
print(json.dumps({
    "auditId": "AUD-008",
    "finding": "DOC003",
    "outcome": "passed",
    "packagedLinks": links,
    "runtimeHashesChecked": len(hashes),
    "guideSha256": hashlib.sha256(guide.encode()).hexdigest(),
    "packageReadmeSha256": hashlib.sha256(package.encode()).hexdigest(),
    "limit": "Explicit repository URL maps to retained source; remote uptime was not checked.",
}))
