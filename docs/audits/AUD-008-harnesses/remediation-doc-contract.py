#!/usr/bin/env python3
"""Recheck AUD-008 documentation promises against the current specification and public vectors."""

import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = Path(sys.argv[1]).resolve()
assert not OUTPUT.exists(), "Use a fresh evidence name."
paths = ["README.md", "docs/API.md", "docs/BROWSER-PACKAGE.md", "src/repair.rs", "src/wallet_check.rs", "src/rehearsal.rs"]
texts = {path: (ROOT / path).read_text() for path in paths}
specification = (ROOT.parent / "mhfe_spec/README.md").read_text()
checks = []


def require(label, condition):
    checks.append({"label": label, "passed": bool(condition)})
    assert condition, label


require("DOC001 API gives bounded-distance failure only", "When no repair within that bound passes the BIP39 checksum" in texts["docs/API.md"])
require("DOC001 API warns about checksum-valid wrong-card output", "give another container that passes the checksum" in texts["docs/API.md"])
require("DOC001 error table promises no authentication", "No repair within the repair words' bound passes the BIP39 checksum" in texts["docs/API.md"])
require("DOC001 rustdoc warns about wrong-card output", "a repair does not show that the card belongs" in texts["src/repair.rs"])
require("DOC002 module points to defined optional source profile", "specification defines as an optional source profile" in texts["src/wallet_check.rs"])
require("DOC002 empty-passphrase Reference matches API", "empty for a wallet without one" in texts["src/rehearsal.rs"])
require("DOC002 README links to normative profile", "#optional-source-profile-a-recovery-check-for-new-24-word-phrases" in texts["README.md"])
require("DOC002 counterpart defines identical draft profile", 'draft source-generation profile `MHFE-WALLET-CHECK-SEED-1`' in specification)
require("DOC002 counterpart permits narrower CLI offer", "MAY offer the profile only with\na nonempty BIP39 passphrase" in specification)
require("DOC002 narrow generation choice retained", 'passphrase.is_empty()' in (ROOT / "src/bin/mhfe/new_wallet.rs").read_text())
for path in ["README.md", "src/wallet_check.rs"]:
    require(f"DOC002 obsolete status absent in {path}", "not yet part of the specification" not in texts[path] and "does not define it yet" not in texts[path])

for counter, passphrase, ending, digest in [
    (76562, "TREZOR", "above proof fatigue", "0000e86481bdfe6dbf45e6e41fba4f309fcf09d3f0af2fe3f46736c663840853"),
    (98918, "", "absorb another spoil", "0000ede77b44fbd62025e1d36a45ebe3846cf48f7b3e76ca6a91495fdadc1fb2"),
]:
    phrase = "abandon " * 21 + ending
    seed = hashlib.pbkdf2_hmac("sha512", phrase.encode(), b"mnemonic" + passphrase.encode(), 2048, 64)
    actual = hashlib.sha256(b"MHFE-WALLET-CHECK-SEED-1" + (256).to_bytes(4, "big") + seed).hexdigest()
    require(f"DOC002 exact public digest counter={counter}", actual == digest and digest in specification)

guide = texts["docs/BROWSER-PACKAGE.md"]
links = re.findall(r"\[[^\]]*\]\(([^)]+)\)", guide)
require("DOC003 measurement link relocates through explicit repository URL", "https://github.com/hobby-eng/mhfe/blob/main/docs/measurements/README.md" in links)
require("DOC003 former missing package-relative link absent", "measurements/README.md" not in links)
require("DOC003 absolute URL targets retained repository source", (ROOT / "docs/measurements/README.md").is_file())
result = {
    "auditId": "AUD-008",
    "checks": checks,
    "checkCount": len(checks),
    "sourceSha256": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in paths},
    "specificationSha256": hashlib.sha256((ROOT.parent / "mhfe_spec/README.md").read_bytes()).hexdigest(),
    "limits": ["No fresh WASM/browser-package rebuild; DOC003 source fix checked without claiming a regenerated package.", "No live remote-link availability check; source URL and local target correspondence checked."],
    "outcome": "passed",
}
OUTPUT.write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({"checks": len(checks), "outcome": "passed", "limits": result["limits"]}))
