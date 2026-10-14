#!/usr/bin/env python3
"""Audit AUD-024, role spec-parity: checks that mhfe agrees with its specification where a script can
tell. Run from the mhfe repository root; the specification repository is ../mhfe_spec unless
MHFE_SPEC names another folder. Prints one line per check and exits 1 when any check fails.

1. Every file of the specification's vectors/suite3 and vectors/suite4 (README.md aside) equals its
   copy under tests/fixtures byte for byte (SHA-256), and both repositories' SHA256SUMS hold.
2. The suite identifiers and domain strings of src/suite.rs, and the source-check tag of
   src/wallet_check.rs, are the strings the specification defines.
3. The browser check() result is documented as the package returns it: web/client.d.ts gives
   `outcome`, so docs/API.md and docs/BROWSER-PACKAGE.md must not document a `matches` field.
4. Every MhfeClient method of web/client.d.ts is named in docs/API.md's browser section.
"""
import hashlib
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path.cwd()
SPEC = pathlib.Path(os.environ.get("MHFE_SPEC", ROOT.parent / "mhfe_spec"))
failures = 0


def report(ok, text):
    global failures
    print(("ok    " if ok else "FAIL  ") + text)
    failures += 0 if ok else 1


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


# 1. Vector bytes.
for suite, folder in (("suite3", "suite3-vectors"), ("suite4", "suite4-vectors")):
    for spec_file in sorted((SPEC / "vectors" / suite).iterdir()):
        if spec_file.name == "README.md":
            continue
        if suite == "suite3" and spec_file.name == "validation-cases.json":
            mine = ROOT / "tests/fixtures/validation-cases.json"
        else:
            mine = ROOT / "tests/fixtures" / folder / spec_file.name
        same = mine.exists() and sha256(mine) == sha256(spec_file)
        report(same, f"vectors/{suite}/{spec_file.name} == {mine.relative_to(ROOT)}")
    for base in (SPEC / "vectors" / suite, ROOT / "tests/fixtures" / folder):
        run = subprocess.run(["sha256sum", "--check", "--quiet", "SHA256SUMS"], cwd=base)
        report(run.returncode == 0, f"sha256sum --check in {base.name} ({base.parent.name})")

# 2. Identifiers and domain strings.
spec_text = (SPEC / "README.md").read_text()
suite_rs = (ROOT / "src/suite.rs").read_text()
for suite_id in ("MHFE-BIP39-256-EXPERIMENTAL-3", "MHFE-BIP39-LP-EXPERIMENTAL-4"):
    report(f'SUITE_ID = ASCII("{suite_id}")' in spec_text, f"specification defines {suite_id}")
    for suffix in ("", "/ROUND-SALT", "/ROUND-MASK"):
        report(f'"{suite_id}{suffix}"' in suite_rs, f"src/suite.rs has {suite_id}{suffix}")
report('ASCII("MHFE-WALLET-CHECK-SEED-1")' in spec_text, "specification defines the source-check tag")
report('b"MHFE-WALLET-CHECK-SEED-1"' in (ROOT / "src/wallet_check.rs").read_text(),
       "src/wallet_check.rs uses the source-check tag")

# 3. The documented shape of check().
dts = (ROOT / "web/client.d.ts").read_text()
report("outcome: MhfeCheckOutcome;" in dts, "web/client.d.ts: check() resolves to outcome")
for doc in ("docs/API.md", "docs/BROWSER-PACKAGE.md"):
    stale = [n + 1 for n, line in enumerate((ROOT / doc).read_text().splitlines())
             if re.search(r"\{ matches, path, evidence|matches is true", line)]
    report(not stale, f"{doc}: no `matches` field of check() documented (lines {stale})")

# 4. Every MhfeClient method in docs/API.md.
api = (ROOT / "docs/API.md").read_text()
body = re.search(r"export (?:declare )?(?:class|interface) MhfeClient\b(.*?)\n}\n", dts, re.S)
methods = sorted(set(re.findall(r"^  ([a-z][A-Za-z]+)\(", body.group(1) if body else "", re.M)) - {"constructor"})
report(bool(methods), f"MhfeClient methods found in web/client.d.ts: {len(methods)}")
for method in methods:
    report(f"client.{method}(" in api, f"docs/API.md names client.{method}()")

print(f"{failures} check(s) failed")
sys.exit(1 if failures else 0)
