#!/usr/bin/env python3
"""AUD-017 R4 probe: 40-hex commit names in the audit records and release notes resolve.

    python3 docs/audits/AUD-017-harnesses/r4-build-docs/record_commit_prose.py

Reads docs/audits/audit-*.{md,json}, docs/audits/README.md and docs/releases/*.md and collects
every whole 40-hex-digit word (a full Git commit name; SHA-256 values have 64 digits). Each must
be a commit of mhfe or of the sibling mhfe_spec or multi-chain-wallet-tools checkouts. The
"before" column of an old-to-new map (a hash followed by "->" or listed as an original commit in
docs/releases/history-rewrite-*.md, or under a privacyRedaction key) is expected to be missing
and is skipped. Exits 1 when another name resolves nowhere. 40-hex values that are not commits
(such as HASH160 values in wallet vectors) would be reported too; read the context.
"""
import json, re, subprocess, sys
from pathlib import Path

REPOS = [Path("."), Path("../mhfe_spec"), Path("../multi-chain-wallet-tools")]
HEX = re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])")


def exists(name):
    for repo in REPOS:
        r = subprocess.run(["git", "-C", str(repo), "cat-file", "-e", f"{name}^{{commit}}"],
                           capture_output=True)
        if r.returncode == 0:
            return True
    return False


files = sorted(Path("docs/audits").glob("audit-*.md")) + sorted(Path("docs/audits").glob("audit-*.json"))
files += [Path("docs/audits/README.md")] + sorted(Path("docs/releases").glob("*.md"))
missing = {}
for f in files:
    text = f.read_text()
    if f.suffix == ".json":
        data = json.loads(text)
        data.pop("privacyRedaction", None)
        text = json.dumps(data)
    for line in text.splitlines() if f.suffix == ".md" else [text]:
        skip = set(re.findall(r"([0-9a-f]{7,40})\s*->", line))
        if f.name.startswith("history-rewrite"):
            cells = [c.strip(" `") for c in line.split("|")]
            if len(cells) > 3:
                skip.add(cells[2])  # "Built from (original commit)"
        for name in HEX.findall(line):
            if name in skip or name in missing:
                continue
            if not exists(name):
                missing[name] = f"{f}"
for name, where in sorted(missing.items(), key=lambda x: x[1]):
    print(f"{where}: {name} is no commit of mhfe, mhfe_spec or multi-chain-wallet-tools")
print(f"{len(missing)} unresolved 40-hex names")
sys.exit(1 if missing else 0)
