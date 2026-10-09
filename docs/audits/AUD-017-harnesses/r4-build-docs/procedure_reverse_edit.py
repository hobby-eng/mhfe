#!/usr/bin/env python3
"""AUD-017 R4 probe: docs/audits/procedure-changes.json reverse edits give the audited bytes.

    python3 docs/audits/AUD-017-harnesses/r4-build-docs/procedure_reverse_edit.py

For each change it checks that the current procedure file (in the sibling checkout
../multi-chain-wallet-tools) has `currentSha256`, and that applying `reverseEdit` once gives
`auditedSha256`. Exits 1 on any mismatch.
"""
import hashlib, json, sys
from pathlib import Path

WORKSPACE = Path.cwd().parent
bad = 0
for change in json.loads(Path("docs/audits/procedure-changes.json").read_text())["changes"]:
    data = (WORKSPACE / change["file"]).read_bytes()
    current = hashlib.sha256(data).hexdigest()
    edit = change["reverseEdit"]
    text = data.decode()
    count = text.count(edit["current"])
    audited = hashlib.sha256(text.replace(edit["current"], edit["audited"], 1).encode()).hexdigest()
    ok = current == change["currentSha256"] and count == 1 and audited == change["auditedSha256"]
    print(change["file"], "current", current == change["currentSha256"], "occurrences", count,
          "audited", audited == change["auditedSha256"])
    bad += not ok
sys.exit(1 if bad else 0)
