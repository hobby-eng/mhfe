#!/usr/bin/env python3
"""AUD-017 R4 probe: docs/API.md's decrypt() line names every option of web/client.d.ts.

    python3 docs/audits/AUD-017-harnesses/r4-build-docs/api_md_decrypt.py

Reads the options of MhfeClient.decrypt() from web/client.d.ts (MhfeSettings plus its own fields)
and the destructured options of `await client.decrypt({ ... })` in docs/API.md. Exits 1 when an
option of the declaration is missing from the document.
"""
import re, sys
from pathlib import Path

dts = Path("web/client.d.ts").read_text()
block = re.search(r"\n  decrypt\(\s*options: MhfeSettings & \{(.*?)\n    \},", dts, re.S)[1]
own = set(re.findall(r"\n\s+(\w+)\??:", block))
settings = re.search(r"interface MhfeSettings \{(.*?)\n\}", dts, re.S)
own |= set(re.findall(r"\n\s+(\w+)\??:", settings[1])) if settings else set()
api = Path("docs/API.md").read_text()
doc = set(re.findall(r"\w+", re.search(r"await client\.decrypt\(\{([^}]*)\}", api)[1]))
missing = sorted(own - doc)
print("declared:", sorted(own)); print("documented:", sorted(doc)); print("missing:", missing)
sys.exit(1 if missing else 0)
