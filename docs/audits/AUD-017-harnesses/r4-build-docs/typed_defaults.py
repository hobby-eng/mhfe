#!/usr/bin/env python3
"""AUD-017 R4 probe: the --scan-gap default is derived from search::DECOY_SCAN_GAP.

    python3 docs/audits/AUD-017-harnesses/r4-build-docs/typed_defaults.py

AGENTS.md rule 6: a value with a meaning is a named constant defined once. The probe reads the
value of DECOY_SCAN_GAP in src/search.rs and reports each "default <value>" or "<value> is the
gap" spelled by hand in src/bin/mhfe/*.rs, and each second declaration of the --scan-gap option.
Exits 1 when it finds one.
"""
import re, sys
from pathlib import Path

gap = re.search(r"pub const DECOY_SCAN_GAP: u32 = (\d+);", Path("src/search.rs").read_text())[1]
hits, declarations = [], []
for f in sorted(Path("src/bin/mhfe").glob("*.rs")):
    for n, line in enumerate(f.read_text().splitlines(), 1):
        if re.search(rf"default {gap}\b|\b{gap} is the gap", line):
            hits.append(f"{f}:{n}: {line.strip()}")
        if 'long = "scan-gap"' in line:
            declarations.append(f"{f}:{n}")
for h in hits:
    print("typed again:", h)
print("--scan-gap declared at:", declarations)
sys.exit(1 if hits or len(declarations) > 1 else 0)
