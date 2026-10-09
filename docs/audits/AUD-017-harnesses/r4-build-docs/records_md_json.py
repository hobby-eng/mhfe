#!/usr/bin/env python3
"""AUD-017 R4 probe: the Markdown and JSON audit records of AUD-009 to AUD-015 agree.

    python3 docs/audits/AUD-017-harnesses/r4-build-docs/records_md_json.py

For each record it compares the finding register of the Markdown (the table rows whose first
cell is a finding ID) with the JSON `findings`: the same IDs, severities and statuses. It also
checks, with the register rows (the first row of each ID; later follow-up tables may
record newer statuses that the JSON keeps under followups), that the audit index (docs/audits/README.md) has a row and a JSON link for each record and
that every AUD-NNN-harnesses folder (and each subfolder holding scripts) has a README.md.
Exits 1 when it finds a disagreement.
"""
import json, re, sys
from pathlib import Path

AUDITS = Path("docs/audits")
problems = []
index = (AUDITS / "README.md").read_text()
for md in sorted(AUDITS.glob("audit-*.md")):
    number = int(md.name.split("-")[1])
    if number < 9:
        continue
    aid = f"AUD-{number:03d}"
    js = md.with_suffix(".json")
    if not js.exists():
        problems.append(f"{md.name}: no JSON companion")
        continue
    data = json.loads(js.read_text())
    jf = {f["id"]: (f.get("severity", "").lower(), f.get("status", "").lower())
          for f in data.get("findings", [])}
    mf = {}
    for line in md.read_text().splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells and re.fullmatch(rf"{aid}-[A-Z]+\d+", cells[0]):
            sev = next((c.lower() for c in cells if c.lower() in
                        ("critical", "high", "medium", "low", "info", "informational")), "")
            st = next((c.lower() for c in cells if c.lower() in
                       ("open", "fixed", "verified", "partly-fixed", "accepted", "wontfix",
                        "not-reproduced", "superseded", "partially-fixed")), "")
            mf.setdefault(cells[0], (sev, st))  # the register row, not later follow-up rows
    if set(mf) != set(jf):
        problems.append(f"{aid}: register IDs differ: only MD {sorted(set(mf)-set(jf))}, "
                        f"only JSON {sorted(set(jf)-set(mf))}")
    for k in set(mf) & set(jf):
        if mf[k][0] and mf[k][0] != jf[k][0]:
            problems.append(f"{aid}: {k} severity MD {mf[k][0]} JSON {jf[k][0]}")
        if mf[k][1] and mf[k][1] != jf[k][1]:
            problems.append(f"{aid}: {k} status MD {mf[k][1]} JSON {jf[k][1]}")
    if f"[{aid}]({md.name})" not in index:
        problems.append(f"index: no row for {aid}")
    if js.name not in index:
        problems.append(f"index: no JSON link for {aid}")
    print(f"{aid}: {len(mf)} MD register rows, {len(jf)} JSON findings")

for folder in sorted(AUDITS.glob("AUD-*-harnesses")):
    if folder.name in ("AUD-016-harnesses", "AUD-017-harnesses"):
        continue  # in progress
    for sub in [folder] + [p for p in folder.rglob("*") if p.is_dir() and p.name != "__pycache__"]:
        scripts = [p for p in sub.iterdir() if p.is_file() and p.suffix in
                   (".py", ".mjs", ".sh", ".rs", ".js")]
        if not (sub / "README.md").exists() and (sub == folder or scripts):
            # A subfolder is covered when its parent README names it, or it is the src/ of a
            # Rust probe crate whose folder has its own README.
            if sub.name == "src" and (sub.parent / "Cargo.toml").exists():
                continue
            parent = sub.parent / "README.md"
            if sub != folder and parent.exists() and sub.name in parent.read_text():
                continue
            problems.append(f"{sub}: no README.md")

for p in problems:
    print("PROBLEM", p)
print(f"{len(problems)} problems")
sys.exit(1 if problems else 0)
