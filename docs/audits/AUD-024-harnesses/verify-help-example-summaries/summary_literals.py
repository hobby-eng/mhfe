#!/usr/bin/env python3
"""AUD-024 harness: fails when a command summary constant of the mhfe command-line tool
(`pub const *SUMMARY: &str = "...";` in src/bin/mhfe/) is typed again as a string literal anywhere
else in the non-test code of src/bin/mhfe/, instead of being used by name (CORE-10,
AUD-023-ARC006). A file's lines from its first `#[cfg(test)]` on are test code and are not read:
a test may type the value it expects.

Run from the repository root: python3 docs/audits/AUD-024-harnesses/verify-help-example-summaries/summary_literals.py
Exit 0: no summary literal is typed twice. Exit 1: each copy is printed as file:line.
"""
import pathlib
import re
import sys

root = pathlib.Path("src/bin/mhfe")
constant = re.compile(r'pub const (\w*SUMMARY): &str = "((?:[^"\\]|\\.)*)";')
files = sorted(root.rglob("*.rs"))
summaries = {}
for path in files:
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        match = constant.search(line)
        if match:
            summaries[match.group(2)] = (f"{path}:{number}", match.group(1))
if not summaries:
    print("no summary constants found: wrong working directory?")
    sys.exit(2)
copies = 0
for path in files:
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip() == "#[cfg(test)]":
            break
        for text, (where, name) in summaries.items():
            if f'"{text}"' in line and not constant.search(line):
                copies += 1
                print(f"{path}:{number} types {name} of {where} again: {text!r}")
print(f"{len(summaries)} summary constants, {copies} literal copies")
sys.exit(1 if copies else 0)
