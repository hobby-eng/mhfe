#!/usr/bin/env python3
"""AUD-044 SEC probe: what memscan logged, by scan: the secrets found in each kind of memory, and
how many blocks went back to the allocator with a secret in them after the note `from_note`.

    summarize.py <memscan.log> [from_note]
"""
import sys
from collections import Counter

NOISE = ("word-word",)
scans = []
freed = Counter()
current = None
label = None
counting = len(sys.argv) < 3
for line in open(sys.argv[1], encoding="ascii"):
    line = line.rstrip("\n")
    if len(sys.argv) > 2 and sys.argv[2] in line:
        counting = True
    if line.startswith("=== scan at:"):
        label = line[13:]
    elif line == "scan-begin":
        current = {}
    elif line == "scan-end":
        scans.append((label, current))
        current = None
    elif line.startswith("scan ") and current is not None:
        parts = line.split(" ")
        if len(parts) == 4 and parts[2] not in NOISE:
            current.setdefault(parts[1], {})[parts[2]] = int(parts[3])
    elif line.startswith(("free ", "realloc-moved ")) and counting:
        # A line of the driver's can run into one of the program's in the shared log.
        parts = line.split(" ")
        if len(parts) == 3 and parts[1] not in NOISE:
            freed[(parts[0], parts[1])] += 1
for label, regions in scans:
    print("## scan at:", label)
    for region, hits in regions.items():
        print("  ", region, " ".join("%s:%d" % item for item in sorted(hits.items())))
print("## blocks that went back with a secret in them")
for (kind, needle), count in sorted(freed.items()):
    print("  ", kind, needle, count)
