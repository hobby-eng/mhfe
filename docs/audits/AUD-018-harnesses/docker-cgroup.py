#!/usr/bin/env python3
"""Check BuildKit RUN cgroup inheritance from host /proc; no project build occurs."""

import json
import subprocess
import sys
import time
from pathlib import Path

parent = sys.argv[1]
marker = b"AUD018_CGROUP_WITNESS"
dockerfile = "FROM alpine:3.20\nRUN /bin/sh -c 'sleep 5; : AUD018_CGROUP_WITNESS'\n"
process = subprocess.Popen(
    ["docker", "buildx", "build", "--no-cache", "--progress=plain", "--cgroup-parent", parent, "-"],
    stdin=subprocess.PIPE,
)
process.stdin.write(dockerfile.encode())
process.stdin.close()
witnesses = []
while process.poll() is None:
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if (entry / "comm").read_text().strip() not in {"sh", "ash"}:
                continue
            if marker not in (entry / "cmdline").read_bytes():
                continue
            group = (entry / "cgroup").read_text().strip().split("::", 1)[1]
            record = {"pid": int(entry.name), "cgroup": group, "expectedParent": parent}
            expected = Path("/sys/fs/cgroup") / parent.lstrip("/")
            record["parentMemoryMax"] = (expected / "memory.max").read_text().strip()
            record["parentSwapMax"] = (expected / "memory.swap.max").read_text().strip()
            if record not in witnesses:
                witnesses.append(record)
        except (FileNotFoundError, PermissionError, ProcessLookupError, IndexError):
            continue
    time.sleep(0.1)
code = process.wait()
passed = code == 0 and bool(witnesses) and all(
    item["cgroup"].startswith(parent + "/")
    and item["parentMemoryMax"] == "4294967296"
    and item["parentSwapMax"] == "0"
    for item in witnesses
)
print(json.dumps({"dockerExit": code, "witnesses": witnesses, "passed": passed}))
sys.exit(0 if passed else 1)
