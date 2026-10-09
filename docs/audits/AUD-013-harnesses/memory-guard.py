"""Run one audit command with Linux RSS and available-memory sampling, public data only."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

GIB = 1024**3
MAX_RSS = 3 * GIB
RESERVE = 2 * GIB
EVIDENCE = Path("docs/audits/AUD-013-evidence")
label, *command = sys.argv[1:]
if not command or not label.replace("-", "").isalnum():
    raise SystemExit("Supply label and command arguments")
EVIDENCE.mkdir(parents=True, exist_ok=True)


def available():
    fields = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        fields[key] = int(value.split()[0]) * 1024
    room = fields["MemAvailable"]
    # Honor finite cgroup-v2 limits where the normal Linux mount is exposed.
    try:
        group = next(line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
                     if line.startswith("0::"))
        directory = Path("/sys/fs/cgroup") / group.lstrip("/")
        while directory.is_relative_to("/sys/fs/cgroup"):
            maximum = (directory / "memory.max").read_text().strip()
            if maximum != "max":
                current = int((directory / "memory.current").read_text())
                stats = dict(line.split() for line in (directory / "memory.stat").read_text().splitlines())
                room = min(room, max(0, int(maximum) - current + int(stats.get("inactive_file", 0))))
            if directory == Path("/sys/fs/cgroup"):
                break
            directory = directory.parent
    except (OSError, StopIteration, ValueError):
        pass
    return room


def processes(root):
    info = {}
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            tail = (directory / "stat").read_text().rsplit(")", 1)[1].split()
            info[int(directory.name)] = (int(tail[1]), int(tail[19]), int(tail[21]))
        except (OSError, ValueError, IndexError):
            continue
    ids = {root}
    while True:
        more = {pid for pid, (parent, _, _) in info.items() if parent in ids}
        if more <= ids:
            break
        ids |= more
    return {pid: info[pid] for pid in ids if pid in info}


start_room = available()
record = {"command": command, "maxAggregateRssBytes": MAX_RSS,
          "minimumAvailableBytes": RESERVE, "initialAvailableBytes": start_room,
          "peakRssBytes": 0, "lowestAvailableBytes": start_room, "samples": 0,
          "limitations": "Sampled RSS sums may count shared pages twice; no hard allocation cap or OS diagnosis."}
if start_room < RESERVE + GIB:
    record["stoppedReason"] = "insufficient available memory before start"
    record["exitCode"] = 75
else:
    child = subprocess.Popen(command, start_new_session=True)
    reason = None
    while child.poll() is None:
        owned = processes(child.pid)
        rss = sum(max(0, item[2]) for item in owned.values()) * os.sysconf("SC_PAGE_SIZE")
        room = available()
        record["peakRssBytes"] = max(record["peakRssBytes"], rss)
        record["lowestAvailableBytes"] = min(record["lowestAvailableBytes"], room)
        record["samples"] += 1
        if rss > MAX_RSS or room < RESERVE:
            reason = "RSS budget exceeded" if rss > MAX_RSS else "available memory reserve reached"
            # Signal only still-owned processes, including descendants that made new groups.
            for pid in reversed(list(owned)):
                try:
                    if processes(child.pid).get(pid, (None, None, None))[1] == owned[pid][1]:
                        os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
            break
        time.sleep(1)
    record["exitCode"] = child.wait()
    record["stoppedReason"] = reason
(EVIDENCE / f"{label}.memory.json").write_text(json.dumps(record, indent=2) + "\n")
print(json.dumps(record))
raise SystemExit(75 if record.get("stoppedReason") else record["exitCode"])
