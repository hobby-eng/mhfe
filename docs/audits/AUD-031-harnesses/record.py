"""Record one bounded public AUD-031 command, keeping evidence local only."""

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone


EVIDENCE = Path("docs/audits/AUD-031-evidence")
RESERVE_KIB = 3 * 1024 * 1024
BUDGET_KIB = 2 * 1024 * 1024
TIMEOUT_SECONDS = 15 * 60


def memory():
    fields = Path("/proc/meminfo").read_text().splitlines()
    return int(next(row.split()[1] for row in fields if row.startswith("MemAvailable:")))


def rss(pid):
    rows = subprocess.check_output(
        ["ps", "-eo", "pid=,ppid=,rss="], text=True,
    ).splitlines()
    processes = {int(a): (int(b), int(c)) for a, b, c in (row.split() for row in rows)}
    children = {pid}
    while True:
        found = {p for p, (parent, _) in processes.items() if parent in children}
        if found.issubset(children):
            break
        children.update(found)
    return sum(processes.get(p, (0, 0))[1] for p in children)


def source():
    baseline = json.loads((EVIDENCE / "snapshot.json").read_text())
    return {p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
            for p in baseline["sourceFiles"]}


def stop_group(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def main():
    if len(sys.argv) < 3:
        raise SystemExit("usage: record.py <unique-name> <command> [arguments...]")
    name, argv = sys.argv[1], sys.argv[2:]
    if not name or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in name):
        raise SystemExit("Invalid evidence name")
    receipt = EVIDENCE / (name + ".command.json")
    log = EVIDENCE / (name + ".log")
    if receipt.exists() or log.exists():
        raise SystemExit("Refusing to overwrite evidence")
    if memory() < RESERVE_KIB + BUDGET_KIB:
        raise SystemExit("Insufficient memory for budget and reserve")
    before = source()
    started = datetime.now(timezone.utc).isoformat()
    environment = {
        "CARGO_BUILD_JOBS": "1", "RUST_TEST_THREADS": "1", "EMCC_CORES": "1",
        "TZ": "UTC", "NODE_OPTIONS": "--max-old-space-size=768",
    }
    stopped = None
    peak = 0
    minimum = memory()
    with log.open("xb") as output:
        child = subprocess.Popen(
            argv, stdout=output, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True, env={**os.environ, **environment},
        )
        deadline = time.monotonic() + TIMEOUT_SECONDS
        try:
            while child.poll() is None:
                minimum = min(minimum, memory())
                peak = max(peak, rss(child.pid))
                if minimum < RESERVE_KIB or peak > BUDGET_KIB:
                    stopped = "memory-budget-or-reserve"
                if time.monotonic() > deadline:
                    stopped = "timeout"
                if stopped:
                    stop_group(child.pid)
                    break
                time.sleep(0.5)
        finally:
            if child.poll() is None:
                stop_group(child.pid)
            child.wait()
    after = source()
    result = {
        "argv": argv, "environment": environment, "startedUtc": started,
        "completedUtc": datetime.now(timezone.utc).isoformat(),
        "exitCode": child.returncode, "stoppedReason": stopped,
        "sourceBefore": before, "sourceAfter": after, "sourceUnchanged": before == after,
        "logSha256": hashlib.sha256(log.read_bytes()).hexdigest(),
        "peakDescendantRssKiB": peak, "minimumAvailableKiB": minimum,
        "reserveKiB": RESERVE_KIB, "budgetKiB": BUDGET_KIB,
        "limits": "Linux-only half-second conservative RSS sampling, not hard memory isolation.",
    }
    receipt.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ["exitCode", "stoppedReason", "sourceUnchanged"]}))
    raise SystemExit(0 if child.returncode == 0 and stopped is None else 1)


if __name__ == "__main__":
    main()
