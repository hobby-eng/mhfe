"""Record bounded audit commands, memory observations and source snapshots."""

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = Path.cwd()
AUDIT = os.environ.get("AUDIT_ID", "AUD-014")
DIRECTORY = ROOT / "docs/audits" / (AUDIT + "-evidence")
DIRECTORY.mkdir(parents=True, exist_ok=True)
MAX_RSS = 3 * 1024**3
RESERVE = 2 * 1024**3
START_RESERVE = 3 * 1024**3


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(label, value):
    (DIRECTORY / label).write_text(json.dumps(value, indent=2) + "\n")


def git(*arguments):
    return subprocess.check_output(["git", *arguments], cwd=ROOT).decode()


def available():
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    raise RuntimeError("MemAvailable is unavailable")


def group_rss(group):
    total = 0
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == group:
                total += int((entry / "statm").read_text().split()[1]) * os.sysconf("SC_PAGE_SIZE")
        except (OSError, ValueError, IndexError):
            continue
    return total


label, *command = sys.argv[1:]
if not label or not command:
    raise SystemExit("Supply LABEL and COMMAND, or LABEL snapshot")
if command == ["snapshot"]:
    paths = sorted(set(path for path in git("ls-files", "-c", "-o", "--exclude-standard", "-z")
                       .split("\0") if path and not path.startswith("docs/audits/")))
    records = [[path, digest(ROOT / path) if (ROOT / path).exists() else "deleted"] for path in paths]
    fingerprint = hashlib.sha256(json.dumps(records, separators=(",", ":"),
                                            ensure_ascii=False).encode()).hexdigest()
    procedures = ["docs/FULL_AUDIT_GUIDE.md", "docs/audits/AUDIT_STANDARD.md",
                  "docs/audits/AUDIT_TEMPLATE.md", "docs/audit-report.schema.json"]
    procedure_hashes = {"multi-chain-wallet-tools/" + path:
                        digest(ROOT.parent / "multi-chain-wallet-tools" / path)
                        for path in procedures}
    artifacts = {path: digest(ROOT / path) for path in ["target/release/mhfe",
                  "target/release/libmhfe.rlib", "dist/runtime/mhfe.wasm", "dist/modules.json"]
                 if (ROOT / path).exists()}
    value = {"capturedAt": now(), "head": git("rev-parse", "HEAD").strip(),
             "status": git("status", "--short"), "sourceFingerprint": fingerprint,
             "records": records, "procedureHashes": procedure_hashes, "artifacts": artifacts}
    save(label + ".json", value)
    print(json.dumps({**value, "records": len(records)}, indent=2))
    raise SystemExit(0)

initial_available = available()
started = now()
peak = 0
lowest = initial_available
samples = 0
stopped = None
log = DIRECTORY / (label + ".log")
if initial_available < START_RESERVE:
    stopped = "Insufficient available memory at startup"
    log.write_text(stopped + "\n")
    result = 75
else:
    with log.open("wb") as output:
        process = subprocess.Popen(command, cwd=ROOT, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        while process.poll() is None:
            rss = group_rss(process.pid)
            remaining = available()
            peak = max(peak, rss)
            lowest = min(lowest, remaining)
            samples += 1
            if rss > MAX_RSS or remaining < RESERVE:
                stopped = "Owned process RSS budget exceeded" if rss > MAX_RSS else "Available memory reserve crossed"
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                break
            time.sleep(0.25)
        result = 75 if stopped else process.wait()
value = {"command": command, "cwd": str(ROOT), "startedAt": started, "endedAt": now(),
         "exitCode": result, "stoppedReason": stopped, "logSha256": digest(log),
         "toolchainEnvironment": {key: os.environ.get(key) for key in ["CARGO_HOME", "RUSTUP_HOME"]},
         "memory": {"rssBudgetBytes": MAX_RSS, "availableReserveBytes": RESERVE,
                    "initialAvailableBytes": initial_available, "peakRssBytes": peak,
                    "minimumAvailableBytes": lowest, "samples": samples,
                    "limitations": "Sampled process-group RSS can count shared pages twice; not a hard allocation cap or freeze diagnosis."}}
save(label + ".command.json", value)
print(log.read_text(errors="replace")[-12000:])
print(json.dumps(value, indent=2))
raise SystemExit(result if result >= 0 else 128 - result)
