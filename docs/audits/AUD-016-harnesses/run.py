#!/usr/bin/env python3
"""Capture AUD-016 command evidence and source snapshots; run from the repository root."""
import datetime
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-016-evidence"
OWN = ("docs/audits/AUD-016-", "docs/audits/audit-16-")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root).decode()


def snapshot(label):
    records = {}
    for name, root in (("mhfe", ROOT), ("mhfe_spec", ROOT.parent / "mhfe_spec")):
        files = sorted(set(filter(None, git(root, "ls-files", "-co", "--exclude-standard", "-z").split("\0"))))
        manifest = []
        code = []
        for path in files:
            if name == "mhfe" and path.startswith(OWN):
                continue
            file = root / path
            if not file.is_file():
                continue
            line = f"{digest(file.read_bytes())}  {path}\n"
            manifest.append(line)
            if not path.startswith("docs/audits/"):
                code.append(line)
        full = "".join(manifest)
        code_text = "".join(code)
        (EVIDENCE / f"{label}-{name}-manifest.txt").write_text(full)
        (EVIDENCE / f"{label}-{name}-code-manifest.txt").write_text(code_text)
        records[name] = {
            "capturedUtc": now(),
            "head": git(root, "rev-parse", "HEAD").strip(),
            "branch": git(root, "rev-parse", "--abbrev-ref", "HEAD").strip(),
            "status": git(root, "status", "--porcelain=v1").splitlines(),
            "files": len(manifest),
            "sourceFingerprint": digest(full.encode()),
            "codeFingerprint": digest(code_text.encode()),
        }
    (EVIDENCE / f"{label}.json").write_text(json.dumps(records, indent=2) + "\n")
    print(json.dumps({name: {k: value[k] for k in ("head", "files", "sourceFingerprint", "codeFingerprint")} for name, value in records.items()}))
    return 0


def run(label, argv):
    record_path = EVIDENCE / f"{label}.command.json"
    log_path = EVIDENCE / f"{label}.log"
    if record_path.exists() or log_path.exists():
        raise SystemExit("Evidence label already exists; use a new label for a rerun.")
    started = now()
    began = time.monotonic()
    peak_rss = 0
    stopped = None
    # Sum RSS conservatively (shared pages count per process); protect the host after its freeze.
    limit = 3 * 1024**3
    with log_path.open("wb") as output:
        process = subprocess.Popen(argv, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        while process.poll() is None:
            rss = 0
            for entry in Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    stat = (entry / "stat").read_text().rsplit(")", 1)[1].split()
                    if int(stat[2]) != process.pid:
                        continue
                    for line in (entry / "status").read_text().splitlines():
                        if line.startswith("VmRSS:"):
                            rss += int(line.split()[1]) * 1024
                except (FileNotFoundError, ProcessLookupError, PermissionError):
                    continue
            peak_rss = max(peak_rss, rss)
            if rss > limit or time.monotonic() - began > 1200:
                stopped = "memory-guard" if rss > limit else "timeout-1200s"
                os.killpg(process.pid, signal.SIGKILL)
                output.write(f"\nAUD-016 guard stopped command: {stopped}\n".encode())
                break
            time.sleep(0.25)
        code = process.wait()
    record = {
        "label": label,
        "argv": argv,
        "cwd": str(ROOT),
        "environment": {key: os.environ[key] for key in ("PATH", "CARGO_HOME", "RUSTUP_HOME", "RUSTFLAGS", "CARGO_BUILD_JOBS", "NODE_OPTIONS") if key in os.environ},
        "startUtc": started,
        "endUtc": now(),
        "seconds": round(time.monotonic() - began, 2),
        "exitCode": code,
        "processGroupPeakRssBytes": peak_rss,
        "rssLimitBytes": limit,
        "guardStopped": stopped,
        "logSha256": digest(log_path.read_bytes()),
    }
    record_path.write_text(json.dumps(record, indent=2) + "\n")
    print(f"{label}: exit {code} in {record['seconds']} s; peak RSS {peak_rss}; log {log_path.name}")
    return code


if __name__ == "__main__":
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    if len(sys.argv) == 3 and sys.argv[1] == "snapshot":
        sys.exit(snapshot(sys.argv[2]))
    if len(sys.argv) < 3:
        sys.exit("Usage: run.py LABEL COMMAND [ARGS...] | run.py snapshot LABEL")
    sys.exit(run(sys.argv[1], sys.argv[2:]))
