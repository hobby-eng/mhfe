#!/usr/bin/env python3
"""Record a bounded AUD-008 command without overwriting prior evidence."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-008-evidence"


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    argv = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not argv or not args.label.replace("-", "").replace("_", "").isalnum():
        parser.error("A command and a simple unique label are required.")
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    log = EVIDENCE / (args.label + ".log")
    ledger = EVIDENCE / (args.label + ".command.json")
    if log.exists() or ledger.exists():
        parser.error("Evidence exists; choose a new label.")
    record = {"argv": argv, "command": shlex.join(argv), "cwd": str(ROOT),
              "startedAt": now(), "timeoutSeconds": args.timeout,
              "environment": {k: os.environ[k] for k in
                  ("PATH", "CARGO_HOME", "RUSTUP_HOME", "CARGO_BUILD_JOBS", "RUST_TEST_THREADS", "EMCC_CORES") if k in os.environ}}
    with log.open("wb") as output:
        try:
            process = subprocess.Popen(argv, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            try:
                record["exitCode"] = process.wait(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                record.update(exitCode=124, timedOut=True)
        except OSError as error:
            output.write((str(error) + "\n").encode())
            record["exitCode"] = 127
    content = log.read_bytes()
    record.update(finishedAt=now(), logSha256=hashlib.sha256(content).hexdigest(), logBytes=len(content))
    ledger.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({k: record[k] for k in ("command", "exitCode", "logSha256", "logBytes")}))
    print(content[-10000:].decode(errors="replace"))
    return record["exitCode"]


if __name__ == "__main__":
    raise SystemExit(main())
