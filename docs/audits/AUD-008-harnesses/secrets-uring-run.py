#!/usr/bin/env python3
"""Record a bounded production-isolation diagnostic using synthetic loopback data only."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

repo = Path(__file__).resolve().parents[3]
evidence = repo / "docs/audits/AUD-008-evidence"
command = [str(evidence / "secrets-uring-probe")]
start = datetime.datetime.now(datetime.timezone.utc).isoformat()
result = subprocess.run(command, cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5)
end = datetime.datetime.now(datetime.timezone.utc).isoformat()
(evidence / "secrets-uring-host.log").write_bytes(result.stdout)
record = {"command": command, "cwd": str(repo), "startUtc": start, "endUtc": end, "exitCode": result.returncode, "logSha256": hashlib.sha256(result.stdout).hexdigest(), "sourceSha256": hashlib.sha256((repo / "src/bin/mhfe/protect.rs").read_bytes()).hexdigest()}
(evidence / "secrets-uring-host.command.json").write_text(json.dumps(record, indent=2) + "\n")
print(result.stdout.decode())
print(json.dumps(record))
sys.exit(result.returncode)
