#!/usr/bin/env python3
"""Build the bounded io_uring diagnostic against the unchanged production isolation module."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

repo = Path(__file__).resolve().parents[3]
harness = Path(__file__).resolve().parent
evidence = repo / "docs/audits/AUD-008-evidence"
evidence.mkdir(exist_ok=True)
libc = max((repo / "target/debug/deps").glob("liblibc-*.rlib"), key=lambda path: path.stat().st_mtime)
env = os.environ.copy()
env.update(CARGO_HOME=str(repo.parent / "workingspace/cargo"), RUSTUP_HOME=str(repo.parent / "workingspace/rustup"))
commands = [
    ["cc", "-O1", "-Wall", "-Wextra", "-c", str(harness / "secrets-uring.c"), "-o", str(evidence / "secrets-uring.o")],
    [str(repo.parent / "workingspace/cargo/bin/rustc"), "--edition=2021", str(harness / "secrets-uring.rs"), "--crate-name", "aud008_secrets_uring", "-L", f"dependency={repo / 'target/debug/deps'}", "--extern", f"libc={libc}", "-C", f"link-arg={evidence / 'secrets-uring.o'}", "-o", str(evidence / "secrets-uring-probe")],
]
start = datetime.datetime.now(datetime.timezone.utc).isoformat()
logs = []
exit_code = 0
for command in commands:
    result = subprocess.run(command, cwd=repo, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logs.append(result.stdout)
    exit_code = result.returncode
    if exit_code:
        break
output = b"\n".join(logs)
(evidence / "secrets-uring-rebuild.log").write_bytes(output)
record = {"commands": commands, "cwd": str(repo), "startUtc": start, "endUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "exitCode": exit_code, "logSha256": hashlib.sha256(output).hexdigest(), "sourceSha256": hashlib.sha256((repo / "src/bin/mhfe/protect.rs").read_bytes()).hexdigest()}
(evidence / "secrets-uring-rebuild.command.json").write_text(json.dumps(record, indent=2) + "\n")
print(output.decode())
print(json.dumps(record))
sys.exit(exit_code)
