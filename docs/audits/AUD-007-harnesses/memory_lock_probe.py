#!/usr/bin/env python3
"""Exercise overlapping lock lifetimes with zero bytes and public test passwords."""

import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess

REPO = Path(__file__).resolve().parents[3]
EVIDENCE = REPO / "docs/audits/AUD-007-evidence"
EVIDENCE.mkdir(parents=True, exist_ok=True)
DEPENDENCIES = REPO / "target/debug/deps"
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
source = Path(__file__).with_suffix(".rs")
binary = EVIDENCE / "memory_lock_probe"

library = max(DEPENDENCIES.glob("libmhfe-*.rlib"), key=lambda p: p.stat().st_mtime_ns)
command = [
    str(REPO.parent / "workingspace/cargo/bin/rustc"), "--edition=2021", str(source),
    "-L", f"dependency={DEPENDENCIES}", "--extern", f"mhfe={library}",
    "-o", str(binary),
]
environment = os.environ.copy()
environment["CARGO_HOME"] = str(REPO.parent / "workingspace/cargo")
environment["RUSTUP_HOME"] = str(REPO.parent / "workingspace/rustup")
compiled = subprocess.run(command, cwd=REPO, env=environment, text=True, capture_output=True)
log = ["COMPILE", compiled.stdout, compiled.stderr]
assert compiled.returncode == 0, compiled.stderr
result = subprocess.run([str(binary)], cwd=REPO, env=environment, text=True, capture_output=True, timeout=10)
log.extend(("RUN", result.stdout, result.stderr))
(EVIDENCE / "memory-lock.log").write_text("\n".join(log))
(EVIDENCE / "memory-lock.command.json").write_text(json.dumps({
    "started_at": started,
    "ended_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "command": command,
    "probe_command": [str(binary)],
    "cwd": str(REPO), "exit_code": result.returncode,
    "input": "8192 zero bytes and public test password alpha; no real wallet material",
    "library_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
    "memory_source_sha256": hashlib.sha256((REPO / "src/memory.rs").read_bytes()).hexdigest(),
}, indent=2) + "\n")
assert result.returncode == 0, result.stderr
print(result.stdout.strip())
