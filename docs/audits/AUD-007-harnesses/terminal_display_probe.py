#!/usr/bin/env python3
"""Compile current terminal modules and show only the public BIP39 zero vector."""

import datetime
import hashlib
import json
import os
from pathlib import Path
import pty
import subprocess

REPO = Path(__file__).resolve().parents[3]
EVIDENCE = REPO / "docs/audits/AUD-007-evidence"
EVIDENCE.mkdir(parents=True, exist_ok=True)
DEPENDENCIES = REPO / "target/debug/deps"
MODULES = ("choice", "exit", "hidden_input", "style", "terminal")
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
source = Path(__file__).with_suffix(".rs")
binary = EVIDENCE / "terminal_display_probe"

command = [
    str(REPO.parent / "workingspace/cargo/bin/rustc"),
    "--edition=2021",
    str(source),
    "-L",
    f"dependency={DEPENDENCIES}",
    "-o",
    str(binary),
]
for crate in ("mhfe", "anstream", "anstyle", "zeroize", "libc", "ctrlc", "clap"):
    library = max(DEPENDENCIES.glob(f"lib{crate}-*.rlib"), key=lambda p: p.stat().st_mtime_ns)
    command.extend(("--extern", f"{crate}={library}"))
environment = os.environ.copy()
environment["CARGO_HOME"] = str(REPO.parent / "workingspace/cargo")
environment["RUSTUP_HOME"] = str(REPO.parent / "workingspace/rustup")
compiled = subprocess.run(command, cwd=REPO, env=environment, text=True, capture_output=True)
log = ["COMPILE", compiled.stdout, compiled.stderr]
(EVIDENCE / "terminal-display.log").write_text("\n".join(log))
assert compiled.returncode == 0, compiled.stderr
master, slave = pty.openpty()
environment["TERM"] = "xterm-256color"
environment["NO_COLOR"] = "1"
try:
    result = subprocess.run(
        [str(binary)], stdin=slave, stderr=slave, stdout=subprocess.PIPE,
        cwd=REPO, env=environment, timeout=10,
    )
    os.close(slave)
    slave = -1
    diagnostics = os.read(master, 65536).decode()
finally:
    if slave >= 0:
        os.close(slave)
    os.close(master)
log.extend(("REDIRECTED_STDOUT", result.stdout.decode(), "PTY_STDERR", diagnostics))
assert result.returncode == 0
assert "AUDIT_PRIVATE_SCREEN_ACTIVE=false" in diagnostics
assert b"abandon abandon abandon" in result.stdout
assert b"about" in result.stdout
(EVIDENCE / "terminal-display.log").write_text("\n".join(log))
(EVIDENCE / "terminal-display.command.json").write_text(json.dumps({
    "started_at": started,
    "ended_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "command": command,
    "probe_command": [str(binary)],
    "cwd": str(REPO),
    "exit_code": result.returncode,
    "public_input": "BIP39 128-bit zero entropy vector",
    "source_sha256": {
        module: hashlib.sha256((REPO / f"src/bin/mhfe/{module}.rs").read_bytes()).hexdigest()
        for module in MODULES
    },
}, indent=2) + "\n")
print("PASS: current enter_to_show returned inactive with redirected stdout; current print_phrase emitted the public mnemonic to that pipe.")
