"""Probe the real CLI's hidden password prompt, stopping before any wallet/KDF operation."""

import errno
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
subprocess.run(["cargo", "build", "--locked", "--offline", "--bin", "mhfe"], cwd=ROOT, check=True)
container = json.loads((ROOT / "tests/fixtures/suite3-vectors/zero-12.json").read_text())["container"]
failures = 0

for password in (b"a\tb", b"a\x00b", b"a\xc2\x85b"):
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["NO_COLOR"] = "1"
        os.execv(str(ROOT / "target/debug/mhfe"), ["mhfe", "check", "--fingerprint"])
    output = bytearray()

    def until(markers):
        deadline = time.monotonic() + 5
        start = len(output)
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0.1)[0]:
                try:
                    chunk = os.read(fd, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                output.extend(chunk)
                for marker in markers:
                    if marker in output[start:]:
                        return marker
        raise AssertionError("Expected prompt not reached: " + repr(output))

    try:
        until([b"Container, 24 words:"])
        os.write(fd, container.encode() + b"\n")
        until([b"Password (hidden):"])
        os.write(fd, password + b"\n")
        reached = until([b"Master key fingerprint", b"Please type it again"])
        print(f"Public password bytes {password.hex()}: next prompt {reached.decode()}")
        print("Stopped before providing a fingerprint; no memory reservation or Argon2 call.")
        failures += reached == b"Master key fingerprint"
    finally:
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        os.close(fd)

raise SystemExit(1 if failures else 0)
