"""Probe public CLI refusal/retry behavior without entering Argon2 work.

Linux/macOS Python PTY support is used instead of adding a Node PTY dependency.
Only the published zero-12 container and synthetic password/passphrase are sent.
"""

import errno
import hashlib
import json
import os
from pathlib import Path
import pty
import select
import signal
import sys
import time


DEADLINE_SECONDS = 15
TERMINATE_SECONDS = 2


class Session:
    """Own one disposable public-input CLI process and its bounded transcript."""

    def __init__(self, binary):
        self.transcript = bytearray()
        self.status = None
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.environ["TERM"] = "dumb"
            os.environ["NO_COLOR"] = "1"
            os.execv(binary, [binary, "check", "--fingerprint", "--pim", "0",
                             "--mem", "0"])
        self.deadline = time.monotonic() + DEADLINE_SECONDS

    def collect(self, check_recovery=True):
        """Read only currently available bytes, remembering actual process exit."""
        ready, _, _ = select.select([self.fd], [], [], 0.05)
        if ready:
            try:
                data = os.read(self.fd, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                data = b""
            self.transcript.extend(data)
        if self.status is None:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.status = os.waitstatus_to_exitcode(status)
        if check_recovery and b"Recovering" in self.transcript:
            raise RuntimeError("The refusal control unexpectedly reached recovery")

    def until(self, needle, start=0):
        """Require the actual prompt, not a guessed process delay."""
        while needle not in self.transcript[start:]:
            self.collect()
            if self.status is not None:
                raise RuntimeError("CLI exited before the expected public prompt")
            if time.monotonic() > self.deadline:
                raise TimeoutError("CLI prompt deadline exceeded")

    def send(self, value):
        os.write(self.fd, value + b"\n")

    def observe_exit(self):
        while self.status is None and time.monotonic() < self.deadline:
            self.collect()
        return self.status

    def close(self):
        """Always reap only the process owned by this control."""
        try:
            if self.status is None:
                try:
                    os.kill(self.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                end = time.monotonic() + TERMINATE_SECONDS
                while self.status is None and time.monotonic() < end:
                    self.collect(check_recovery=False)
        finally:
            try:
                if self.status is None:
                    try:
                        os.kill(self.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    _, status = os.waitpid(self.pid, 0)
                    self.status = os.waitstatus_to_exitcode(status)
            finally:
                os.close(self.fd)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: cli-refusal.py <binary> invalid-utf8|long-passphrase")
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    mode = sys.argv[2]
    if mode not in ("invalid-utf8", "long-passphrase"):
        raise SystemExit("Unknown public refusal control")
    vector = json.loads(Path("tests/fixtures/suite3-vectors/zero-12.json").read_text())
    session = Session(binary)
    try:
        session.until(b"Container, 24 words")
        session.send(vector["container"].encode())
        session.until(b"Enter: ")
        session.send(b"")
        session.until(b"Container password")
        session.send(b"public test password")
        session.until(b"Master key fingerprint, eight hex digits")
        # Benign malformed reference must retry; this proves the prompt/control is live.
        before = len(session.transcript)
        session.send(b"not-a-fingerprint")
        session.until(b"Master key fingerprint, eight hex digits", before)
        if mode == "invalid-utf8":
            session.send(b"\xff")
        else:
            session.send(b"00000000")
            session.until(b"BIP39 passphrase of the wallet")
            session.send(b"x" * 1025)
        status = session.observe_exit()
        refused = (
            b"not valid UTF-8" in session.transcript
            if mode == "invalid-utf8"
            else b"passphrase" in session.transcript and b"1024" in session.transcript
        )
        print(json.dumps({
            "mode": mode,
            "benignMalformedReferenceRetried": True,
            "exitCode": status,
            "refusalObserved": refused,
            "recoveryStarted": False,
            "binarySha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
            "transcriptSha256": hashlib.sha256(session.transcript).hexdigest(),
            "expected": "Explain invalid interactive input and ask again",
            "observed": "CLI ended after the refused input" if status == 2 else
                        "No matching premature exit established",
        }), flush=True)
        if status != 2 or not refused:
            raise SystemExit("The proposed premature-exit finding was not reproduced")
    finally:
        session.close()
        output = Path("docs/audits/AUD-032-evidence")
        output.mkdir(parents=True, exist_ok=True)
        transcript = output / f"{mode}-{time.time_ns()}.transcript"
        transcript.write_bytes(session.transcript)


if __name__ == "__main__":
    main()
