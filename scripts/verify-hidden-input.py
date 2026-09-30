"""Checks the hidden terminal input of the mhfe tool in a pseudo-terminal (Linux and macOS).

    python3 scripts/verify-hidden-input.py [path/to/mhfe]

The default is target/debug/mhfe. It drives `mhfe check --fingerprint`, which asks for the
container and then for the password at a hidden prompt, and stops the tool before a fingerprint is given,
so no memory is reserved and Argon2 never runs. Only the public zero-12 test container is used.

It checks that
- every control character in a password reaches the password check and is refused, including
  the ones a terminal would otherwise act on (Ctrl+S, Ctrl+Q, Ctrl+V, Ctrl+W, Ctrl+R, Ctrl+O,
  Ctrl+\\, Ctrl+Z and Ctrl+D inside the line), and that a Unicode password is accepted, also the
  longest one: 1024 characters U+1D400, 4096 bytes that NFKD turns into 1024;
- Backspace and Ctrl+U still edit a hidden line: a TAB typed and then deleted leaves an accepted
  password;
- nothing typed at a hidden prompt is shown;
- Ctrl+C at a hidden prompt ends the tool with exit code 130;
- the terminal settings are exactly the original ones afterwards, after a normal answer and after
  Ctrl+C.
"""

import fcntl
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import termios
import time

ROOT = Path(__file__).resolve().parent.parent
PROGRAM = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "target/debug/mhfe")
CONTAINER = json.loads((ROOT / "tests/fixtures/suite3-vectors/zero-12.json").read_text())["container"]
# Exit code of the tool when the person cancels (src/bin/mhfe/exit.rs).
CANCELLED = 130
# What the tool prints next after each kind of answer. An accepted one leads to the fingerprint.
# A refused password is asked again ("Please type it again").
REFUSED = b"again"
ACCEPTED = b"ingerprint"
BACKSPACE, CTRL_U, CTRL_C = b"\x7f", b"\x15", b"\x03"
# The control characters a terminal in its usual mode acts on instead of passing them on.
TERMINAL_KEYS = {
    "Ctrl+S": b"\x13",
    "Ctrl+Q": b"\x11",
    "Ctrl+V": b"\x16",
    "Ctrl+W": b"\x17",
    "Ctrl+R": b"\x12",
    "Ctrl+O": b"\x0f",
    "Ctrl+\\": b"\x1c",
    "Ctrl+Z": b"\x1a",
}
OTHER_CONTROLS = {
    "TAB": b"\t",
    "NUL": b"\x00",
    "U+0085": "\u0085".encode(),
    "Ctrl+D inside the line": b"\x04",
}
# The longest valid password: 4096 bytes typed, 1024 bytes after NFKD. A terminal in line mode
# would cut it after 4095 bytes on Linux.
LONGEST = "\U0001D400".encode() * 1024
SECRET = b"synthetic"


def attach_terminal():
    """Makes the pseudo-terminal the controlling terminal, so that Ctrl+C sends SIGINT."""
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


class Session:
    def __init__(self):
        self.master, self.slave = os.openpty()
        os.set_blocking(self.master, False)
        # The settings are read through the master side: on macOS the slave side stops answering
        # once the tool, the leader of its session, has ended, because the system revokes the
        # terminal of an ended session. The master side reads the same terminal on every system.
        self.original = termios.tcgetattr(self.master)
        environment = dict(os.environ, NO_COLOR="1")
        self.process = subprocess.Popen(
            [PROGRAM, "check", "--fingerprint"],
            stdin=self.slave, stdout=self.slave, stderr=self.slave,
            start_new_session=True, preexec_fn=attach_terminal, env=environment,
        )
        self.output = b""

    def wait_for(self, *needles, limit=10):
        """Reads until one of `needles` appears after the text already seen; returns it."""
        start = len(self.output)
        end = time.monotonic() + limit
        while time.monotonic() < end:
            if select.select([self.master], [], [], 0.1)[0]:
                try:
                    self.output += os.read(self.master, 4096)
                except OSError:
                    break
            for needle in needles:
                if needle in self.output[start:]:
                    return needle
        raise AssertionError(f"none of {needles} in {self.output[start:]!r}")

    def type(self, data, limit=10):
        """Writes `data` as pasted text; the line only ends at the carriage return.

        A pseudo-terminal holds little input (about 1 KiB on macOS), so a long paste is written
        in parts as the tool reads them. The tool's output is read meanwhile, so that neither
        side waits for the other, and a tool that stops reading fails the check instead of
        blocking it for ever.
        """
        end = time.monotonic() + limit
        while data:
            if time.monotonic() > end:
                raise AssertionError(f"the tool stopped reading; {len(data)} bytes left to type")
            readable, writable, _ = select.select([self.master], [self.master], [], 0.1)
            if readable:
                try:
                    self.output += os.read(self.master, 4096)
                except OSError:
                    pass
            if writable:
                try:
                    data = data[os.write(self.master, data):]
                except BlockingIOError:
                    pass

    def close(self):
        """Ends the tool as a person would, with Ctrl+C, so that it can restore the terminal."""
        if self.process.poll() is None:
            self.type(CTRL_C)
            if not self.drain_until_exit(5):
                # SIGKILL leaves the terminal as it is; the settings check below then fails.
                self.process.send_signal(signal.SIGKILL)
        if not self.drain_until_exit(10):
            raise AssertionError("the tool did not end")
        code = self.process.returncode
        settings = termios.tcgetattr(self.master)
        os.close(self.master)
        os.close(self.slave)
        return code, settings

    def drain_until_exit(self, limit):
        """Waits up to `limit` seconds for the tool to end, reading its output meanwhile.

        On macOS a process that ends waits until the terminal has delivered its last output, which
        happens only when this side reads it; without reading, the tool never finishes exiting.
        """
        end = time.monotonic() + limit
        while self.process.poll() is None:
            if time.monotonic() > end:
                return False
            if select.select([self.master], [], [], 0.1)[0]:
                try:
                    self.output += os.read(self.master, 4096)
                except OSError:
                    time.sleep(0.05)
        return True

    def at_password_prompt(self):
        self.wait_for(b"words: ")
        self.type(CONTAINER.encode() + b"\r")
        self.wait_for(b"Password")


def check_password(label, password, expected):
    session = Session()
    try:
        session.at_password_prompt()
        session.type(password + b"\r")
        seen = session.wait_for(REFUSED, ACCEPTED)
        assert seen == expected, f"{label}: expected {expected!r}, the tool answered {seen!r}"
        assert SECRET not in session.output, f"{label}: the password was shown"
    finally:
        code, settings = session.close()
    assert settings == session.original, f"{label}: the terminal settings were not restored"
    return code


def main():
    # Each result is shown at once, so that a CI log shows how far the checks came.
    sys.stdout.reconfigure(line_buffering=True)
    for label, key in {**TERMINAL_KEYS, **OTHER_CONTROLS}.items():
        check_password(label, SECRET + key + b"x", REFUSED)
        print(f"refused: a password with {label}")
    check_password("Unicode", SECRET + "пароль".encode(), ACCEPTED)
    print("accepted: a Unicode password")
    check_password("1024 x U+1D400", LONGEST, ACCEPTED)
    print("accepted: the longest valid password, 4096 bytes before normalization")
    # A TAB would be refused, so the password is accepted only if the key really deleted it.
    check_password("Backspace", SECRET + b"\t" + BACKSPACE, ACCEPTED)
    check_password("Ctrl+U", b"\t" + CTRL_U + SECRET, ACCEPTED)
    print("edited: Backspace and Ctrl+U at a hidden prompt")

    session = Session()
    session.at_password_prompt()
    session.type(SECRET + CTRL_C)
    session.wait_for(b"Cancelled")
    code, settings = session.close()
    assert code == CANCELLED, f"Ctrl+C: exit code {code}"
    assert settings == session.original, "Ctrl+C: the terminal settings were not restored"
    print("cancelled: Ctrl+C at a hidden prompt, exit code 130, terminal restored")


if __name__ == "__main__":
    main()
