"""Shared helpers of the AUD-010 cli-terminal probes: running mhfe in a pipe or in a
pseudo-terminal of 80 x 24, and reading its colour codes. Linux only; public test data only."""

import fcntl
import os
import re
import resource
import select
import signal
import struct
import subprocess
import termios
import time

# The variables that turn colour on or off for anstream and clap (anstyle-query), removed from the
# inherited environment so that each run sets only its own.
COLOUR_VARIABLES = ("NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "TERM", "CI", "COLORTERM")
# Large enough for the checks at start (Argon2 at 1 MiB), too small for the 2 GiB of memory level
# 0, so that a command stops at the reservation (exit code 4) before any Argon2 round.
ADDRESS_SPACE_CAP = 1 << 30
# Every SGR escape sequence ("\x1b[...m") and every other CSI sequence.
SGR = re.compile(rb"\x1b\[([0-9;]*)m")
CSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-ln-z]")
# SGR parameters of the sixteen standard colours and the styles the terminal rules allow: reset,
# bold, normal intensity, default colour, the eight colours and their eight bright forms.
ALLOWED_SGR = {0, 1, 22, 39} | set(range(30, 38)) | set(range(90, 98))

ZERO_12 = (
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)
# The public BIP39 vector of 32 zero bytes, a valid 24-word phrase and so a valid container.
ZERO_24 = " ".join(["abandon"] * 23 + ["art"])


def environment(**settings):
    env = {name: value for name, value in os.environ.items() if name not in COLOUR_VARIABLES}
    env.setdefault("TERM", "xterm-256color")
    for name, value in settings.items():
        if value is None:
            env.pop(name, None)
        else:
            env[name] = value
    return env


def run_pipe(program, arguments, stdin=b"", capped=False, **settings):
    """Runs the tool with standard input, output and error as pipes; returns (code, out, err)."""

    def limit():
        resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_CAP, ADDRESS_SPACE_CAP))

    done = subprocess.run(
        [program, *arguments],
        input=stdin,
        capture_output=True,
        env=environment(**settings),
        preexec_fn=limit if capped else None,
        timeout=120,
    )
    return done.returncode, done.stdout, done.stderr


def sgr_parameters(data):
    """Every SGR parameter used in `data`."""
    found = set()
    for match in SGR.finditer(data):
        text = match.group(1).decode()
        for part in (text or "0").split(";"):
            found.add(int(part) if part else 0)
    return found


def plain(data):
    return CSI.sub(b"", SGR.sub(b"", data))


def visible_width(line):
    return len(plain(line).decode("utf-8", "replace"))


class Pty:
    """The tool on a pseudo-terminal of 80 columns and 24 rows as its controlling terminal."""

    def __init__(self, program, arguments, columns=80, rows=24, **settings):
        self.master, self.slave = os.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
        os.set_blocking(self.master, False)

        def attach():
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        self.process = subprocess.Popen(
            [program, *arguments],
            stdin=self.slave,
            stdout=self.slave,
            stderr=self.slave,
            start_new_session=True,
            preexec_fn=attach,
            env=environment(**settings),
        )
        self.output = b""

    def _read(self):
        if select.select([self.master], [], [], 0.1)[0]:
            try:
                self.output += os.read(self.master, 65536)
            except OSError:
                time.sleep(0.05)

    def wait_for(self, needle, limit=20, since=0):
        end = time.monotonic() + limit
        while time.monotonic() < end:
            if needle in self.output[since:]:
                return True
            if self.process.poll() is not None:
                self._read()
                return needle in self.output[since:]
            self._read()
        return False

    def type(self, data):
        os.write(self.master, data)

    def idle(self, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self._read()

    def finish(self, limit=60):
        """Waits for the tool to end, reading its output; kills it after `limit` seconds."""
        end = time.monotonic() + limit
        while self.process.poll() is None and time.monotonic() < end:
            self._read()
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGKILL)
            self.process.wait()
        self.idle(0.3)
        os.close(self.master)
        os.close(self.slave)
        return self.process.returncode
