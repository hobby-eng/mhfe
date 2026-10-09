"""Shared helper of the AUD-015 R2 probes: runs the mhfe tool in a pseudo-terminal of a chosen size,
types keys, reads what it writes, and replays that output on a small VT100 screen model.

Every run gets an address space of 1 GiB (RLIMIT_AS), too small for the 2 GiB that memory level 0
reserves, so that no probe can reach full-cost Argon2 even by mistake. Only the public zero-12 test
container and phrase and synthetic passwords are typed.
"""

import fcntl
import json
import os
import resource
import select
import signal
import struct
import subprocess
import termios
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
ZERO_12 = json.loads((ROOT / "tests/fixtures/suite3-vectors/zero-12.json").read_text())
CONTAINER = ZERO_12["container"].encode()
PHRASE = ZERO_12["inputs"]["phrase"].encode()
ADDRESS_SPACE_CAP = 1 << 30
ENTER_PRIVATE = b"\x1b[?1049h"
LEAVE_PRIVATE = b"\x1b[2J\x1b[H\x1b[?1049l"
CTRL_C = b"\x03"
COLOUR_VARIABLES = ("NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE")


def program(argv):
    """The tool to run: the first argument, or the coordinator's release build."""
    return argv[1] if len(argv) > 1 else str(ROOT / "target/release/mhfe")


def environment(term="xterm-256color", colour=True, extra=None):
    env = {k: v for k, v in os.environ.items() if k not in COLOUR_VARIABLES}
    env["TERM"] = term
    if not colour:
        env["NO_COLOR"] = "1"
    env.update(extra or {})
    return env


class Session:
    """The tool in a pseudo-terminal of `columns` x `rows`. With `stdin_data`, standard input is a
    pipe holding those bytes (a script) while standard error and output stay the terminal."""

    def __init__(self, tool, arguments, columns=80, rows=24, term="xterm-256color", colour=True,
                 stdin_data=None, extra_env=None):
        self.master, self.slave = os.openpty()
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
        os.set_blocking(self.master, False)
        self.original = termios.tcgetattr(self.master)

        def attach():
            fcntl.ioctl(self.slave, termios.TIOCSCTTY, 0)
            resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_CAP, ADDRESS_SPACE_CAP))

        stdin = self.slave if stdin_data is None else subprocess.PIPE
        self.process = subprocess.Popen(
            [tool, *arguments], stdin=stdin, stdout=self.slave, stderr=self.slave,
            start_new_session=True, preexec_fn=attach,
            env=environment(term, colour, extra_env))
        if stdin_data is not None:
            self.process.stdin.write(stdin_data)
            self.process.stdin.close()
        self.output = b""

    def _read(self, timeout=0.1):
        if select.select([self.master], [], [], timeout)[0]:
            try:
                self.output += os.read(self.master, 65536)
            except OSError:
                time.sleep(0.05)

    def wait_for(self, needle, limit=20):
        start = len(self.output)
        end = time.monotonic() + limit
        while needle not in self.output[start:] and needle not in self.output:
            if time.monotonic() > end:
                raise AssertionError(f"{needle!r} not in {self.output[-600:]!r}")
            self._read()

    def type(self, data, then=None, limit=20):
        """Types `data`; with `then`, reads until it appears after the keys, else for 0.5 s."""
        start = len(self.output)
        os.write(self.master, data)
        end = time.monotonic() + (limit if then else 0.5)
        while time.monotonic() < end:
            self._read()
            if then is not None and then in self.output[start:]:
                return self.output[start:]
        if then is not None:
            raise AssertionError(f"{then!r} not after {data!r} in {self.output[start:][-600:]!r}")
        return self.output[start:]

    def wait_exit(self, limit=20):
        """Reads until the tool ends by itself; whether it did within `limit` seconds."""
        end = time.monotonic() + limit
        while self.process.poll() is None and time.monotonic() < end:
            self._read()
        for _ in range(5):
            self._read(0.05)
        return self.process.poll() is not None

    def finish(self, limit=10):
        """Ends the tool with Ctrl+C if it still runs, SIGKILL as a last resort; returns the exit
        code (negative for a signal) and the terminal settings afterwards."""
        if self.process.poll() is None:
            try:
                os.write(self.master, CTRL_C)
            except OSError:
                pass
        end = time.monotonic() + limit
        while self.process.poll() is None and time.monotonic() < end:
            self._read()
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGKILL)
            self.process.wait(5)
        for _ in range(5):
            self._read(0.05)
        settings = termios.tcgetattr(self.master)
        os.close(self.master)
        os.close(self.slave)
        return self.process.returncode, settings


class Screen:
    """A small VT100 screen model: printable characters with xterm's pending wrap, CR, LF, BS, and
    the control sequences the tool writes (CUU A, CHA G, ED J, CUP H, the alternate screen switch,
    colours). Each cell remembers the character written there."""

    def __init__(self, columns, rows):
        self.columns, self.rows = columns, rows
        self.cells = [[" "] * columns for _ in range(rows)]
        self.row = self.column = 0
        self.pending_wrap = False

    def _newline(self):
        if self.row == self.rows - 1:
            self.cells.pop(0)
            self.cells.append([" "] * self.columns)
        else:
            self.row += 1

    def _put(self, character):
        if self.pending_wrap:
            self.column = 0
            self._newline()
            self.pending_wrap = False
        self.cells[self.row][self.column] = character
        if self.column == self.columns - 1:
            self.pending_wrap = True
        else:
            self.column += 1

    def _erase_below(self):
        self.cells[self.row][self.column:] = [" "] * (self.columns - self.column)
        for row in range(self.row + 1, self.rows):
            self.cells[row] = [" "] * self.columns

    def feed(self, data):
        text = data.decode("utf-8", "replace")
        index = 0
        while index < len(text):
            character = text[index]
            index += 1
            if character == "\x1b":
                if index < len(text) and text[index] == "[":
                    end = index + 1
                    while end < len(text) and not ("@" <= text[end] <= "~"):
                        end += 1
                    parameters, final = text[index + 1:end], text[end] if end < len(text) else ""
                    index = end + 1
                    self._control(parameters, final)
                elif index < len(text) and text[index] == "]":
                    # An OSC sequence, up to BEL or ST: no effect on the cells.
                    end = index
                    while end < len(text) and text[end] not in "\x07\x9c":
                        if text[end] == "\x1b" and end + 1 < len(text) and text[end + 1] == "\\":
                            break
                        end += 1
                    index = end + 1
                continue
            if character == "\r":
                self.column, self.pending_wrap = 0, False
            elif character == "\n":
                self._newline()
                self.pending_wrap = False
            elif character == "\x08":
                self.column, self.pending_wrap = max(0, self.column - 1), False
            elif character >= " ":
                self._put(character)

    def _control(self, parameters, final):
        number = int(parameters) if parameters.isdigit() else 1
        if final == "A":
            self.row, self.pending_wrap = max(0, self.row - number), False
        elif final == "G":
            self.column, self.pending_wrap = min(self.columns - 1, number - 1), False
        elif final == "J":
            if parameters == "2":
                self.cells = [[" "] * self.columns for _ in range(self.rows)]
            else:
                self._erase_below()
        elif final == "H":
            self.row = self.column = 0
            self.pending_wrap = False
        elif final in ("h", "l") and parameters == "?1049":
            self.cells = [[" "] * self.columns for _ in range(self.rows)]
            self.row = self.column = 0

    def text(self):
        return "\n".join("".join(row).rstrip() for row in self.cells)
