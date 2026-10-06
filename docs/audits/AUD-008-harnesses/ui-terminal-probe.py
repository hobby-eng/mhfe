#!/usr/bin/env python3
"""Bounded AUD-008 CLI presentation probes using public data and no Argon2."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-008-evidence"
PROGRAM = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "target/release/mhfe").resolve()
VECTOR = ROOT / "tests/fixtures/suite3-vectors/zero-12.json"
CONTAINER = json.loads(VECTOR.read_text())["container"]
ENTER_PRIVATE = b"\x1b[?1049h"
LEAVE_PRIVATE = b"\x1b[2J\x1b[H\x1b[?1049l"
CSI = re.compile(r"\x1b\[([?0-9;]*)([A-Za-z])")
SGR = re.compile(rb"\x1b\[[0-9;]*m")
RECORDS = []
FAILURES = []
DEADLINE_SECONDS = 5


def environment(**overrides):
    result = dict(os.environ)
    for name in ("NO_COLOR", "CLICOLOR_FORCE", "CLICOLOR", "TERM"):
        result.pop(name, None)
    result.update(TERM="xterm-256color")
    result.update(overrides)
    return result


def attach_terminal():
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


class Session:
    """Two-stream public PTY capture, with geometry set before the child starts."""

    def __init__(self, arguments=(), columns=80, rows=100, split=False, **env):
        self.master, self.slave = os.openpty()
        self.original = termios.tcgetattr(self.master)
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
        self.pairs = [(self.master, self.slave)]
        self.buffers = {self.master: b""}
        output = self.slave
        self.output_master = None
        if split:
            self.output_master, output = os.openpty()
            self.pairs.append((self.output_master, output))
            self.buffers[self.output_master] = b""
        for master, _ in self.pairs:
            os.set_blocking(master, False)
        self.arguments = [str(PROGRAM), *arguments]
        self.columns, self.rows = columns, rows
        self.env = environment(**env)
        self.process = subprocess.Popen(
            self.arguments,
            stdin=self.slave,
            stdout=output,
            stderr=self.slave,
            start_new_session=True,
            preexec_fn=attach_terminal,
            env=self.env,
        )

    @property
    def output(self):
        return self.buffers[self.master]

    def read(self, wait=0.05):
        ready, _, _ = select.select(list(self.buffers), [], [], wait)
        for master in ready:
            try:
                self.buffers[master] += os.read(master, 16384)
            except (OSError, BlockingIOError):
                pass
        return bool(ready)

    def wait_for(self, marker, start=0):
        deadline = time.monotonic() + DEADLINE_SECONDS
        while marker not in self.output[start:]:
            if time.monotonic() > deadline:
                raise AssertionError(f"Did not find {marker!r}: {self.output[start:]!r}")
            self.read()
        self.drain()

    def drain(self):
        # An idle read closes a capture boundary without assuming a scheduler-specific sleep.
        while self.read(0.05):
            pass

    def type(self, value):
        os.write(self.master, value)

    def answer(self, value, marker):
        start = len(self.output)
        self.type(value)
        self.wait_for(marker, start)

    def close(self, cancel=True):
        if cancel and self.process.poll() is None:
            self.type(b"\x03")
        deadline = time.monotonic() + DEADLINE_SECONDS
        while self.process.poll() is None and time.monotonic() < deadline:
            self.read()
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGKILL)
            self.process.wait()
            raise AssertionError("CLI did not cancel within the bounded deadline")
        self.drain()
        restored = termios.tcgetattr(self.master) == self.original
        for master, slave in self.pairs:
            os.close(master)
            os.close(slave)
        return self.process.returncode, restored

    def transcript(self):
        result = {"stdinStderrTerminal": self.output.decode(errors="replace")}
        if self.output_master is not None:
            result["stdoutTerminal"] = self.buffers[self.output_master].decode(errors="replace")
        return result


def retain(label, expected, observed, **details):
    passed = expected == observed
    record = dict(label=label, expected=expected, observed=observed, passed=passed, **details)
    RECORDS.append(record)
    if not passed:
        FAILURES.append(label)
    print(json.dumps({key: value for key, value in record.items() if key != "transcript"}))


def plain(data):
    return SGR.sub(b"", data).decode(errors="replace")


def menu_grid(data, columns):
    """Small terminal accounting model for menu CR/LF, delayed wrap, CUU and ED only.

    This is a derived text reconstruction, not a terminal screenshot. Menus use only
    single-column public glyphs. A tall PTY isolates wrapping from screen-height scrolling.
    """
    cells = [[" "] * columns for _ in range(200)]
    row, col = 0, 0
    text = plain(data)
    index = 0
    unsupported = []
    while index < len(text):
        match = CSI.match(text, index)
        if match:
            parameters, operation = match.groups()
            if operation == "A":
                row = max(0, row - int(parameters or "1"))
            elif operation == "J" and parameters in ("", "0"):
                cells[row][min(col, columns) :] = [" "] * (columns - min(col, columns))
                for later in range(row + 1, len(cells)):
                    cells[later] = [" "] * columns
            else:
                unsupported.append(match.group())
            index = match.end()
            continue
        character = text[index]
        if character == "\r":
            col = 0
        elif character == "\n":
            row += 1
        elif ord(character) >= 32:
            if col == columns:
                row += 1
                col = 0
            cells[row][col] = character
            col += 1
        else:
            unsupported.append(repr(character))
        index += 1
    return {"rows": ["".join(line).rstrip() for line in cells[: row + 1]], "unsupported": unsupported}


def menu_width(columns):
    session = Session(columns=columns, NO_COLOR="1")
    try:
        session.wait_for(b"Esc quits")
        before = session.output
        session.answer(b"\x1b[B", b"Esc quits")
        after = session.output
        session.type(b"\x1b")
        session.drain()
    finally:
        code, restored = session.close(cancel=False)
    initial = menu_grid(before, columns)
    redrawn = menu_grid(after, columns)
    initial_marker_count = sum(line.count("›") for line in initial["rows"])
    redraw_marker_count = sum(line.count("›") for line in redrawn["rows"])
    retain(
        f"{columns}-column menu leaves exactly one selection after Down",
        1,
        redraw_marker_count,
        geometry={"columns": columns, "rows": 100},
        initialMarkerCount=initial_marker_count,
        renderedInitial=initial,
        renderedAfterDown=redrawn,
        exitCode=code,
        settingsRestored=restored,
        transcript=session.transcript(),
    )
    retain(f"{columns}-column menu Escape exits and restores termios", True, code == 0 and restored)


def menu_return_paths():
    session = Session(NO_COLOR="1")
    try:
        session.wait_for(b"Esc quits")
        session.answer(b"7", b"Repair a plate, or make repair words for one?")
        session.answer(b"\x1b", b"Esc quits")
        # Entry 7 stays selected on return; Help is three down, above Quit.
        session.type(b"\x1b[B" * 3 + b"\r")
        session.wait_for(b"Press Enter to return to the menu")
        session.answer(b"\r", b"Esc quits")
        session.type(b"q")
    finally:
        code, restored = session.close(cancel=False)
    retain(
        "Repair submenu Escape, help Enter and menu q return paths",
        True,
        code == 0 and restored and b"Usage:" in session.output,
        exitCode=code,
        settingsRestored=restored,
        transcript=session.transcript(),
    )


def color_case(label, expected_color, pipe=False, **env):
    if pipe:
        completed = subprocess.run(
            [str(PROGRAM), "--help"], capture_output=True, timeout=DEADLINE_SECONDS, env=environment(**env)
        )
        output = completed.stdout + completed.stderr
        code, restored, transcript = completed.returncode, None, {"pipeOutput": plain(output)}
    else:
        session = Session(("--help",), **env)
        session.wait_for(b"Experimental:")
        code, restored = session.close(cancel=False)
        output, transcript = session.output, session.transcript()
    retain(
        label,
        expected_color,
        bool(SGR.search(output)),
        environment={name: environment(**env).get(name) for name in ("TERM", "NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE")},
        outputKind="pipe" if pipe else "terminal",
        exitCode=code,
        settingsRestored=restored,
        transcript=transcript,
    )


def help_commands():
    names = ["new", "encrypt", "decrypt", "check", "rekey", "wallets", "repair", "repair-words", "password", "self-test", "serve", "test-vectors", "test-benchmark"]
    for name in names:
        completed = subprocess.run(
            [str(PROGRAM), name, "--help"], capture_output=True, timeout=DEADLINE_SECONDS, env=environment(NO_COLOR="1")
        )
        output = completed.stdout + completed.stderr
        retain(f"{name} --help exits 0 with Usage and no ANSI", True, completed.returncode == 0 and b"Usage:" in output and b"\x1b" not in output, exitCode=completed.returncode, transcript={"help": plain(output)})


def public_private_screen(split):
    session = Session(("repair-words", "--count", "4"), split=split, NO_COLOR="1")
    try:
        session.wait_for(b"original: ")
        session.answer(CONTAINER.encode() + b"\r", b"Enter or Escape clears this screen.")
        session.type(b"\x1b")
        session.drain()
    finally:
        code, restored = session.close(cancel=False)
    output = session.buffers[session.output_master] if split else session.output
    retain(
        "Separate stdout PTY receives private-screen controls" if split else "Same PTY public repair result is entered, cleared and restored",
        True,
        ENTER_PRIVATE in output and LEAVE_PRIVATE in output and restored and code == 0,
        splitStdout=split,
        exitCode=code,
        settingsRestored=restored,
        stdoutHasPrivateControls=ENTER_PRIVATE in output,
        stdoutHasNumberedPublicCard=b"1/4" in output,
        transcript=session.transcript(),
    )


def split_new_guard():
    session = Session(("new",), split=True, NO_COLOR="1")
    try:
        session.wait_for(b"Esc cancels")
        reached_question = b"#settings-pim-and-memory-level" in session.output
    finally:
        code, restored = session.close()
    retain(
        "new refuses stdout redirected to a separate PTY before asking settings",
        False,
        reached_question,
        exitCode=code,
        settingsRestored=restored,
        transcript=session.transcript(),
        note="Stopped at the first settings question: no new phrase was generated and no Argon2 was entered.",
    )


def pipe_public_card():
    completed = subprocess.run([str(PROGRAM), "repair-words", "--stdin", "--count", "4"], input=(CONTAINER + "\n").encode(), capture_output=True, timeout=DEADLINE_SECONDS, env=environment())
    words = completed.stdout.decode().strip().split()
    retain("Public repair script result is bare four words without ANSI", True, completed.returncode == 0 and len(words) == 4 and b"\x1b" not in completed.stdout + completed.stderr, exitCode=completed.returncode, transcript={"stdout": completed.stdout.decode(), "stderr": completed.stderr.decode()})


def main():
    help_commands()
    for columns in (80, 60, 40):
        menu_width(columns)
    menu_return_paths()
    color_case("TTY color by default", True)
    color_case("NO_COLOR disables terminal color", False, NO_COLOR="1")
    color_case("CLICOLOR=0 disables terminal color", False, CLICOLOR="0")
    color_case("TERM=dumb disables terminal color", False, TERM="dumb")
    color_case("CLICOLOR_FORCE=1 enables terminal color", True, CLICOLOR_FORCE="1")
    color_case("Piped help has no color by default", False, pipe=True)
    color_case("NO_COLOR disables piped help color", False, pipe=True, NO_COLOR="1")
    # Explicit FORCE precedence is a diagnostic; default-pipe plainness is the acceptance case.
    color_case("Explicit CLICOLOR_FORCE=1 forces piped help color", True, pipe=True, CLICOLOR_FORCE="1")
    pipe_public_card()
    public_private_screen(False)
    public_private_screen(True)
    split_new_guard()
    sources = ["src/bin/mhfe/main.rs", "src/bin/mhfe/menu.rs", "src/bin/mhfe/choice.rs", "src/bin/mhfe/style.rs", "src/bin/mhfe/terminal.rs", "src/bin/mhfe/hidden_input.rs", "src/bin/mhfe/new_wallet.rs", "src/bin/mhfe/plate_repair.rs", "src/bin/mhfe/flow.rs", "scripts/verify-hidden-input.py", str(VECTOR.relative_to(ROOT))]
    hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sources}
    snapshot = json.loads((EVIDENCE / "snapshot.json").read_text())["mhfe"]["files"]
    unchanged = all(snapshot.get(name) == value for name, value in hashes.items())
    retain("Reviewed interface sources match initial AUD-008 snapshot", True, unchanged)
    summary = {"auditId": "AUD-008", "binary": str(PROGRAM), "binarySha256": hashlib.sha256(PROGRAM.read_bytes()).hexdigest(), "sourceSha256": hashes, "cases": RECORDS, "failures": FAILURES, "argon2Calls": 0, "generatedWallets": 0, "caseCount": len(RECORDS), "outcome": "failed" if FAILURES else "passed"}
    (EVIDENCE / "ui-terminal-probe.json").write_text(json.dumps(summary, indent=2) + "\n")
    return bool(FAILURES)


if __name__ == "__main__":
    raise SystemExit(main())
