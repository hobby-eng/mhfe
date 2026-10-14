# TOOL-01: public fixtures and cases of the Python PTY test runtime.
"""The pseudo-terminal that drives the tool, and the helpers that run it
without one.

A Session starts the tool on a pseudo-terminal of its own, types keys as
a person does and reads what the tool writes; shown_privately checks
that a secret stayed on the private screen. The other helpers run the
tool with its outputs in pipes, take the hint rows out of what a line
showed and wrap text as mhfe does. Nothing here checks a case of its
own.
"""

import fcntl
import os
import re
import resource
import select
import signal
import subprocess
import termios
import textwrap
import time

from .constants import (
    ADDRESS_SPACE_CAP,
    ANSWER_DELAY,
    COLOUR_VARIABLES,
    CONTAINER,
    CONTROL_SEQUENCE,
    CTRL_C,
    ENTER_PRIVATE,
    LEAVE_PRIVATE,
    PROGRAM,
    QUIET_SECONDS,
)

# Most cases test a later operation: accept the explicit spelling
# read-back along the way.
# Cases that check that screen themselves pass auto_read_back=False and
# answer it explicitly.
READ_BACK_PROMPT = b"Check the written-out words; Enter continues."


def attach_terminal():
    """
    Makes the pseudo-terminal the controlling terminal, so that Ctrl+C
    sends SIGINT.
    """
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def attach_terminal_capped():
    """
    attach_terminal, and the address space limited to ADDRESS_SPACE_CAP.
    """
    attach_terminal()
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_CAP, ADDRESS_SPACE_CAP))


def tool_environment(colour=False, term=None):
    """
    The environment of the tool: NO_COLOR unless `colour`, and nothing
    else that turns colour on or off. A capable terminal unless `term`
    names another: the shell that runs the checks may itself be a dumb
    one, as some editors' consoles are.
    """
    environment = {name: value for name, value in os.environ.items()
                   if name not in COLOUR_VARIABLES}
    environment["TERM"] = term or "xterm-256color"
    if not colour:
        environment["NO_COLOR"] = "1"
    return environment


class Session:
    def __init__(self, arguments=("check", "--fingerprint", "--pim", "0"), stdout=None, term=None,
                 capped=False, colour=False, program=PROGRAM, auto_read_back=True):
        """`stdout` replaces the terminal as standard output, such as a
        pipe; `term` sets TERM; `capped` limits the address space, so
        that the memory for Argon2 is refused; `colour` leaves out
        NO_COLOR; `program` runs another copy of the tool.
        """
        self.master, self.slave = os.openpty()
        os.set_blocking(self.master, False)
        # The settings are read through the master side: on macOS the
        # slave side stops answering
        # once the tool, the leader of its session, has ended, because
        # the system revokes the
        # terminal of an ended session. The master side reads the same
        # terminal on every system.
        self.original = termios.tcgetattr(self.master)
        environment = tool_environment(colour, term)
        self.process = subprocess.Popen(
            [program, *arguments],
            stdin=self.slave, stdout=self.slave if stdout is None else stdout, stderr=self.slave,
            start_new_session=True,
            preexec_fn=attach_terminal_capped if capped else attach_terminal, env=environment,
        )
        self.output = b""
        self.auto_read_back = auto_read_back
        self.read_back_seen = 0

    def confirm_read_back(self, expected):
        """
        Answers only the spelling screen, unless the case is inspecting
        it explicitly.
        """
        if not self.auto_read_back or READ_BACK_PROMPT in expected:
            return
        position = self.output.find(READ_BACK_PROMPT, self.read_back_seen)
        if position >= 0:
            self.read_back_seen = position + len(READ_BACK_PROMPT)
            self.press(b"\r")

    def wait_for(self, *needles, limit=10, since=None):
        """Reads until one of `needles` appears after the text already
        seen, or after the place `since` in it; returns it.
        """
        start = len(self.output) if since is None else since
        end = time.monotonic() + limit
        while time.monotonic() < end:
            if select.select([self.master], [], [], 0.1)[0]:
                try:
                    self.output += os.read(self.master, 4096)
                except OSError:
                    break
            for needle in needles:
                self.confirm_read_back(needles)
                if needle in self.output[start:]:
                    return needle
        raise AssertionError(f"none of {needles} in {self.output[start:]!r}")

    def answer(self, keys, *expected, limit=10):
        """Types `keys` and reads until every one of `expected` has
        appeared after them. A list and its question arrive together, so
        each is looked for in all that followed the keys.
        """
        start = len(self.output)
        self.press(keys)
        end = time.monotonic() + limit
        while not all(needle in self.output[start:] for needle in expected):
            if time.monotonic() > end:
                raise AssertionError(f"not all of {expected} in {self.output[start:]!r}")
            if select.select([self.master], [], [], 0.1)[0]:
                try:
                    self.output += os.read(self.master, 4096)
                except OSError:
                    time.sleep(0.05)
            self.confirm_read_back(expected)

    def idle(self, keys, seconds=QUIET_SECONDS):
        """Types `keys` and returns all that the tool wrote in the
        `seconds` after them.
        """
        start = len(self.output)
        time.sleep(ANSWER_DELAY)
        self.type(keys)
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if select.select([self.master], [], [], 0.1)[0]:
                try:
                    self.output += os.read(self.master, 4096)
                except OSError:
                    time.sleep(0.05)
        return self.output[start:]

    def press(self, keys):
        """Types `keys` as a person answers what appeared: after
        ANSWER_DELAY, so that the tool does not take them for keys typed
        ahead, Escape and q included.
        """
        time.sleep(ANSWER_DELAY)
        self.type(keys)

    def type(self, data, limit=10):
        """
        Writes `data` as pasted text; the line only ends at the carriage
        return.

        A pseudo-terminal holds little input (about 1 KiB on macOS), so
        a long paste is written in parts as the tool reads them. The
        tool's output is read meanwhile, so that neither side waits for
        the other, and a tool that stops reading fails the check instead
        of blocking it for ever.
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
        """Ends the tool as a person would, with Ctrl+C, so that it can
        restore the terminal.
        """
        if self.process.poll() is None:
            self.type(CTRL_C)
            if not self.drain_until_exit(5):
                # SIGKILL leaves the terminal as it is; the settings
                # check below then fails.
                self.process.send_signal(signal.SIGKILL)
        if not self.drain_until_exit(10):
            raise AssertionError("the tool did not end")
        code = self.process.returncode
        settings = termios.tcgetattr(self.master)
        os.close(self.master)
        os.close(self.slave)
        return code, settings

    def drain_until_exit(self, limit):
        """Waits up to `limit` seconds for the tool to end, reading its
        output meanwhile.

        On macOS a process that ends waits until the terminal has
        delivered its last output, which happens only when this side
        reads it; without reading, the tool never finishes exiting.
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
        self.wait_for(b"original seed phrase: ")
        # The container is read on its own private screen and taken at
        # once.
        self.answer(CONTAINER.encode() + b"\r", b"Container password: ")


def shown_privately(label, output, secret):
    """The secret was shown on the private screen and nowhere after the
    tool left it.
    """
    entered = output.rfind(ENTER_PRIVATE, 0, output.find(secret))
    assert entered >= 0, f"{label}: the password was shown off the private screen"
    left = output.find(LEAVE_PRIVATE, entered)
    assert left >= 0, f"{label}: the private screen was not left"
    assert secret not in output[left:], f"{label}: the password reached the main screen"


# The rows of a hint below a line being typed (typed_line.rs in the
# tool): each written after the
# line's "clear below" on a row of its own, in colour or not, before the
# cursor moves back up.
HINT_ROWS = re.compile(rb"(?<=\x1b\[J)(?:\r?\r\n(?:[^\x1b]|\x1b\[[0-9;]*m)*)+(?=\x1b\[\d+A)")


def without_hints(output):
    """`output` without the rows of hints, and nothing else taken out.
    """
    return HINT_ROWS.sub(b"", output)


def typed_echo(output):
    """The characters a line showed as they were typed: without the hint
    rows below it, the space and backspace that move the cursor to the
    next row, and the control sequences.
    """
    return re.sub(CONTROL_SEQUENCE, b"", without_hints(output).replace(b" \x08", b""))


def run_plainly(arguments, data=b"", colour=False, capped=False, timeout=30):
    """Runs the tool with `data` on standard input and both outputs in
    pipes, without a terminal; `colour` forces colour on, `capped`
    limits the address space as for a Session, and `timeout` is in
    seconds.
    """
    environment = tool_environment(colour)
    if colour:
        environment["CLICOLOR_FORCE"] = "1"
    limit = None
    if capped:
        def limit():
            resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_CAP, ADDRESS_SPACE_CAP))
    return subprocess.run([PROGRAM, *arguments], input=data, capture_output=True, env=environment,
                          timeout=timeout, preexec_fn=limit)


def wrapped(text, width):
    """`text` broken into lines of at most `width` characters at its
    spaces, as mhfe wraps running text (wrap in src/bin/mhfe/style.rs).
    """
    return textwrap.wrap(text, width, break_long_words=False, break_on_hyphens=False)


def run_with_output(arguments, redirected=False, term=None, capped=False):
    """Starts the tool with standard output in a pipe when `redirected`;
    returns the session and the read end of the pipe, or None.
    """
    if not redirected:
        return Session(arguments, term=term, capped=capped), None
    reader, writer = os.pipe()
    session = Session(arguments, stdout=writer, term=term, capped=capped)
    # The tool holds its own copy; the pipe ends once the tool has
    # ended.
    os.close(writer)
    return session, reader
