"""Checks the terminal input of the mhfe tool in a pseudo-terminal (Linux and macOS).

    python3 scripts/verify-hidden-input.py [path/to/mhfe]

The default is target/debug/mhfe. It drives `mhfe check --fingerprint --pim 0`, which reads the
container on a private screen, taken at once, and then the password on another, and stops
the tool before a fingerprint is given, so no memory is reserved and Argon2 never runs; the PIM
given skips the question of the settings. Only the public zero-12 test container is used.

It checks that
- every control character in a password reaches the password check and is refused, including
  the ones a terminal would otherwise act on (Ctrl+S, Ctrl+Q, Ctrl+V, Ctrl+W, Ctrl+R, Ctrl+O,
  Ctrl+\\, Ctrl+Z and Ctrl+D inside the line), and that a Unicode password is accepted, also the
  longest one: 1024 characters U+1D400, 4096 bytes that NFKD turns into 1024;
- Backspace and Ctrl+U edit the line: a TAB typed and then deleted leaves an accepted password;
- the password is shown as it is typed only on the private (alternate) screen, which is cleared
  and left once it is accepted, and none of its control characters is ever written back;
- Ctrl+C at the password ends the tool with exit code 130 and leaves the private screen;
- the terminal settings are exactly the original ones afterwards, after a normal answer and after
  Ctrl+C.

It also drives the menu that `mhfe` shows when it starts without arguments: the arrow keys and Enter
choose an entry, its number chooses it at once, other escape sequences (Ctrl+Up) and keys do
nothing and are not shown, q and a lone Escape quit with exit code 0 and Ctrl+C with 130, and the
terminal settings are restored either way. The `mhfe password` entry shows each password on one
private screen, which it clears for the next one on Enter and when Escape or q returns to the menu;
the help entry returns on Enter. Neither needs secret input.

Last, it answers the questions of `mhfe encrypt` up to the password, so again without Argon2: its
own settings, PIM 1 after a mistyped one, which the settings shown next record; the phrase on the
private screen, refused once for its checksum and then taken without a question, which the
summary records by its length; ? explains the container lengths, and the arrows and Enter keep 24
words; Ctrl+C at the repeated password ends the tool and leaves the private screen. Escape at a
list cancels with exit code 130. The phrase is the public zero-12 test phrase and the password a
synthetic one, which never reaches the main screen.
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
ZERO_12 = json.loads((ROOT / "tests/fixtures/suite3-vectors/zero-12.json").read_text())
CONTAINER, PHRASE = ZERO_12["container"], ZERO_12["inputs"]["phrase"]
# Exit code of the tool when the person cancels (src/bin/mhfe/exit.rs).
CANCELLED = 130
# What the tool prints next after each kind of answer. An accepted one leads to the fingerprint.
# A refused password is asked again ("Please type it again").
REFUSED = b"again"
ACCEPTED = b"ingerprint"
# The private screen: the terminal's alternate screen, cleared before the tool leaves it
# (src/bin/mhfe/terminal.rs).
ENTER_PRIVATE, LEAVE_PRIVATE = b"\x1b[?1049h", b"\x1b[2J\x1b[H\x1b[?1049l"
CLEAR = b"\x1b[2J\x1b[H"
BACKSPACE, CTRL_U, CTRL_C = b"\x7f", b"\x15", b"\x03"
# The keys of the menu, as a terminal sends them. Ctrl+Up carries a 5, which must not choose entry 5.
UP, DOWN, ENTER, CTRL_UP, ESCAPE = b"\x1b[A", b"\x1b[B", b"\r", b"\x1b[1;5A", b"\x1b"
# The menu entry of `mhfe password` when no browser tool lies next to the program.
PASSWORD_ENTRY = 6
# The entry that shows the help and returns to the menu on Enter; mhfe self-test lies between.
HELP_ENTRY = PASSWORD_ENTRY + 2
# The prompts are matched whole: the "Esc quits" at the end of the first must not pass for the menu.
MENU_SHOWN, PASSWORD_MADE = b"Esc quits", b"bits"
BACK_TO_MENU = b"Press Enter to return to the menu (Esc quits)."
PASSWORD_AGAIN = b"Press Enter to generate other words (Esc returns to the menu)."
# What the lists of `mhfe encrypt` show: a list's hint line, the explanation behind ?, and the line
# that records the chosen container length.
LIST_SHOWN, EXPLAINED = b"Esc cancels", b"8-character code"
LENGTH_RECORDED = b"Container  24 words (recommended)"
PHRASE_RECORDED = b"Phrase     12 words, valid"
# Valid words whose checksum fails: the phrase is refused and asked again.
BAD_CHECKSUM = b" ".join([b"abandon"] * 12)
SETTINGS_ASKED, OWN_SETTINGS = b"#settings-pim-and-memory-level", b"PIM 1 \xc2\xb7 memory level 0"
# A key the menu ignores; it appears nowhere in what the menu or `mhfe password` print.
IGNORED_KEY = b"Z"
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
    def __init__(self, arguments=("check", "--fingerprint", "--pim", "0")):
        self.master, self.slave = os.openpty()
        os.set_blocking(self.master, False)
        # The settings are read through the master side: on macOS the slave side stops answering
        # once the tool, the leader of its session, has ended, because the system revokes the
        # terminal of an ended session. The master side reads the same terminal on every system.
        self.original = termios.tcgetattr(self.master)
        environment = dict(os.environ, NO_COLOR="1")
        self.process = subprocess.Popen(
            [PROGRAM, *arguments],
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

    def answer(self, keys, *expected, limit=10):
        """Types `keys` and reads until every one of `expected` has appeared after them. A list
        and its question arrive together, so each is looked for in all that followed the keys."""
        start = len(self.output)
        self.type(keys)
        end = time.monotonic() + limit
        while not all(needle in self.output[start:] for needle in expected):
            if time.monotonic() > end:
                raise AssertionError(f"not all of {expected} in {self.output[start:]!r}")
            if select.select([self.master], [], [], 0.1)[0]:
                try:
                    self.output += os.read(self.master, 4096)
                except OSError:
                    time.sleep(0.05)

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
        self.wait_for(b"original: ")
        # The container is read on its own private screen and taken at once.
        self.answer(CONTAINER.encode() + b"\r", b"Password: ")


def shown_privately(label, output, secret):
    """The secret was shown on the private screen and nowhere after the tool left it."""
    entered = output.rfind(ENTER_PRIVATE, 0, output.find(secret))
    assert entered >= 0, f"{label}: the password was shown off the private screen"
    left = output.find(LEAVE_PRIVATE, entered)
    assert left >= 0, f"{label}: the private screen was not left"
    assert secret not in output[left:], f"{label}: the password reached the main screen"


def check_password(label, password, expected, not_shown=None):
    session = Session()
    try:
        session.at_password_prompt()
        prompt = len(session.output)
        session.type(password + b"\r")
        seen = session.wait_for(REFUSED, ACCEPTED)
        assert seen == expected, f"{label}: expected {expected!r}, the tool answered {seen!r}"
        if not_shown is not None:
            assert not_shown not in session.output[prompt:], f"{label}: the key was written back"
    finally:
        code, settings = session.close()
    if password.startswith(SECRET):
        shown_privately(label, session.output, SECRET)
    assert settings == session.original, f"{label}: the terminal settings were not restored"
    return code


def check_menu():
    session = Session(arguments=())
    session.wait_for(MENU_SHOWN)
    moves = DOWN * PASSWORD_ENTRY + UP
    session.type(IGNORED_KEY + CTRL_UP + moves + ENTER)
    # wait_for looks only at new output, and the password and the prompt arrive together; the
    # count of passwords is checked at the end.
    session.wait_for(PASSWORD_AGAIN)
    for _ in range(2):
        session.answer(ENTER, PASSWORD_AGAIN)
    session.answer(ESCAPE, MENU_SHOWN)
    session.type(str(PASSWORD_ENTRY).encode())
    session.wait_for(PASSWORD_AGAIN)
    session.answer(b"q", MENU_SHOWN)
    session.answer(str(HELP_ENTRY).encode(), BACK_TO_MENU)
    session.answer(ENTER, MENU_SHOWN)
    session.type(b"q")
    # The tool needs a moment to end; close() would send Ctrl+C to a tool that is still running.
    assert session.drain_until_exit(10), "menu: q did not end the tool"
    code, settings = session.close()
    assert code == 0, f"menu: q gave exit code {code}"
    assert settings == session.original, "menu: the terminal settings were not restored"
    assert session.output.count(PASSWORD_MADE) == 4, "menu: passwords were not regenerated"
    # One private screen each time the entry is chosen; it is cleared on entering and on leaving,
    # and once more before each password made again.
    assert session.output.count(ENTER_PRIVATE) == 2, "menu: passwords did not use private screens"
    assert session.output.count(LEAVE_PRIVATE) == 2, "menu: password screens were not left"
    assert session.output.count(CLEAR) == 6, "menu: a password was not replaced by the next"
    assert IGNORED_KEY not in session.output, "menu: a key was shown"
    print("menu: password regeneration, Escape/q return, private screens cleared, terminal restored")

    # Escape alone: the tool waits a moment for the rest of an arrow key's sequence, then quits.
    session = Session(arguments=())
    session.wait_for(MENU_SHOWN)
    session.type(ESCAPE)
    assert session.drain_until_exit(10), "menu: Escape did not end the tool"
    code, settings = session.close()
    assert code == 0, f"menu: Escape gave exit code {code}"
    assert settings == session.original, "menu: Escape did not restore the terminal settings"
    print("menu: a lone Escape quits, exit code 0, terminal restored")

    session = Session(arguments=())
    session.wait_for(MENU_SHOWN)
    session.type(CTRL_C)
    session.wait_for(b"Cancelled")
    code, settings = session.close()
    assert code == CANCELLED, f"menu: Ctrl+C gave exit code {code}"
    assert settings == session.original, "menu: Ctrl+C did not restore the terminal settings"
    print("menu: Ctrl+C, exit code 130, terminal restored")


def check_encrypt_lists():
    session = Session(arguments=("encrypt",))
    # Nothing typed yet: this waits for the whole first question, its link and its list.
    session.answer(b"", SETTINGS_ASKED, LIST_SHOWN)
    session.answer(b"2", b"PIM: ")
    session.answer(b"x\r", b"whole number", b"PIM: ")
    session.answer(b"1\r", b"Memory level: ")
    session.answer(b"0\r", OWN_SETTINGS, ENTER_PRIVATE, b"seed phrase: ")
    # Twelve times the first word fails the checksum; the phrase is asked again.
    session.answer(BAD_CHECKSUM + b"\r", b"Please type it again", b"seed phrase: ")
    # A valid phrase is taken at once: the private screen is left without a question.
    session.answer(
        PHRASE.encode() + b"\r", LEAVE_PRIVATE, PHRASE_RECORDED, b"How long should", LIST_SHOWN
    )
    session.answer(b"?", EXPLAINED, LIST_SHOWN)
    session.answer(IGNORED_KEY + DOWN + UP + ENTER, LENGTH_RECORDED, b"Password: ")
    session.answer(SECRET + b"\r", b"Repeat the password: ")
    session.answer(SECRET + CTRL_C, b"Cancelled")
    assert session.drain_until_exit(10), "encrypt: Ctrl+C did not end the tool"
    code, settings = session.close()
    assert code == CANCELLED, f"encrypt: Ctrl+C gave exit code {code}"
    assert settings == session.original, "encrypt: the terminal settings were not restored"
    shown_privately("encrypt", session.output, SECRET)
    assert IGNORED_KEY not in session.output, "encrypt: a key was shown"
    print("encrypt: own settings; phrase refused once, then taken at once; ? and the arrows")
    print("encrypt: password shown only on the private screen; Ctrl+C leaves it, exit code 130")

    session = Session(arguments=("encrypt",))
    session.answer(b"", SETTINGS_ASKED, LIST_SHOWN)
    session.answer(ESCAPE, b"Cancelled")
    assert session.drain_until_exit(10), "encrypt: Escape did not end the tool"
    code, settings = session.close()
    assert code == CANCELLED, f"encrypt: Escape gave exit code {code}"
    assert settings == session.original, "encrypt: Escape did not restore the terminal settings"
    print("encrypt: Escape at a list cancels, exit code 130, terminal restored")


def main():
    # Each result is shown at once, so that a CI log shows how far the checks came.
    sys.stdout.reconfigure(line_buffering=True)
    for label, key in {**TERMINAL_KEYS, **OTHER_CONTROLS}.items():
        check_password(label, SECRET + key + b"x", REFUSED, not_shown=key)
        print(f"refused: a password with {label}")
    check_password("Unicode", SECRET + "пароль".encode(), ACCEPTED)
    print("accepted: a Unicode password")
    check_password("1024 x U+1D400", LONGEST, ACCEPTED)
    print("accepted: the longest valid password, 4096 bytes before normalization")
    # A TAB would be refused, so the password is accepted only if the key really deleted it.
    check_password("Backspace", SECRET + b"\t" + BACKSPACE, ACCEPTED)
    check_password("Ctrl+U", b"\t" + CTRL_U + SECRET, ACCEPTED)
    print("edited: Backspace and Ctrl+U at the password")

    session = Session()
    session.at_password_prompt()
    session.type(SECRET + CTRL_C)
    session.wait_for(b"Cancelled")
    code, settings = session.close()
    assert code == CANCELLED, f"Ctrl+C: exit code {code}"
    assert settings == session.original, "Ctrl+C: the terminal settings were not restored"
    shown_privately("Ctrl+C", session.output, SECRET)
    print("cancelled: Ctrl+C at the password, exit code 130, private screen left, terminal restored")

    check_menu()
    check_encrypt_lists()


if __name__ == "__main__":
    main()
