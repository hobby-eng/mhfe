"""Checks the terminal input of the mhfe tool in a pseudo-terminal (Linux and macOS).

    python3 scripts/verify-hidden-input.py [path/to/mhfe]

The default is target/debug/mhfe. At a terminal every step of a command has a screen of its own on
the terminal's alternate screen, and the main screen gets only the summary, when the command ends.
It drives `mhfe check --fingerprint --pim 0`, which reads the container on a step of its own, taken
at once, and then the container password on another, and stops the tool before a fingerprint is
given, so no memory is reserved and Argon2 never runs; the PIM given skips the question of the
settings. Only the public zero-12 test container is used.

It checks that
- every control character in a password reaches the password check and is refused, including
  the ones a terminal would otherwise act on (Ctrl+S, Ctrl+Q, Ctrl+V, Ctrl+W, Ctrl+R, Ctrl+O,
  Ctrl+\\, Ctrl+Z and Ctrl+D inside the line), and that a Unicode password is accepted, also the
  longest one: 1024 characters U+1D400, 4096 bytes that NFKD turns into 1024;
- Backspace and Ctrl+U edit the line: a TAB typed and then deleted leaves an accepted password;
- the password is shown as it is typed only on the alternate screen, which is cleared and left
  before the summary, and none of its control characters is ever written back;
- Ctrl+C at the password ends the tool with exit code 130 and leaves the alternate screen;
- the terminal settings are exactly the original ones afterwards, after a normal answer and after
  Ctrl+C.

A password with a check word (MHFE-PASSWORD-CHECK-1) is repaired only on the person's choice and
before Argon2: a word typed as ? is restored as the third public vector says, "chokehold", with the
repair as the first answer, also after a stray leading space, which the repair removes; a wrong word
gets the question with the password as typed first, and "Type the password again" asks for it
again. The summary records how the check word came out and none of the words.

A command started directly runs in a network namespace with only inactive loopback where the
system allows user namespaces. Its summary says "isolated network, new sockets blocked";
elsewhere it says "new sockets blocked" for the seccomp restriction. Previously opened
descriptors are not revoked by these restrictions.

It also drives the menu that `mhfe` shows when it starts without arguments: the arrow keys and Enter
choose an entry, its number chooses it at once, other escape sequences (Ctrl+Up) and keys do
nothing and are not shown, q and a lone Escape quit with exit code 0 and Ctrl+C with 130, and the
terminal settings are restored either way. The `mhfe password` entry shows each password on one
private screen, which it clears for the next one on Enter and when Escape or q returns to the menu;
the help entry returns on Enter. Neither needs secret input.

It answers the first question of `mhfe rekey`, which every user gets: whether the funds of other
wallets on the container are moved or backed up another way (AUD-007-FUN002). Yes goes on to the
container, No stops with exit code 130 before anything is typed, and so does Escape; the question
never asks for another wallet or its password.

Last, it answers the questions of `mhfe encrypt` up to the password, so again without Argon2: its
own settings, PIM 1 after a mistyped one; the phrase, refused once for its checksum and then taken
without a question; the length question on a cleared screen, where ? explains both lengths and the
arrows and Enter keep 24 words; no repair words; Ctrl+C at the repeated password ends the tool. The
summary then records the settings, the phrase's length, the container's and the repair choice, and
holds none of the questions.
Escape at a list cancels with exit code 130. The phrase is the public zero-12 test phrase and the
password a synthetic one, which never reaches the main screen.

Finally it checks that a phrase the person did not ask to export is shown only on a private screen
(AUD-007-SEC001): `mhfe new` and `mhfe wallets` refuse to start, before anything is asked and with
nothing on standard output, when standard output goes to a pipe or to a second terminal
(AUD-008-SEC004) or TERM is dumb, while `mhfe new` at a terminal goes on to its first question;
and `mhfe rekey` offers to show the phrase for the owner's comparison only when standard output is
the terminal. Neither gets as far as Argon2.
"""

import fcntl
import json
import os
from pathlib import Path
import re
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
# Exit codes of the tool when the person cancels and when an answer or the setup is refused
# (src/bin/mhfe/exit.rs).
CANCELLED, INVALID_INPUT = 130, 2
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
PASSWORD_ENTRY = 8
# The entry that shows the help, two below the password entry with mhfe self-test between: it is
# the tenth, past the number keys, so it is reached with the arrows from the password entry.
HELP_FROM_PASSWORD = 2
# The prompts are matched whole: the "Esc quits" at the end of the first must not pass for the menu.
MENU_SHOWN, PASSWORD_MADE = b"Esc quits", b"bits"
BACK_TO_MENU = b"Press Enter to return to the menu (Esc quits)."
PASSWORD_AGAIN = b"Press Enter for another password (Esc returns to the menu)."
# The question of the password entry: five dice words, five words and a check word, or sixteen
# random characters.
PASSWORD_KIND = b"What kind of password?"
# What the lists of `mhfe encrypt` show: a list's hint line, the explanation behind ?, and the line
# that records the chosen container length.
LIST_SHOWN, EXPLAINED = b"Esc cancels", b"8-character code"
LENGTH_RECORDED = b"Container  24 words (recommended)"
# The question about repair words for the plate, and the record of "No repair words".
REPAIR_ASKED, REPAIR_RECORDED = b"Repair words for the plate?", b"Repair     No repair words"
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
    def __init__(self, arguments=("check", "--fingerprint", "--pim", "0"), stdout=None, term=None):
        """`stdout` replaces the terminal as standard output, such as a pipe; `term` sets TERM."""
        self.master, self.slave = os.openpty()
        os.set_blocking(self.master, False)
        # The settings are read through the master side: on macOS the slave side stops answering
        # once the tool, the leader of its session, has ended, because the system revokes the
        # terminal of an ended session. The master side reads the same terminal on every system.
        self.original = termios.tcgetattr(self.master)
        # A capable terminal unless a case asks for another: the shell that runs the checks may
        # itself be a dumb one, as some editors' consoles are.
        environment = dict(os.environ, NO_COLOR="1", TERM=term or "xterm-256color")
        self.process = subprocess.Popen(
            [PROGRAM, *arguments],
            stdin=self.slave, stdout=self.slave if stdout is None else stdout, stderr=self.slave,
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
        self.answer(CONTAINER.encode() + b"\r", b"Container password: ")


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


# The third public vector of MHFE-PASSWORD-CHECK-1, and the question asked about its check word.
CHECK_WORD_PASSWORD = b"jovial trailing chokehold pavilion cresting ninth"
CHECK_WORD_ASKED = b"Repair the password with its check word?"


def check_check_word():
    session = Session()
    try:
        session.at_password_prompt()
        session.answer(CHECK_WORD_PASSWORD.replace(b"chokehold", b"?") + b"\r", CHECK_WORD_ASKED,
                       b"Word 3: chokehold", LIST_SHOWN)
        session.answer(ENTER, ACCEPTED)
    finally:
        code, settings = session.close()
    assert settings == session.original, "check word: the terminal settings were not restored"
    left = session.output.rfind(LEAVE_PRIVATE)
    record = b"Password   typed, word 3 repaired by its check word"
    assert record in session.output[left:], "check word: no record"
    assert b"chokehold" not in session.output[left:], "check word: a word reached the main screen"
    print("check word: a word typed as ? restored on Enter, recorded without the words")

    session = Session()
    try:
        session.at_password_prompt()
        wrong = CHECK_WORD_PASSWORD.replace(b"ninth", b"zoom")
        session.answer(wrong + b"\r", CHECK_WORD_ASKED, b"Word 6: ninth instead of zoom",
                       LIST_SHOWN)
        session.answer(b"2", b"Container password: ")
        session.answer(CHECK_WORD_PASSWORD + b"\r", ACCEPTED)
    finally:
        code, settings = session.close()
    assert settings == session.original, "check word: the terminal settings were not restored"
    left = session.output.rfind(LEAVE_PRIVATE)
    record = b"Password   typed, its check word fits"
    assert record in session.output[left:], "check word: a fit was not recorded"
    assert b"ninth" not in session.output[left:], "check word: a word reached the main screen"
    print("check word: a wrong word asked about, typed again, then the fit recorded")

    session = Session()
    try:
        session.at_password_prompt()
        # The stray space of a password typed in a hurry: the repair also removes it.
        typed = b" " + CHECK_WORD_PASSWORD.replace(b"chokehold", b"?")
        session.answer(typed + b"\r", CHECK_WORD_ASKED, b"Word 3: chokehold",
                       b"extra spaces removed", LIST_SHOWN)
        session.answer(ENTER, ACCEPTED)
    finally:
        code, settings = session.close()
    assert settings == session.original, "check word: the terminal settings were not restored"
    left = session.output.rfind(LEAVE_PRIVATE)
    record = b"Password   typed, word 3 repaired by its check word; extra spaces removed"
    assert record in session.output[left:], "check word: the corrected repair was not recorded"
    print("check word: a leading space removed together with the repair")


def user_namespaces_allowed():
    """Whether a process of this user may create a user namespace with an empty network, which
    some systems refuse; tried in a child, so that this process stays as it is."""
    if not hasattr(os, "unshare"):
        return False
    child = os.fork()
    if child == 0:
        try:
            os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNET)
        except OSError:
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    return os.waitstatus_to_exitcode(status) == 0


def check_empty_network():
    """A command started directly runs in an empty network where the system allows it, and says
    so in its summary; elsewhere it runs on with the seccomp filter alone."""
    if sys.platform != "linux":
        return
    session = Session()
    try:
        session.at_password_prompt()
    finally:
        session.close()
    shown = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", session.output)
    allowed = user_namespaces_allowed()
    expected = (
        b"isolated network, new sockets blocked"
        if allowed
        else b"Isolation  new sockets blocked,"
    )
    assert expected in shown, f"empty network: {expected!r} not in the summary"
    state = "an empty network" if allowed else "seccomp alone, as this system allows no namespace"
    print(f"isolation: a command started directly runs with {state}")


def check_menu():
    session = Session(arguments=())
    session.wait_for(MENU_SHOWN)
    moves = DOWN * PASSWORD_ENTRY + UP
    # The password and the prompt arrive together; the count of passwords is checked at the end.
    session.answer(IGNORED_KEY + CTRL_UP + moves + ENTER, PASSWORD_KIND)
    session.answer(ENTER, PASSWORD_AGAIN)
    for _ in range(2):
        session.answer(ENTER, PASSWORD_AGAIN)
    session.answer(ESCAPE, MENU_SHOWN)
    # The second time, random characters.
    session.answer(str(PASSWORD_ENTRY).encode(), PASSWORD_KIND)
    session.answer(b"3", b"random characters", PASSWORD_AGAIN)
    session.answer(b"q", MENU_SHOWN)
    # The menu keeps the password entry highlighted after it.
    session.answer(DOWN * HELP_FROM_PASSWORD + ENTER, BACK_TO_MENU)
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
    # A password of random characters may hold the key's letter; nothing else may.
    shown = re.sub(rb"(?m)^  [2-9A-HJ-NP-Za-km-z]{16}\r?$", b"", session.output)
    assert IGNORED_KEY not in shown, "menu: a key was shown"
    print("menu: password regeneration, Escape/q return, private screens cleared, terminal restored")
    print("menu: the password entry asks for words or characters and makes both")

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


def check_rekey_asks_about_other_wallets():
    question = b"backed up another way?"
    for label, key, expected in (("Yes", b"1", (b"original: ",)),
                                 ("No", b"2", (b"Move the funds", b"Cancelled")),
                                 ("Escape", ESCAPE, (b"Cancelled",))):
        session = Session(("rekey", "--pim", "0", "--words", "24"))
        session.wait_for(question)
        session.answer(key, *expected)
        code, settings = session.close()
        assert code == CANCELLED, f"rekey, {label}: exit code {code}"
        assert settings == session.original, f"rekey, {label}: terminal settings changed"
        asked = session.output[: session.output.find(question)]
        assert b"Password" not in asked, f"rekey, {label}: a password was asked first"
        if label != "Yes":
            assert b"original: " not in session.output, f"rekey, {label}: went on to the container"
        result = "goes on to the container" if label == "Yes" else "stops, exit code 130"
        print(f"rekey: {label} at the question about other wallets {result}")


def check_encrypt_lists():
    session = Session(arguments=("encrypt",))
    # Nothing typed yet: this waits for the whole first question, its link and its list.
    session.answer(b"", SETTINGS_ASKED, LIST_SHOWN)
    session.answer(b"2", b"PIM: ")
    session.answer(b"x\r", b"whole number", b"PIM: ")
    session.answer(b"1\r", b"Memory level: ")
    session.answer(b"0\r", b"seed phrase: ")
    # Twelve times the first word fails the checksum; the phrase is asked again.
    session.answer(BAD_CHECKSUM + b"\r", b"Please type it again", b"seed phrase: ")
    # A valid phrase is taken at once, without a question; the next step clears the screen.
    session.answer(PHRASE.encode() + b"\r", CLEAR, b"How long should", LIST_SHOWN)
    session.answer(b"?", EXPLAINED, LIST_SHOWN)
    session.answer(IGNORED_KEY + DOWN + UP + ENTER, REPAIR_ASKED, LIST_SHOWN)
    # No repair words: they would appear only after the encryption, which this test never reaches.
    session.answer(b"5", b"Container password: ")
    session.answer(SECRET + b"\r", b"Repeat the container password: ")
    session.answer(SECRET + CTRL_C, b"Cancelled")
    assert session.drain_until_exit(10), "encrypt: Ctrl+C did not end the tool"
    code, settings = session.close()
    assert code == CANCELLED, f"encrypt: Ctrl+C gave exit code {code}"
    assert settings == session.original, "encrypt: the terminal settings were not restored"
    shown_privately("encrypt", session.output, SECRET)
    assert IGNORED_KEY not in session.output, "encrypt: a key was shown"
    # The steps stayed on the alternate screen; the main screen got the summary when it ended.
    summary = session.output[session.output.rfind(LEAVE_PRIVATE):]
    for record in (OWN_SETTINGS, PHRASE_RECORDED, LENGTH_RECORDED, REPAIR_RECORDED):
        assert record in summary, f"encrypt: the summary lacks {record!r}"
    for step in (b"How long should", b"seed phrase: ", EXPLAINED):
        assert step not in summary, f"encrypt: {step!r} reached the main screen"
    print("encrypt: own settings; phrase refused once, then taken at once; ? and the arrows")
    print("encrypt: password shown only on the alternate screen; Ctrl+C leaves it, exit code 130")
    print("encrypt: every step on a cleared screen; only the summary on the main screen")

    session = Session(arguments=("encrypt",))
    session.answer(b"", SETTINGS_ASKED, LIST_SHOWN)
    session.answer(ESCAPE, b"Cancelled")
    assert session.drain_until_exit(10), "encrypt: Escape did not end the tool"
    code, settings = session.close()
    assert code == CANCELLED, f"encrypt: Escape gave exit code {code}"
    assert settings == session.original, "encrypt: Escape did not restore the terminal settings"
    print("encrypt: Escape at a list cancels, exit code 130, terminal restored")


def run_with_output(arguments, redirected=False, term=None):
    """Starts the tool with standard output in a pipe when `redirected`; returns the session and
    the read end of the pipe, or None."""
    if not redirected:
        return Session(arguments, term=term), None
    reader, writer = os.pipe()
    session = Session(arguments, stdout=writer, term=term)
    # The tool holds its own copy; the pipe ends once the tool has ended.
    os.close(writer)
    return session, reader


def piped_output(reader):
    """Everything the tool wrote to standard output, read once it has ended."""
    data = b""
    while chunk := os.read(reader, 65536):
        data += chunk
    os.close(reader)
    return data


def other_terminal_output(leader):
    """Everything the tool wrote to a second terminal, read once it has ended. A pseudo-terminal
    whose other end is closed reports an error instead of the end of the data."""
    os.set_blocking(leader, False)
    data = b""
    try:
        while chunk := os.read(leader, 65536):
            data += chunk
    except OSError:
        pass
    os.close(leader)
    return data


def check_private_reveals():
    refused = b"only on a private screen"
    for command in ("new", "wallets"):
        for label, redirected, term in (("standard output in a pipe", True, None),
                                        ("TERM=dumb", False, "dumb")):
            session, reader = run_with_output((command, "--pim", "0"), redirected, term)
            session.wait_for(refused)
            code, settings = session.close()
            assert code == INVALID_INPUT, f"{command}, {label}: exit code {code}"
            assert settings == session.original, f"{command}, {label}: terminal settings changed"
            for asked in (b"assphrase", b"Password", b"Esc cancels"):
                assert asked not in session.output, f"{command}, {label}: asked {asked!r} first"
            if reader is not None:
                assert piped_output(reader) == b"", f"{command}, {label}: wrote to the pipe"
            print(f"{command}: refused with {label}, before any question, exit code 2")
        # Standard output on a second terminal: the private screen would be switched and cleared
        # on the first one only (AUD-008-SEC004).
        leader, follower = os.openpty()
        session = Session((command, "--pim", "0"), stdout=follower)
        os.close(follower)
        session.wait_for(refused)
        code, settings = session.close()
        label = "standard output on another terminal"
        assert code == INVALID_INPUT, f"{command}, {label}: exit code {code}"
        assert settings == session.original, f"{command}, {label}: terminal settings changed"
        for asked in (b"assphrase", b"Password", b"Esc cancels"):
            assert asked not in session.output, f"{command}, {label}: asked {asked!r} first"
        assert other_terminal_output(leader) == b"", f"{command}, {label}: wrote to it"
        print(f"{command}: refused with {label}, before any question, exit code 2")

    session = Session(("new", "--pim", "0"))
    session.wait_for(b"passphrase of the new wallet")
    code, _ = session.close()
    assert code == CANCELLED, f"new at a terminal: exit code {code}"
    print("new: at a terminal it goes on to the passphrase")

    for redirected in (False, True):
        session, reader = run_with_output(("rekey", "--pim", "0", "--words", "24"), redirected)
        # Everyone confirms that other wallets' funds are safe (AUD-007-FUN002).
        session.wait_for(b"backed up another way?")
        session.answer(b"1", b"original: ")
        session.answer(CONTAINER.encode() + b"\r", b"container password: ")
        session.answer(SECRET + b"\r", b"confirmed?", LIST_SHOWN)
        offered = b"Show me the phrase" in session.output
        code, _ = session.close()
        assert code == CANCELLED, f"rekey: exit code {code}"
        label = "with standard output in a pipe" if redirected else "at a terminal"
        assert offered != redirected, f"rekey, {label}: showing the phrase offered: {offered}"
        if reader is not None:
            assert piped_output(reader) == b"", f"rekey, {label}: wrote to the pipe"
        state = "not offered" if redirected else "offered"
        print(f"rekey: showing the phrase for comparison {state} {label}")


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

    check_check_word()
    check_empty_network()
    check_menu()
    check_rekey_asks_about_other_wallets()
    check_encrypt_lists()
    check_private_reveals()


if __name__ == "__main__":
    main()
