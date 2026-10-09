"""Checks the hidden terminal input of the mhfe tool in a Windows pseudo-console (ConPTY).

    python scripts/verify-hidden-input-windows.py [path\\to\\mhfe.exe]

The Windows counterpart of scripts/verify-hidden-input.py, for CI on a Windows machine; it needs
the pywinpty package, pinned in scripts/verify-hidden-input-windows-requirements.txt. The default
program is target\\debug\\mhfe.exe. It drives `mhfe check --fingerprint --pim 0`, which reads the
container on a step of its own, taken at once, and then the container password on another, and stops
the tool before a fingerprint is given, so no memory is reserved and Argon2 never runs; the PIM
given skips the question of the settings. Only the public zero-12 test container is used. The pseudo-console redraws
the screen in its own way, so where the password is shown is checked in the Unix pseudo-terminal
only.

It checks that
- control characters in a password reach the password check and are refused, including those a
  console in line mode would act on;
- a Unicode password and the longest valid password (1024 characters U+1D400) are accepted;
- Backspace and Ctrl+U edit the line: a TAB typed and then deleted leaves an accepted
  password;
- Ctrl+C at the password ends the tool with exit code 130.

It also drives the menu that `mhfe` shows when it starts without arguments, which asks the console
for VT input so that the arrow keys arrive as on Unix: Down, Up and Enter choose `mhfe password`,
its number chooses it at once, Ctrl+Up's 5 chooses nothing, q and a lone Escape quit with exit
code 0 and Ctrl+C with 130. The password entry regenerates on Enter and returns on Escape/q;
help still returns to the menu on Enter.
"""

import json
import os
from pathlib import Path
import sys
import time

from winpty import PtyProcess

ROOT = Path(__file__).resolve().parent.parent
PROGRAM = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "target" / "debug" / "mhfe.exe")
CONTAINER = json.loads((ROOT / "tests/fixtures/suite3-vectors/zero-12.json").read_text())["container"]
# Exit code of the tool when the person cancels (src/bin/mhfe/exit.rs).
CANCELLED = 130
# A refused password is asked again ("Please type it again"); an accepted one leads to the
# fingerprint question.
REFUSED = "again"
ACCEPTED = "ingerprint"
BACKSPACE, CTRL_U, CTRL_C = "\x08", "\x15", "\x03"
# The keys of the menu as VT input; the pseudo-console turns them into key presses.
UP, DOWN, ENTER, CTRL_UP = "\x1b[A", "\x1b[B", "\r", "\x1b[1;5A"
# The menu entry of `mhfe password` when no browser tool lies next to the program.
PASSWORD_ENTRY = 8
# The entry that shows the help, two below the password entry with mhfe self-test between: it is
# the tenth, past the number keys, so it is reached with the arrows from the password entry.
HELP_FROM_PASSWORD = 2
# The prompts are matched whole: the "Esc quits" at the end of the first must not pass for the menu.
MENU_SHOWN = "Esc quits"
BACK_TO_MENU = "Press Enter to return to the menu (Esc quits)."
PASSWORD_AGAIN = "Press Enter for another password (Esc returns to the menu)."
# The question of the password entry: five dice words, five words and a check word, or sixteen
# random characters.
PASSWORD_KIND = "What kind of password?"
ESCAPE = "\x1b"
CONTROLS = {
    "TAB": "\t",
    "Ctrl+S": "\x13",
    "Ctrl+Q": "\x11",
    "Ctrl+V": "\x16",
    "Ctrl+W": "\x17",
    "Ctrl+Z": "\x1a",
    "Ctrl+\\": "\x1c",
}
# U+0085 (NEL) is left out: the pseudo-console parses its input as VT sequences and does not pass
# the C1 control on to the program, so the password arrives without it. The password check that
# refuses it is covered by the library tests and by scripts/verify-hidden-input.py in a Unix PTY.
SECRET = "synthetic"
LONGEST = "\U0001d400" * 1024


class Session:
    def __init__(self, arguments=("check", "--fingerprint", "--pim", "0")):
        environment = dict(os.environ, NO_COLOR="1")
        self.process = PtyProcess.spawn(
            [PROGRAM, *arguments], env=environment, dimensions=(40, 200)
        )
        self.output = ""

    def wait_for(self, *needles, limit=20):
        """Reads until one of `needles` appears after the text already seen; returns it."""
        start = len(self.output)
        end = time.monotonic() + limit
        while time.monotonic() < end:
            try:
                self.output += self.process.read(4096)
            except EOFError:
                break
            for needle in needles:
                if needle in self.output[start:]:
                    return needle
            time.sleep(0.05)
        raise AssertionError(f"none of {needles} in {self.output[start:]!r}")

    def type(self, text):
        self.process.write(text)

    def close(self):
        if self.process.isalive():
            self.type(CTRL_C)
            end = time.monotonic() + 10
            while self.process.isalive() and time.monotonic() < end:
                time.sleep(0.1)
        if self.process.isalive():
            self.process.terminate(force=True)
        return self.process.exitstatus

    def at_password_prompt(self):
        self.wait_for("original seed phrase: ")
        # The container is read on a step of its own and taken at once.
        self.type(CONTAINER + "\r")
        self.wait_for("Container password: ")


def check_password(label, password, expected):
    session = Session()
    try:
        session.at_password_prompt()
        session.type(password + "\r")
        seen = session.wait_for(REFUSED, ACCEPTED)
        assert seen == expected, f"{label}: expected {expected!r}, the tool answered {seen!r}"
    finally:
        session.close()


def check_menu():
    session = Session(arguments=())
    try:
        session.wait_for(MENU_SHOWN)
        session.type(CTRL_UP + DOWN * PASSWORD_ENTRY + UP + ENTER)
        session.wait_for(PASSWORD_KIND)
        session.type(ENTER)
        # The password and this prompt may arrive together, and wait_for looks only at new text.
        session.wait_for(PASSWORD_AGAIN)
        assert "bits" in session.output, "menu: the arrow keys did not choose mhfe password"
        for _ in range(2):
            session.type(ENTER)
            session.wait_for(PASSWORD_AGAIN)
        session.type(ESCAPE)
        session.wait_for(MENU_SHOWN)
        session.type(str(PASSWORD_ENTRY))
        session.wait_for(PASSWORD_KIND)
        # The second time, random characters.
        session.type("3")
        session.wait_for(PASSWORD_AGAIN)
        session.type("q")
        session.wait_for(MENU_SHOWN)
        # The menu keeps the password entry highlighted after it.
        session.type(DOWN * HELP_FROM_PASSWORD + ENTER)
        session.wait_for(BACK_TO_MENU)
        session.type(ENTER)
        session.wait_for(MENU_SHOWN)
        session.type("q")
        end = time.monotonic() + 10
        while session.process.isalive() and time.monotonic() < end:
            time.sleep(0.1)
    finally:
        code = session.close()
    assert code == 0, f"menu: q gave exit code {code}"
    print("menu: password regeneration, Escape/q return, exit code 0")

    # Escape alone: the tool waits a moment for the rest of an arrow key's sequence, then quits.
    session = Session(arguments=())
    try:
        session.wait_for(MENU_SHOWN)
        session.type(ESCAPE)
        end = time.monotonic() + 10
        while session.process.isalive() and time.monotonic() < end:
            time.sleep(0.1)
    finally:
        code = session.close()
    assert code == 0, f"menu: Escape gave exit code {code}"
    print("menu: a lone Escape quits, exit code 0")

    session = Session(arguments=())
    session.wait_for(MENU_SHOWN)
    session.type(CTRL_C)
    session.wait_for("Cancelled")
    code = session.close()
    assert code == CANCELLED, f"menu: Ctrl+C gave exit code {code}"
    print("menu: Ctrl+C, exit code 130")


def main():
    for label, key in CONTROLS.items():
        check_password(label, SECRET + key + "x", REFUSED)
        print(f"refused: a password with {label}")
    check_password("Unicode", SECRET + "пароль", ACCEPTED)
    check_password("1024 x U+1D400", LONGEST, ACCEPTED)
    print("accepted: a Unicode password and the longest valid password")
    check_password("Backspace", SECRET + "\t" + BACKSPACE, ACCEPTED)
    check_password("Ctrl+U", "\t" + CTRL_U + SECRET, ACCEPTED)
    print("edited: Backspace and Ctrl+U at the password")

    session = Session()
    session.at_password_prompt()
    session.type(SECRET + CTRL_C)
    session.wait_for("Cancelled")
    code = session.close()
    assert code == CANCELLED, f"Ctrl+C: exit code {code}"
    print("cancelled: Ctrl+C at the password, exit code 130")

    check_menu()


if __name__ == "__main__":
    main()
