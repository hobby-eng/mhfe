"""Checks the hidden terminal input of the mhfe tool in a Windows pseudo-console (ConPTY).

    python scripts/verify-hidden-input-windows.py [path\\to\\mhfe.exe]

The Windows counterpart of scripts/verify-hidden-input.py, for CI on a Windows machine; it needs
the pywinpty package, pinned in scripts/verify-hidden-input-windows-requirements.txt. The default
program is target\\debug\\mhfe.exe. It drives `mhfe check --fingerprint`, which asks for the
container and then for the password at a hidden prompt, and stops the tool before a fingerprint is
given, so no memory is reserved and Argon2 never runs. Only the public zero-12 test container is
used.

It checks that
- control characters in a password reach the password check and are refused, including those a
  console in line mode would act on;
- a Unicode password and the longest valid password (1024 characters U+1D400) are accepted;
- Backspace and Ctrl+U edit the hidden line: a TAB typed and then deleted leaves an accepted
  password;
- nothing typed at the hidden prompt is shown;
- Ctrl+C at the hidden prompt ends the tool with exit code 130.

It also drives the menu that `mhfe` shows when it starts without arguments, which asks the console
for VT input so that the arrow keys arrive as on Unix: Down, Up and Enter choose `mhfe password`,
its number chooses it at once, Ctrl+Up's 5 chooses nothing, q quits with exit code 0 and Ctrl+C
with 130.
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
PASSWORD_ENTRY = 4
MENU_SHOWN, BACK_TO_MENU = "q quits", "return to the menu"
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
    def __init__(self, arguments=("check", "--fingerprint")):
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
        self.wait_for("original: ")
        self.type(CONTAINER + "\r")
        self.wait_for("Password")


def check_password(label, password, expected):
    session = Session()
    try:
        session.at_password_prompt()
        session.type(password + "\r")
        seen = session.wait_for(REFUSED, ACCEPTED)
        assert seen == expected, f"{label}: expected {expected!r}, the tool answered {seen!r}"
        assert SECRET not in session.output, f"{label}: the password was shown"
    finally:
        session.close()


def check_menu():
    session = Session(arguments=())
    try:
        session.wait_for(MENU_SHOWN)
        session.type(CTRL_UP + DOWN * PASSWORD_ENTRY + UP + ENTER)
        # The password and this prompt may arrive together, and wait_for looks only at new text.
        session.wait_for(BACK_TO_MENU)
        assert "bits" in session.output, "menu: the arrow keys did not choose mhfe password"
        session.type(ENTER)
        session.wait_for(MENU_SHOWN)
        session.type(str(PASSWORD_ENTRY))
        session.wait_for(BACK_TO_MENU)
        session.type("q")
        end = time.monotonic() + 10
        while session.process.isalive() and time.monotonic() < end:
            time.sleep(0.1)
    finally:
        code = session.close()
    assert code == 0, f"menu: q gave exit code {code}"
    print("menu: arrows, Enter, a number and q, exit code 0")

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
    print("edited: Backspace and Ctrl+U at a hidden prompt")

    session = Session()
    session.at_password_prompt()
    session.type(SECRET + CTRL_C)
    session.wait_for("Cancelled")
    code = session.close()
    assert code == CANCELLED, f"Ctrl+C: exit code {code}"
    print("cancelled: Ctrl+C at a hidden prompt, exit code 130")

    check_menu()


if __name__ == "__main__":
    main()
