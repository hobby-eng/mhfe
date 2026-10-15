"""Checks the hidden terminal input of the mhfe tool in a Windows
pseudo-console (ConPTY).

python scripts/verify-hidden-input-windows.py [path\\to\\mhfe.exe]

The Windows counterpart of scripts/verify-hidden-input.py, for CI on a
Windows machine; it needs the pywinpty package, pinned in
scripts/verify-hidden-input-windows-requirements.txt. The default
program is target\\debug\\mhfe.exe. It drives `mhfe check --fingerprint
--pim 0`, which reads the container on a step of its own, taken at once,
and then the container password on another, and stops the tool before a
fingerprint is given, so no memory is reserved and Argon2 never runs;
the PIM given skips the question of the settings. Only the public
zero-12 test container is used. The pseudo-console redraws the screen in
its own way, so where the password is shown is checked in the Unix
pseudo-terminal only.

It checks that - control characters in a password reach the password
check and are refused, including those a console in line mode would act
on; - a Unicode password and the longest valid password (1024 characters
U+1D400) are accepted; - Backspace and Ctrl+U edit the line: a TAB typed
and then deleted leaves an accepted password; - Ctrl+C at the password
ends the tool with exit code 130.

It also drives the menu that `mhfe` shows when it starts without
arguments, which asks the console for VT input so that the arrow keys
arrive as on Unix: Down, Up and Enter choose `mhfe password`, its number
chooses it at once, Ctrl+Up's 5 chooses nothing, q and a lone Escape
quit with exit code 0 and Ctrl+C with 130. The password entry
regenerates on Enter and returns on Escape/q; help still returns to the
menu on Enter.
"""

import os
from pathlib import Path
import sys
import time

# Deliberate copy in the four checker entry points: refuse before any
# optional dependency or test module loads. verify-python-checks.mjs
# checks
# their identical refusal under -O, -OO and PYTHONOPTIMIZE.
if sys.flags.optimize:
    sys.exit(
        "Python optimization disables assertions; run this checker "
        "without -O or PYTHONOPTIMIZE."
    )

# TOOL-01: in-process ConPTY tests need Python's pywinpty library.
from terminal_suite import constants as shared

ROOT = Path(__file__).resolve().parent.parent
PROGRAM = shared.PROGRAM if len(sys.argv) > 1 else str(ROOT / "target" / "debug" / "mhfe.exe")
if shared.FULL:
    print("This Windows checker does not support --full.", file=sys.stderr)
    sys.exit(2)
CONTAINER, CANCELLED = shared.CONTAINER, shared.CANCELLED
REFUSED, ACCEPTED = shared.REFUSED.decode(), shared.ACCEPTED.decode()
READ_BACK_PROMPT = shared.READ_BACK_PROMPT.decode()
# ConPTY uses a different Backspace byte; all other keys are shared
# public input.
BACKSPACE = "\x08"
CTRL_U, CTRL_C = shared.CTRL_U.decode(), shared.CTRL_C.decode()
UP, DOWN, ENTER, CTRL_UP, ESCAPE = (key.decode() for key in (
    shared.UP, shared.DOWN, shared.ENTER, shared.CTRL_UP, shared.ESCAPE))
PASSWORD_ENTRY, HELP_FROM_PASSWORD = shared.PASSWORD_ENTRY, shared.HELP_FROM_PASSWORD
MENU_SHOWN, BACK_TO_MENU, PASSWORD_AGAIN, PASSWORD_KIND = (text.decode() for text in (
    shared.MENU_SHOWN, shared.BACK_TO_MENU, shared.PASSWORD_AGAIN, shared.PASSWORD_KIND))
# U+0085 is parsed as VT input by ConPTY and cannot be sent unchanged;
# Unix PTY tests cover it.
CONTROLS = {name: shared.TERMINAL_KEYS[name].decode() for name in (
    "Ctrl+S", "Ctrl+Q", "Ctrl+V", "Ctrl+W", "Ctrl+Z", "Ctrl+\\")}
CONTROLS["TAB"] = shared.OTHER_CONTROLS["TAB"].decode()
SECRET, LONGEST = shared.SECRET.decode(), shared.LONGEST.decode()
ANSWER_DELAY = shared.ANSWER_DELAY


from winpty import PtyProcess


class Session:
    def __init__(self, arguments=("check", "--fingerprint", "--pim", "0")):
        environment = dict(os.environ, NO_COLOR="1")
        self.process = PtyProcess.spawn(
            [PROGRAM, *arguments], env=environment, dimensions=(40, 200)
        )
        self.output = ""

    def wait_for(self, *needles, limit=20):
        """Reads until one of `needles` appears after the text already
        seen; returns it.
        """
        start = len(self.output)
        end = time.monotonic() + limit
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            # pywinpty 3.0.5 reads through this socket. A blocking recv
            # must not outlive the prompt deadline.
            self.process.fileobj.settimeout(remaining)
            try:
                self.output += self.process.read(4096)
            except (EOFError, TimeoutError):
                break
            for needle in needles:
                if needle in self.output[start:]:
                    return needle
            time.sleep(0.05)
        raise AssertionError(f"none of {needles} in {self.output[start:]!r}")

    def type(self, text):
        """Types `text` as a person answers what appeared: after
        ANSWER_DELAY.
        """
        time.sleep(ANSWER_DELAY)
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
        password_prompt = "Container password: "
        if self.wait_for(password_prompt, READ_BACK_PROMPT) == READ_BACK_PROMPT:
            self.type(ENTER)
            self.wait_for(password_prompt)


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
        # The password and this prompt may arrive together, and wait_for
        # looks only at new text.
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

    # Escape alone: the tool waits a moment for the rest of an arrow
    # key's sequence, then quits.
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
    # Keep progress visible if the console or tool stops replying.
    sys.stdout.reconfigure(line_buffering=True)
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
