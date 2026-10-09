"""AUD-015 R2 probe: what does Ctrl+\\ (SIGQUIT) leave on the terminal while a secret is on the private
screen and the tool reads a line in the terminal's own line mode?

    python3 docs/audits/AUD-015-harnesses/r2-cli/quit_key_private_screen.py [path/to/mhfe]

In `mhfe new` a chosen word of the new phrase is typed on the private screen, and its position is
then asked on the same screen with an ordinary visible prompt (chosen_words.rs read_place), in the
terminal's line mode, where Ctrl+\\ sends SIGQUIT and Ctrl+Z SIGTSTP. Only SIGINT has a handler
(terminal.rs stop_on_ctrl_c). The probe gives no passphrase, chooses one word, types the public word
"zoo" and presses Ctrl+\\ at the position prompt. Nothing is drawn and Argon2 never runs.

Reported, not judged against a stated promise (SECURITY.md promises the clearing on acceptance and
on Ctrl+C): exit 1 when the tool ended without leaving the alternate screen while the chosen word
was still on it, 0 when it left the screen or did not die.
"""

import sys

from pty_session import ENTER_PRIVATE, LEAVE_PRIVATE, Screen, Session, program

QUIT = b"\x1c"


def main():
    tool = program(sys.argv)
    session = Session(tool, ["new", "--pim", "0"])
    session.wait_for(b"or Enter for none: ")
    session.type(b"\r", then=b"choose a word")
    session.type(b"2", then=b"Chosen word, or Enter for none: ")
    session.type(b"zoo\r", then=b"or Enter for anywhere: ")
    session.type(QUIT)
    session.wait_exit(limit=10)
    code, settings = session.finish()
    output = session.output
    screen = Screen(80, 24)
    screen.feed(output)
    left = output.rfind(LEAVE_PRIVATE) > output.rfind(ENTER_PRIVATE)
    print(f"exit code {code} (negative: ended by that signal)")
    print(f"alternate screen left at the end: {left}")
    print(f"terminal settings restored: {settings == session.original}")
    print(f"what the terminal shows afterwards:\n{screen.text()}")
    if code is not None and code < 0 and not left and "zoo" in screen.text():
        print("FAIL (reproduced): SIGQUIT ended the tool on the alternate screen, with the chosen "
              "word still shown and no clearing")
        return 1
    print("PASS: the private screen was cleared and left, or the tool did not end")
    return 0


if __name__ == "__main__":
    sys.exit(main())
