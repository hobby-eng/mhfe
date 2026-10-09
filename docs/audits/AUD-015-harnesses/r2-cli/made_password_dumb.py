"""AUD-015 R2 probe: where does a password made by `mhfe encrypt --new-password words` appear on a
terminal that cannot switch screens (TERM=dumb)?

    python3 docs/audits/AUD-015-harnesses/r2-cli/made_password_dumb.py [path/to/mhfe]

README.md ("A password it makes is shown once on a private screen") and the header of
src/bin/mhfe/made_password.rs say a made password is shown on a private screen. With TERM=dumb no
private screen can be opened. The probe types the public zero-12 phrase (hidden there), waits for
the prompt that asks the made password back, and stops the tool with Ctrl+C before anything is
encrypted; Argon2 never runs, and the address space is capped at 1 GiB in any case.

Expected by the documents: the made password never appears outside an alternate screen. Exit 1 when
it is written to the main screen (the defect), 0 otherwise. The password is random and synthetic: it
encrypts nothing and is discarded with the run.
"""

import re
import sys

from pty_session import ENTER_PRIVATE, PHRASE, Session, program

# Five EFF dice words on a line of their own, as made_password::show writes them.
MADE = re.compile(rb"\r\n  ([a-z]+(?:[ -][a-z]+){4})\r\n")


def main():
    tool = program(sys.argv)
    session = Session(tool, ["encrypt", "--pim", "0", "--new-password", "words"], term="dumb",
                      colour=False)
    session.wait_for(b"seed phrase (hidden): ")
    session.type(PHRASE + b"\r", then=b"Password as you wrote it down")
    code, settings = session.finish()
    output = session.output
    print(f"exit code {code}")
    print(f"output: {output!r}")
    shown = MADE.search(output)
    failed = False
    if not shown:
        print("FAIL: no made password was found in the output")
        return 1
    before = output[:shown.start()]
    if ENTER_PRIVATE not in before or before.rfind(b"\x1b[?1049l") > before.rfind(ENTER_PRIVATE):
        print("FAIL (defect reproduced): the made password was written to the main screen, outside "
              "any alternate screen, where it stays in the scrollback")
        failed = True
    else:
        print("PASS: the made password appeared only on an alternate screen")
    if settings != session.original:
        print("FAIL: the terminal settings changed")
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
