"""AUD-015 R2 probe: are control sequences in a refused public answer written back to the terminal?

    python3 docs/audits/AUD-015-harnesses/r2-cli/public_answer_echo.py [path/to/mhfe]

`mhfe check --fingerprint` reads the public zero-12 container, a synthetic password and then the
master key fingerprint. A fingerprint that is not eight hexadecimal digits is refused with a message
that quotes what was typed (src/wallet.rs parse_fingerprint). The probe gives a "fingerprint" that
holds an OSC title sequence and an erase-display sequence:

- as a script (`--stdin`, standard input a pipe, standard error the terminal): the refusal ends the
  tool before any memory is reserved;
- at the terminal: the refusal is shown and the fingerprint asked again; Ctrl+C then ends the tool.

Expected: the refusal reaches the terminal without the typed escape bytes. Exit 1 when the raw bytes
reach the terminal (the defect), 0 otherwise. Argon2 never runs: the reference is read before the
memory is reserved, and the address space is capped at 1 GiB in any case.
"""

import sys

from pty_session import CONTAINER, Session, program

MARK = b"\x1b]0;AUD015-TITLE\x07"
ERASE = b"\x1b[2J"
TYPED = b"ab" + MARK + ERASE + b"cd"
PASSWORD = b"synthetic probe password 7"


def judge(label, output, failed):
    if b"is not eight hexadecimal digits" not in output:
        print(f"{label}: output tail {output[-400:]!r}")
        print(f"{label}: FAIL: the fingerprint was not refused as expected")
        return True
    # The refusal and what precedes it on its line: at a terminal, the line discipline's own echo
    # of the typed answer shows ESC as "^[" (ECHOCTL), so a raw ESC there comes from the tool.
    at = output.find(b"is not eight hexadecimal digits")
    refusal = output[output.rfind(b"Invalid master key fingerprint", 0, at):at + 60]
    print(f"{label}: echo and refusal {output[max(0, at - 120):at + 60]!r}")
    if MARK in refusal or ERASE in refusal:
        print(f"{label}: FAIL (defect reproduced): the typed escape sequences reached the terminal "
              "in the refusal")
        return True
    print(f"{label}: PASS: the refusal carries no typed escape bytes")
    return failed


def main():
    tool = program(sys.argv)
    failed = False

    script = Session(tool, ["check", "--stdin", "--fingerprint", "--pim", "0"],
                     stdin_data=CONTAINER + b"\n" + PASSWORD + b"\n" + TYPED + b"\n\n")
    script.wait_exit(limit=30)
    code, _ = script.finish(limit=5)
    print(f"script: exit code {code}")
    failed = judge("script", script.output, failed)

    person = Session(tool, ["check", "--fingerprint", "--pim", "0"])
    person.wait_for(b"seed phrase: ")
    person.type(CONTAINER + b"\r", then=b"Container password: ")
    person.type(PASSWORD + b"\r", then=b"eight hex digits: ")
    person.type(TYPED + b"\r", then=b"type it again")
    code, settings = person.finish()
    print(f"terminal: exit code {code}")
    failed = judge("terminal", person.output, failed)
    if settings != person.original:
        print("terminal: FAIL: the terminal settings changed")
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
