"""AUD-015 R2 probe: what a command started from the start menu states about its isolation.

    python3 docs/audits/AUD-015-harnesses/r2-cli/menu_isolation.py [path/to/mhfe]

SECURITY.md: a command started directly runs in a network namespace of its own and says "isolated
network, no new sockets or file writes"; the menu runs each command in a thread of its own, which
cannot get a namespace, so it says "no new sockets or file writes" (seccomp and Landlock alone,
both probed in that thread by protect::verify_isolation). The probe starts `mhfe` without
arguments, chooses `mhfe check` by its number in the menu, takes the default settings with Enter
and reads the Isolation line of the summary that Ctrl+C at the container prompt writes; then it starts
`mhfe check --fingerprint --pim 0` directly and reads the same line. Ctrl+C ends both before
anything secret is typed. Exit 0 when both lines say what SECURITY.md says for their case (the
direct one on a system that allows user namespaces), 1 otherwise.
"""

import re
import sys

from pty_session import Session, program

ISOLATION = re.compile(rb"Isolation\s+(?:\x1b\[0m\s*)?([^\r\n\x1b]+)")


def isolation_line(session):
    match = ISOLATION.search(session.output)
    return match.group(1).strip().decode() if match else None


def main():
    tool = program(sys.argv)
    failed = False

    menu = Session(tool, [], colour=False)
    menu.wait_for(b"Esc quits")
    # Without a browser tool next to the program: new, encrypt, decrypt, check, ...
    menu.type(b"4", then=b"Rehearse a recovery")
    try:
        menu.wait_for(b"Which settings")
        menu.type(b"\r")
        menu.wait_for(b"original seed phrase: ")
    finally:
        code, settings = menu.finish()
    # The facts of a command shown one step at a time come with its summary, after Ctrl+C.
    from_menu = isolation_line(menu)
    print(f"menu: exit code {code}; Isolation: {from_menu!r}")
    if from_menu != "no new sockets or file writes (kernel-enforced)":
        print("menu: FAIL: the line does not state seccomp and Landlock without a namespace")
        failed = True
    else:
        print("menu: PASS")
    if settings != menu.original:
        print("menu: FAIL: the terminal settings changed")
        failed = True

    direct = Session(tool, ["check", "--fingerprint", "--pim", "0"], colour=False)
    try:
        direct.wait_for(b"original seed phrase: ")
    finally:
        code, settings = direct.finish()
    started_directly = isolation_line(direct)
    print(f"direct: exit code {code}; Isolation: {started_directly!r}")
    if started_directly != "isolated network, no new sockets or file writes (kernel-enforced)":
        print("direct: FAIL (or this system allows no user namespaces)")
        failed = True
    else:
        print("direct: PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
