"""Verifier probe (audit AUD-024): where no private screen can open (TERM=dumb), does the tool show
a displayed secret on the main screen? Public data only, no Argon2.

    python3 probe.py <binary>

Cases:
  A. mhfe password, TERM=dumb: the password line, any ESC[?1049h, whether it waits for a key.
  B. mhfe password, TERM=xterm-256color: the control case, alternate screen and a wait.
  C. mhfe repair-words --count 4, TERM=dumb and xterm-256color: PrivateScreen::enter_to_show,
     the same call decrypt.rs:212 makes for the recovered phrase, with a public container.
Exits 1 when case A shows the password on the main screen (the defect), 0 otherwise.
"""

import os
import pty
import re
import select
import signal
import sys
import time

BINARY = sys.argv[1]
ENTER_ALT = b"\x1b[?1049h"
LEAVE_ALT = b"\x1b[?1049l"
CONTAINER24 = " ".join(["abandon"] * 23 + ["art"])
WORDS5 = re.compile(rb"\r\n  (\x1b\[[0-9;]*m)*([a-z\-]+(?: [a-z\-]+){4})(\x1b\[[0-9;]*m)*\r\n")


def spawn(arguments, term):
    env = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "TERM": term, "LANG": "C.UTF-8"}
    pid, fd = pty.fork()
    if pid == 0:
        import fcntl, struct, termios
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 100, 0, 0))
        os.execve(BINARY, [BINARY, *arguments], env)
    return pid, fd


def read_for(fd, seconds, sink):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        ready, _, _ = select.select([fd], [], [], 0.05)
        if ready:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                return
            if not chunk:
                return
            sink.append(chunk)


EXITED = {}


def status(pid):
    if pid in EXITED:
        return EXITED[pid]
    done, code = os.waitpid(pid, os.WNOHANG)
    if done == 0:
        return None
    EXITED[pid] = os.waitstatus_to_exitcode(code)
    return EXITED[pid]


def finish(pid, fd, sink):
    code = status(pid)
    if code is None:
        os.write(fd, b"\x03")
        read_for(fd, 1.0, sink)
        code = status(pid)
        if code is None:
            os.kill(pid, signal.SIGKILL)
            code = os.waitstatus_to_exitcode(os.waitpid(pid, 0)[1])
            EXITED[pid] = code
    return code


def case_password(term):
    print(f"### mhfe password, TERM={term}")
    pid, fd = spawn(["password"], term)
    sink = []
    read_for(fd, 3.0, sink)
    first = b"".join(sink)
    alive = status(pid) is None
    print(f"after 3 s: still running (waiting for a key): {alive}")
    print(f"raw bytes: {first!r}")
    match = WORDS5.search(first)
    print(f"password line found: {bool(match)}")
    entered = ENTER_ALT in first
    print(f"ESC[?1049h written: {entered}")
    if match and entered:
        start = first.index(ENTER_ALT)
        print(f"password written after ESC[?1049h: {match.start() > start}")
    rest = []
    if alive:
        os.write(fd, b"\r")
        read_for(fd, 1.5, rest)
    code = finish(pid, fd, rest)
    tail = b"".join(rest)
    print(f"after Enter: raw bytes: {tail!r}")
    print(f"ESC[?1049l written at the end: {LEAVE_ALT in tail}")
    if match:
        print(f"password repeated after the screen was left: {match.group(2) in tail}")
    print(f"exit code: {code}")
    print()
    return bool(match), entered, alive


def case_repair_words(term):
    print(f"### mhfe repair-words --count 4, TERM={term} (PrivateScreen::enter_to_show)")
    pid, fd = spawn(["repair-words", "--count", "4"], term)
    sink = []
    read_for(fd, 2.0, sink)
    os.write(fd, CONTAINER24.encode() + b"\r")
    read_for(fd, 3.0, sink)
    out = b"".join(sink)
    alive = status(pid) is None
    print(f"still running (waiting for a key): {alive}")
    print(f"ESC[?1049h written: {ENTER_ALT in out}")
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]|\r", "", out.decode("utf-8", "replace"))
    print("as text:")
    print(text)
    code = finish(pid, fd, sink)
    print(f"exit code: {code}")
    print()


if __name__ == "__main__":
    shown_dumb, alt_dumb, waits_dumb = case_password("dumb")
    shown_xterm, alt_xterm, waits_xterm = case_password("xterm-256color")
    case_repair_words("dumb")
    case_repair_words("xterm-256color")
    defect = shown_dumb and not alt_dumb and not waits_dumb
    print(f"RESULT: TERM=dumb shows the password on the main screen without a wait: {defect}; "
          f"control TERM=xterm-256color uses the alternate screen and waits: "
          f"{shown_xterm and alt_xterm and waits_xterm}")
    sys.exit(1 if defect else 0)
