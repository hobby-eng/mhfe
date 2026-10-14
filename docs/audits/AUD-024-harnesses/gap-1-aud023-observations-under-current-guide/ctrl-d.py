#!/usr/bin/env python3
"""AUD-024 harness: Ctrl+D on the first, empty prompt or list of a command in a pseudo-terminal.
src/bin/mhfe/exit.rs documents CANCELLED (130) for "Escape or q at a question, or Ctrl+D at an
empty prompt". Prints one line per case and exits 1 when a visible prompt or a list ends with
another code than 130. No Argon2 round runs: every case ends at its first prompt.

    python3 ctrl-d.py <path to mhfe>
"""
import os
import pty
import re
import select
import sys
import time

binary = sys.argv[1]


def run(args, term, wait_for, label):
    pid, fd = pty.fork()
    if pid == 0:
        env = dict(os.environ, TERM=term, NO_COLOR="1", COLUMNS="100")
        os.execve(binary, [binary] + args, env)
    out = b""
    deadline = time.time() + 20
    sent = False
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        if not sent and wait_for.encode() in out:
            time.sleep(0.4)
            os.write(fd, b"\x04")
            sent = True
    for _ in range(50):
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            break
        time.sleep(0.1)
    else:
        os.kill(pid, 9)
        _, status = os.waitpid(pid, 0)
    code = os.waitstatus_to_exitcode(status)
    plain = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", out).decode("utf-8", "replace")
    lines = [line.strip() for line in plain.splitlines() if line.strip()]
    print(f"{label} [TERM={term}]: Ctrl+D sent: {sent}; exit {code}; "
          f"last line: {lines[-1] if lines else ''!r}")
    return code


visible = [
    run(["repair-words", "--count", "4"], "xterm-256color", "Container",
        "repair-words, empty container prompt (hinted)"),
    run(["repair-words", "--count", "4"], "dumb", "Container",
        "repair-words, empty container prompt (plain)"),
    run(["decrypt", "--pim", "0", "--mem", "0"], "xterm-256color", "Container",
        "decrypt, empty container prompt"),
    run(["decrypt"], "dumb", "Choice", "decrypt, settings question as a numbered list"),
]
controls = [
    run(["decrypt"], "xterm-256color", "Which settings", "decrypt, settings question as a list"),
    run(["encrypt", "--same-length", "no", "--new-password", "own", "--repair-words", "0"],
        "xterm-256color", "phrase", "encrypt, empty secret phrase prompt"),
]
failed = any(code != 130 for code in visible)
print(("FAIL" if failed else "PASS") + ": Ctrl+D at an empty visible prompt or numbered list "
      + ("does not" if failed else "does") + " end with 130 as exit.rs documents; controls: "
      + ", ".join(str(code) for code in controls))
sys.exit(1 if failed else 0)
