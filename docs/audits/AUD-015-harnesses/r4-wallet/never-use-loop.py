#!/usr/bin/env python3
"""AUD-015 R4: `mhfe new --never-use <a word outside the list>` in a pseudo-terminal.

The option is not checked when the command starts. After the settings and the passphrase, the
chosen-word question comes; whatever the person answers there, the library refuses the option's
word, and the command asks the same question again with the same refused word, so there is no way
forward but to quit (src/bin/mhfe/chosen_words.rs, `ask`). This drives the release binary: the
default settings ("1"), no passphrase (Enter), "Every word at random" ("1") three times, then
Escape. It reaches no secret and no Argon2 beyond the startup known answers.

    python3 docs/audits/AUD-015-harnesses/r4-wallet/never-use-loop.py [path/to/mhfe]

Exits 1 when the question comes back after a refusal of the option's word (the defect), 0 when the
option is refused before the questions or the command goes on, 2 when the screens differ from
those expected.
"""
import fcntl
import os
import pty
import re
import select
import struct
import sys
import termios
import time

BINARY = sys.argv[1] if len(sys.argv) > 1 else "target/release/mhfe"
QUESTION = "Do you want to choose a word of the new phrase?"
REFUSAL = "not an English BIP39 word"
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]|\x1b[=>78]")


def main():
    pid, fd = pty.fork()
    if pid == 0:
        env = {"PATH": os.environ.get("PATH", ""), "TERM": "xterm-256color", "NO_COLOR": "1",
               "HOME": os.environ.get("HOME", "/")}
        os.execve(BINARY, [BINARY, "new", "--never-use", "notaword"], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 100, 0, 0))
    seen = ""

    def wait_for(text, count=1, timeout=60):
        nonlocal seen
        deadline = time.monotonic() + timeout
        while seen.count(text) < count:
            if time.monotonic() > deadline:
                return False
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    return False
                if not chunk:
                    return False
                seen += ANSI.sub("", chunk.decode("utf-8", "replace"))
        return True

    def send(keys):
        time.sleep(0.3)
        os.write(fd, keys)

    steps = [
        ("PIM 0 and memory level 0", 1, b"1"),
        ("BIP39 passphrase of the new wallet", 1, b"\r"),
        (QUESTION, 1, b"1"),
        (QUESTION, 2, b"1"),
        (QUESTION, 3, b"\x1b"),
    ]
    reached = 0
    for text, count, keys in steps:
        if not wait_for(text, count):
            break
        reached += 1
        send(keys)
    wait_for("\x00", timeout=5)  # Drains what the program writes as it ends.
    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    # A refusal wraps over lines that each begin with "!".
    refusals = re.sub(r"\s*\n!\s*", " ", seen).count(REFUSAL)
    questions = seen.count(QUESTION)
    print(f"steps reached {reached} of {len(steps)}; the question shown {questions} times; "
          f"the option's word refused {refusals} times")
    for line in seen.splitlines():
        if line.startswith("! "):
            print("  " + line.strip())
    if reached >= 4 and refusals >= 2:
        print("DEFECT: the refused --never-use word is asked about again with no way to change it")
        return 1
    if reached < 3 and refusals >= 1:
        return 0
    print("--- screen text ---")
    print(seen[-3000:])
    return 2


if __name__ == "__main__":
    sys.exit(main())
