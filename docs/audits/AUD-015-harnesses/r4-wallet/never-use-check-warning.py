#!/usr/bin/env python3
"""AUD-015 R4: what `mhfe new --never-use abandon` says with the wallet check and no chosen word.

A word never to use costs about 0.02 bits (README, "Chosen words"), and "a word never to use alone
tells too little to matter"; with the check's 16 bits the phrase keeps 239.98 bits, under the
240 of RECOMMENDED_RANDOM_BITS. This drives the release binary in a pseudo-terminal: default
settings, the public test passphrase TREZOR typed twice, the phrase + passphrase check, "Every word
at random", and stops at the repair-words question that follows, before any phrase is drawn (no
wallet-check draw runs). It prints the warnings shown.

    python3 docs/audits/AUD-015-harnesses/r4-wallet/never-use-check-warning.py [path/to/mhfe]

Exits 1 when the person who chose no word is told "Not recommended" and advised about a word
anywhere and at a fixed position, 0 when not, 2 when the screens differ from those expected.
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
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]|\x1b[=>78]")


def main():
    pid, fd = pty.fork()
    if pid == 0:
        env = {"PATH": os.environ.get("PATH", ""), "TERM": "xterm-256color", "NO_COLOR": "1",
               "HOME": os.environ.get("HOME", "/")}
        os.execve(BINARY, [BINARY, "new", "--never-use", "abandon"], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 100, 0, 0))
    seen = ""

    def wait_for(text, timeout=60):
        nonlocal seen
        deadline = time.monotonic() + timeout
        while text not in seen:
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

    steps = [
        ("PIM 0 and memory level 0", b"1"),
        ("BIP39 passphrase of the new wallet", b"TREZOR\r"),
        ("Repeat the passphrase", b"TREZOR\r"),
        ("Do you want a check that confirms the password at recovery?", b"2"),
        ("Do you want to choose a word of the new phrase?", b"1"),
        ("Repair words for the container phrase?", None),
    ]
    reached = 0
    for text, keys in steps:
        if not wait_for(text):
            break
        reached += 1
        if keys is not None:
            time.sleep(0.3)
            os.write(fd, keys)
    # Stopped at the repair-words question: nothing is drawn.
    os.kill(pid, 9)
    os.waitpid(pid, 0)
    flat = re.sub(r"\s*\n!\s*", " ", seen)
    warnings = [line.strip() for line in seen.splitlines() if line.startswith("! ")]
    print(f"steps reached {reached} of {len(steps)}")
    for line in warnings:
        print("  " + line)
    told = "Not recommended: the phrase keeps about 239" in flat
    advised = "A word anywhere in the phrase keeps more than one at a fixed position" in flat
    if reached == len(steps) and told and advised:
        print("DEFECT: no word was chosen, yet the phrase is 'Not recommended' and the advice is "
              "about where to put a chosen word")
        return 1
    if reached == len(steps):
        return 0
    print(seen[-3000:])
    return 2


if __name__ == "__main__":
    sys.exit(main())
