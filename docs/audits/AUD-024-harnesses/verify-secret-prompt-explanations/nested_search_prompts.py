#!/usr/bin/env python3
"""AUD-024 verifier probe: the secret prompts of the missing-word search, at TERM=xterm-256color,
with standard output on the terminal (the command's steps are shown) and redirected to /dev/null (no
steps; the container's private screen is active and the search's prompts open nested, inactive
screens). Public data only: the 24-word "abandon ... art" container with word 4 typed as ?, the
BIP39 test-vector passphrase "TREZOR"; no password is typed. Every run ends with Ctrl+C at
the container password prompt, before the memory reservation and any Argon2 round (run_long, container_search.rs:455, comes after read_password).

Usage: nested_search_prompts.py <path to mhfe>
Exits 1 if a prompt lacks its explanation in any case.
"""
import os
import pty
import re
import select
import struct
import fcntl
import termios
import sys
import time

WORDS = ["abandon"] * 23 + ["art"]
WORDS[3] = "?"
MARKED = " ".join(WORDS)
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")


def flat(text):
    return " ".join(text.split())


class Session:
    def __init__(self, binary, args, term, stdout_file=None):
        self.out = b""
        pid, fd = pty.fork()
        if pid == 0:
            if stdout_file:
                f = os.open(stdout_file, os.O_WRONLY)
                os.dup2(f, 1)
            env = {k: v for k, v in os.environ.items() if k not in ("NO_COLOR", "CI")}
            env["TERM"] = term
            os.execve(binary, [binary] + args, env)
        self.pid, self.fd = pid, fd
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 100, 0, 0))
        self.code = None

    def read_for(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            ready, _, _ = select.select([self.fd], [], [], 0.05)
            if ready:
                try:
                    data = os.read(self.fd, 65536)
                except OSError:
                    return
                if not data:
                    return
                self.out += data

    def wait_for(self, needle, start=0, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            if needle in flat(self.since(start)):
                self.read_for(0.4)
                return
            self.read_for(0.1)
        raise SystemExit(f"timeout waiting for {needle!r}; output so far:\n{self.since(start)}")

    def type(self, text):
        for ch in text:
            os.write(self.fd, ch.encode())
            time.sleep(0.003)

    def stop(self):
        os.write(self.fd, b"\x03")
        self.read_for(1.5)
        _, status = os.waitpid(self.pid, 0)
        self.code = os.waitstatus_to_exitcode(status)

    def mark(self):
        return len(self.out)

    def since(self, start):
        return ANSI.sub(b"", self.out[start:]).decode("utf-8", "replace").replace("\r", "")


def run(binary, redirected):
    label = "stdout to /dev/null" if redirected else "stdout on the terminal"
    path = os.devnull
    s = Session(binary, ["decrypt", "--pim", "0", "--mem", "0"], "xterm-256color",
                path if redirected else None)
    s.wait_for("Container, 24 words")
    start = s.mark()
    s.type(MARKED + "\r")
    s.wait_for("Repair words:", start)
    start = s.mark()
    s.type("\r")
    s.wait_for("what do you know?", start)
    menu = s.since(start)
    # The answer "The original seed phrase's passphrase": its number in the list.
    number = None
    for line in menu.split("\n"):
        m = re.search(r"(\d)\.?\s+The original seed phrase's passphrase", line)
        if m:
            number = m.group(1)
    if number is None:
        raise SystemExit(f"no passphrase answer in:\n{menu}")
    start = s.mark()
    s.type(number)
    s.wait_for("BIP39 passphrase of the original seed phrase", start)
    seg = flat(s.since(start))
    passphrase_explained = "it is NOT the container password" in seg
    start = s.mark()
    s.type("TREZOR\r")
    s.wait_for("Start the search?", start)
    menu = s.since(start)
    start = s.mark()
    s.type("1")
    s.wait_for("Container password", start)
    seg = flat(s.since(start))
    password_explained = "it is NOT a BIP39 passphrase" in seg
    s.stop()
    print(f"decrypt search, {label:24} passphrase prompt explained={passphrase_explained}")
    print(f"decrypt search, {label:24} password prompt explained={password_explained}")
    print(f"    (ended by Ctrl+C at the password prompt, exit code {s.code})")
    return passphrase_explained and password_explained


def main():
    binary = os.path.abspath(sys.argv[1])
    ok = [run(binary, False), run(binary, True)]
    sys.exit(0 if all(ok) else 1)


if __name__ == "__main__":
    main()
