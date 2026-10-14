#!/usr/bin/env python3
"""AUD-024 verifier probe: does each secret prompt say what the secret is, at TERM=dumb and at
TERM=xterm-256color? Public test data only; every run ends with Ctrl+C at a secret prompt, before
any Argon2 round or memory reservation.

Usage: dumb_terminal_prompts.py <path to mhfe>
Prints one line per prompt and case; exits 1 if any prompt at TERM=dumb lacks its explanation.
"""
import os
import pty
import re
import select
import signal
import struct
import fcntl
import termios
import sys
import time

P12 = " ".join(["abandon"] * 11 + ["about"])
P24 = " ".join(["abandon"] * 23 + ["art"])
PASSWORD = "public test password"  # tests/fixtures/validation-cases.json
ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")


class Session:
    def __init__(self, binary, args, term):
        self.out = b""
        pid, fd = pty.fork()
        if pid == 0:
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

    def wait_for(self, needle, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            if needle.encode() in ANSI.sub(b"", self.out):
                self.read_for(0.3)
                return
            self.read_for(0.1)
        raise SystemExit(f"timeout waiting for {needle!r}; output so far:\n{self.text()}")

    def type(self, text):
        for ch in text:
            os.write(self.fd, ch.encode())
            time.sleep(0.003)

    def stop(self):
        os.write(self.fd, b"\x03")
        self.read_for(1.5)
        _, status = os.waitpid(self.pid, 0)
        self.code = os.waitstatus_to_exitcode(status)

    def text(self):
        return ANSI.sub(b"", self.out).decode("utf-8", "replace").replace("\r", "")

    def mark(self):
        return len(self.out)

    def since(self, start):
        return ANSI.sub(b"", self.out[start:]).decode("utf-8", "replace").replace("\r", "")


def lines_before(text, prompt, n=3):
    idx = text.rfind(prompt)
    head = text[:idx].rstrip("\n").split("\n")
    return [line for line in head[-n:]]


def check_case(binary, term):
    """check --words auto --passphrase-used yes: container, password, BIP39 passphrase."""
    results = []
    s = Session(binary, ["check", "--words", "auto", "--passphrase-used", "yes",
                         "--pim", "0", "--mem", "0"], term)
    s.wait_for("Container, 24 words")
    start = s.mark()
    s.type(P24 + "\r")
    s.wait_for("Container password")
    seg = s.since(start)
    results.append(("check: container password", term,
                    "NOT a BIP39 passphrase" in " ".join(seg.split()), lines_before(seg, "Container password")))
    start = s.mark()
    s.type(PASSWORD + "\r")
    s.wait_for("BIP39 passphrase of")
    seg = s.since(start)
    results.append(("check: BIP39 passphrase", term,
                    "NOT the container password" in " ".join(seg.split()), lines_before(seg, "BIP39 passphrase of")))
    s.stop()
    return results, s.code


def encrypt_case(binary):
    """encrypt at TERM=dumb: settings, phrase, container password (own password only there)."""
    s = Session(binary, ["encrypt", "--pim", "0", "--mem", "0"], "dumb")
    s.wait_for("Original seed phrase")
    start = s.mark()
    s.type(P12 + "\r")
    s.read_for(2)
    seg = s.since(start)
    if "How long" in seg or "Choice" in seg:
        # The container length question of a 12-word phrase, if asked: take the default.
        s.type("\r")
    s.wait_for("Container password")
    seg = s.since(start)
    result = ("encrypt: container password", "dumb", "NOT a BIP39 passphrase" in " ".join(seg.split()),
              lines_before(seg, "Container password"))
    s.stop()
    return [result], s.code


def main():
    binary = os.path.abspath(sys.argv[1])
    missing_at_dumb = 0
    for case in (lambda: check_case(binary, "dumb"),
                 lambda: check_case(binary, "xterm-256color"),
                 lambda: encrypt_case(binary)):
        results, code = case()
        for name, term, explained, before in results:
            print(f"{name:32} TERM={term:15} explained={explained}")
            for line in before:
                print(f"    | {line}")
            if term == "dumb" and not explained:
                missing_at_dumb += 1
        print(f"    (run ended by Ctrl+C at the prompt, exit code {code})")
    print(f"prompts without their explanation at TERM=dumb: {missing_at_dumb}")
    sys.exit(1 if missing_at_dumb else 0)


if __name__ == "__main__":
    main()
