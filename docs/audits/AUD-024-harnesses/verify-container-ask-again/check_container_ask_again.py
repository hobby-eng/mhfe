"""Audit AUD-024 at b6fca69, verifier verify-container-ask-again.

Checks the coding guide's CORE-42 ("A wrong or unusable answer is explained in one line and asked
again ... A command ends only on the person's Escape or Ctrl+C, or on a critical self-test
failure") for a container or seed phrase that the command cannot use, typed at a terminal:

    python3 docs/audits/AUD-024-harnesses/verify-container-ask-again/check_container_ask_again.py <mhfe>

Each terminal case starts mhfe in a pseudo-terminal, types one answer (public test data only: the
BIP39 "abandon ... about" and "abandon ... art" phrases) and passes when the command is still
running 10 seconds later (it asks again, or goes on to its next question), and fails when it has
ended by itself. A running command is then stopped with Ctrl+C, before any Argon2 round. A last
case checks that a script (--stdin), which cannot be asked again, still ends with exit code 2.
Exit code 0 when every check passes, 1 otherwise.
"""

import os
import pty
import re
import select
import signal
import subprocess
import sys
import time

P12 = " ".join(["abandon"] * 11 + ["about"])
P24 = " ".join(["abandon"] * 23 + ["art"])
CONTAINER_PROMPT = "Container, 24 words"
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b[()][A-Z0-9]|\r|\x08")
ENV = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "TERM": "xterm-256color", "LANG": "C.UTF-8"}


class Session:
    def __init__(self, binary, arguments):
        pid, fd = pty.fork()
        if pid == 0:
            import fcntl
            import struct
            import termios

            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 200, 0, 0))
            os.execve(binary, [binary, *arguments], ENV)
        self.pid, self.fd, self.raw, self.status = pid, fd, b"", None

    def text(self):
        return ANSI.sub("", self.raw.decode("utf-8", "replace"))

    def pump(self, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            ready, _, _ = select.select([self.fd], [], [], 0.05)
            if ready:
                try:
                    chunk = os.read(self.fd, 65536)
                except OSError:
                    return
                if not chunk:
                    return
                self.raw += chunk

    def exited(self):
        if self.status is None:
            done, status = os.waitpid(self.pid, os.WNOHANG)
            if done:
                self.status = status
        return self.status is not None

    def wait_for(self, needle, limit=40):
        end = time.monotonic() + limit
        while time.monotonic() < end and not self.exited():
            if needle in self.text():
                self.pump(0.4)
                return True
            self.pump(0.1)
        return needle in self.text()

    def stop(self):
        if not self.exited():
            os.write(self.fd, b"\x03")
            self.pump(1.5)
        if not self.exited():
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
        self.pump(0.2)


def last_lines(text, count=3):
    return " | ".join(line.strip() for line in text.splitlines() if line.strip())[-300:]


def terminal_case(binary, name, arguments, prompt, answer):
    s = Session(binary, arguments)
    if not s.wait_for(prompt):
        s.stop()
        return False, f"prompt {prompt!r} not shown: {last_lines(s.text())}"
    time.sleep(0.4)  # longer than the tool's 200 ms typed-ahead window
    os.write(s.fd, (answer + "\r").encode())
    # The debug build redraws its word hints after every key: give it time to take the answer.
    end = time.monotonic() + 10
    while time.monotonic() < end and not s.exited():
        s.pump(0.2)
    ended = s.exited()
    code = os.waitstatus_to_exitcode(s.status) if ended else None
    text = s.text()
    s.stop()
    if ended:
        return False, f"ended by itself with exit code {code}: {last_lines(text)}"
    return True, "still running after the answer (asked again or went on)"


def script_case(binary):
    run = subprocess.run(
        [binary, "encrypt", "--same-length", "--stdin", "--pim", "0", "--mem", "0"],
        input=f"{P24}\npublic test password\npublic test password\n",
        capture_output=True, text=True, timeout=60, env=ENV,
    )
    if run.returncode == 2 and run.stdout == "":
        return True, "a script still ends with exit code 2 and no output"
    return False, f"exit code {run.returncode}, standard output {run.stdout!r}"


def main():
    if len(sys.argv) != 2:
        print("usage: check_container_ask_again.py <path to mhfe>", file=sys.stderr)
        return 2
    binary = sys.argv[1]
    cases = [
        # A control that passes at b6fca69: a usable container goes on to the next question.
        ("control_wallets_with_a_24_word_container", ["wallets", "--pim", "0", "--mem", "0"],
         CONTAINER_PROMPT, P24),
        ("wallets_with_a_12_word_container",["wallets", "--pim", "0", "--mem", "0"],
         CONTAINER_PROMPT, P12),
        ("encrypt_same_length_with_a_24_word_phrase",
         ["encrypt", "--same-length", "--pim", "0", "--mem", "0"], "Original seed phrase:", P24),
        ("decrypt_words_15_with_a_12_word_container",
         ["decrypt", "--words", "15", "--pim", "0", "--mem", "0"], CONTAINER_PROMPT, P12),
        ("check_words_15_with_a_12_word_container",
         ["check", "--words", "15", "--pim", "0", "--mem", "0"], CONTAINER_PROMPT, P12),
        ("rekey_words_15_with_a_12_word_container",
         ["rekey", "--words", "15", "--pim", "0", "--mem", "0"], CONTAINER_PROMPT, P12),
    ]
    passed = 0
    total = len(cases) + 1
    for name, arguments, prompt, answer in cases:
        ok, detail = terminal_case(binary, name, arguments, prompt, answer)
        passed += ok
        print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}")
    ok, detail = script_case(binary)
    passed += ok
    print(f"{'PASS' if ok else 'FAIL'} script_encrypt_same_length_24_still_exits_2: {detail}")
    print(f"{passed} of {total} checks pass")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
