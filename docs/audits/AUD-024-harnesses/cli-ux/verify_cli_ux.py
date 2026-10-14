"""AUD-024 cli-ux: checks of the command-line tool's questions, prompts and messages.

    python3 docs/audits/AUD-024-harnesses/cli-ux/verify_cli_ux.py <path to the mhfe binary>

Each check drives the binary in a pseudo-terminal (Linux or macOS) or with standard input closed,
with public test data only, and stops it before any Argon2 round: no recovery, encryption or
memory reservation is reached. A check prints PASS when the tool behaves as its guide rules, help
texts and SECURITY.md say, and FAIL otherwise; the harness exits 1 when any check fails. At commit
b6fca69 every check fails: each one reproduces one AUD-024 cli-ux finding.
"""

import os
import pty
import re
import select
import signal
import subprocess
import sys
import time

P12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
P24 = " ".join(["abandon"] * 23 + ["art"])
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\r")
# Longer than the tool's 200 ms window in which keys typed ahead are dropped.
ANSWER_DELAY = 0.35


class Session:
    """The binary in a pseudo-terminal of 100 x 40 cells with TERM `term`."""

    def __init__(self, binary, arguments, term, extra_env=None):
        env = {"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/tmp"), "TERM": term,
               "LANG": "C.UTF-8", **(extra_env or {})}
        pid, fd = pty.fork()
        if pid == 0:
            import fcntl
            import struct
            import termios

            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 100, 0, 0))
            os.execve(binary, [binary, *arguments], env)
        self.pid, self.fd, self.raw, self.status = pid, fd, b"", None

    def text(self):
        return ANSI.sub("", self.raw.decode("utf-8", "replace"))

    def read_for(self, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if select.select([self.fd], [], [], 0.05)[0]:
                try:
                    chunk = os.read(self.fd, 65536)
                except OSError:
                    return
                if not chunk:
                    return
                self.raw += chunk

    def wait_for(self, needle, limit=30):
        end = time.monotonic() + limit
        while time.monotonic() < end:
            if needle in self.text():
                self.read_for(0.3)
                return True
            self.read_for(0.1)
            if self.exited():
                return needle in self.text()
        return False

    def type(self, text):
        time.sleep(ANSWER_DELAY)
        os.write(self.fd, text.encode())

    def exited(self):
        if self.status is None:
            done, status = os.waitpid(self.pid, os.WNOHANG)
            if done:
                self.status = status
        return self.status is not None

    def stop(self):
        if not self.exited():
            self.type("\x03")
            self.read_for(1.5)
        if not self.exited():
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)
        self.read_for(0.2)


def dumb_terminal_asks_the_container_length(binary):
    """encrypt at TERM=dumb asks the container length of a 12-word phrase, numbered, as its
    --same-length help says a person at a terminal is asked."""
    s = Session(binary, ["encrypt", "--pim", "0", "--mem", "0"], "dumb")
    s.wait_for("Original seed phrase")
    s.type(P12 + "\r")
    s.wait_for("Container password")
    s.stop()
    return "How long should the encrypted phrase be?" in s.text()


def dumb_terminal_explains_the_password(binary):
    """check at TERM=dumb says what the container password is before its prompt (CORE-39)."""
    s = Session(binary, ["check", "--fingerprint", "--pim", "0", "--mem", "0"], "dumb")
    s.wait_for("Container, 24 words")
    s.type(P24 + "\r")
    s.wait_for("Container password")
    s.stop()
    return "NOT a BIP39 passphrase" in s.text()


def a_pim_out_of_range_is_asked_again_at_once(binary):
    """Own settings: a PIM out of range is refused before the memory level is asked (CORE-42)."""
    s = Session(binary, ["decrypt"], "xterm-256color")
    s.wait_for("Which settings was the container made with?")
    s.type("2")
    s.wait_for("PIM:")
    s.type("5000\r")
    s.read_for(1.5)
    asked_level = "Memory level:" in s.text()
    s.stop()
    return not asked_level


def wallets_asks_again_for_a_short_container(binary):
    """wallets with a 12-word container asks for the container again instead of ending."""
    s = Session(binary, ["wallets", "--pim", "0", "--mem", "0"], "xterm-256color")
    s.wait_for("Container, 24 words")
    s.type(P12 + "\r")
    s.read_for(2)
    ended = s.exited()
    s.stop()
    return not ended


def confirm_show_is_refused_before_the_container(binary):
    """rekey --confirm show at TERM=dumb, where no private screen exists, is refused before the
    container is asked, as --new-password words is."""
    s = Session(binary, ["rekey", "--confirm", "show", "--pim", "0", "--mem", "0"], "dumb")
    s.read_for(3)
    asked = "Container, 24 words" in s.text()
    s.stop()
    return not asked


def a_phrase_argument_is_not_repeated(binary):
    """A phrase given as an argument by mistake is not repeated by the usage error (SECURITY.md:
    error messages never contain a phrase)."""
    run = subprocess.run([binary, "decrypt", P12], stdin=subprocess.DEVNULL,
                         capture_output=True, env=dict(os.environ, NO_COLOR="1"))
    # The message is wrapped: compare with the white space collapsed.
    shown = " ".join((run.stderr + run.stdout).decode().split())
    return P12 not in shown


def an_unknown_coin_reads_as_a_sentence(binary):
    """The refusal of an unknown --coin is not the run-on "unknown coin the coins are"."""
    run = subprocess.run([binary, "check", "--address", "--coin", "dogecoinz"],
                         stdin=subprocess.DEVNULL, capture_output=True,
                         env=dict(os.environ, NO_COLOR="1"))
    text = " ".join(run.stderr.decode().split())
    return "unknown coin the coins" not in text


def dumb_terminal_has_no_colour_with_ci_or_clicolor(binary):
    """TERM=dumb turns colour off also when CI=true or CLICOLOR=1 is set (CORE-38): no SGR
    sequence in what repair-words writes to the terminal."""
    for extra in ({"CI": "true"}, {"CLICOLOR": "1"}):
        s = Session(binary, ["repair-words", "--count", "4"], "dumb", extra)
        s.wait_for("Container, 24 words")
        s.type(P24 + "\r")
        s.wait_for("Write it on a card")
        s.stop()
        if re.search(rb"\x1b\[[0-9;]*m", s.raw):
            return False
    return True


CHECKS = [
    dumb_terminal_asks_the_container_length,
    dumb_terminal_explains_the_password,
    a_pim_out_of_range_is_asked_again_at_once,
    wallets_asks_again_for_a_short_container,
    confirm_show_is_refused_before_the_container,
    a_phrase_argument_is_not_repeated,
    an_unknown_coin_reads_as_a_sentence,
    dumb_terminal_has_no_colour_with_ci_or_clicolor,
]


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    binary = os.path.abspath(sys.argv[1])
    failed = 0
    for check in CHECKS:
        passed = check(binary)
        failed += not passed
        print(f"{'PASS' if passed else 'FAIL'} {check.__name__}")
    print(f"{len(CHECKS) - failed} of {len(CHECKS)} checks pass")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
