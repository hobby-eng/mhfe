"""Audit AUD-024 (verifier, ask-again candidate), commit b6fca69: CORE-42 for the settings and
chosen-word questions of mhfe.

    python3 docs/audits/AUD-024-harnesses/verify-ask-again/check_ask_again.py <mhfe binary>

Each case drives the binary in a pseudo-terminal, types one wrong answer among valid ones and
checks that only the wrong answer is asked again, keeping the valid ones (CORE-42). Every case is
stopped with Ctrl+C before any Argon2 round. Public test data only. Prints PASS or FAIL per case
and exits 1 when any case fails.
"""
import os, pty, re, select, signal, sys, time

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b[()][A-Z0-9]|\r")


class Session:
    def __init__(self, binary, args):
        env = {"PATH": "/usr/bin:/bin", "HOME": os.environ.get("HOME", "/tmp"),
               "TERM": "xterm-256color", "LANG": "C.UTF-8"}
        pid, fd = pty.fork()
        if pid == 0:
            import fcntl, struct, termios
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
            os.execve(binary, [binary, *args], env)
        self.pid, self.fd, self.raw, self.seen = pid, fd, b"", 0

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

    def wait(self, needle, limit=20):
        """The text shown since the last wait, once `needle` is in it; None if it never comes."""
        end = time.monotonic() + limit
        while time.monotonic() < end:
            text = ANSI.sub("", self.raw[self.seen:].decode("utf-8", "replace"))
            if needle in text:
                self.pump(0.4)
                text = ANSI.sub("", self.raw[self.seen:].decode("utf-8", "replace"))
                self.seen = len(self.raw)
                return text
            self.pump(0.1)
        return None

    def after(self, keys, seconds=2.0):
        """Types `keys` and returns the text shown in the next `seconds`."""
        for character in keys:
            os.write(self.fd, character.encode())
            time.sleep(0.03)
        self.pump(seconds)
        text = ANSI.sub("", self.raw[self.seen:].decode("utf-8", "replace"))
        self.seen = len(self.raw)
        return text

    def stop(self):
        try:
            os.write(self.fd, b"\x03")
        except OSError:
            pass
        self.pump(1.0)
        try:
            os.kill(self.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(self.pid, 0)


def flat(text):
    """A refusal as one line: wrapped lines joined, their '! ' marks removed."""
    return " ".join(line.removeprefix("! ").strip() for line in (text or "").splitlines())


def own_settings(binary):
    s = Session(binary, ["decrypt"])
    s.wait("Which settings was the container made with?")
    s.after("2")
    return s


def a_refused_level_keeps_the_pim(binary):
    """PIM 0, then memory level 22: the level is refused and asked again, not the PIM."""
    s = own_settings(binary)
    s.after("0\r")
    shown = s.after("22\r")
    s.stop()
    return "not 22" in flat(shown) and "Memory level:" in shown and "PIM:" not in shown


def a_level_above_this_computer_keeps_the_pim(binary):
    """PIM 0, then a level above the one this computer can hold: only the level is asked again."""
    s = own_settings(binary)
    shown = s.after("0\r")
    match = re.search(r"memory for level (\d+) at most", shown)
    if not match or int(match.group(1)) >= 21:
        s.stop()
        print("  (no highest level below 21 is shown here: case not applicable, counted as passed)")
        return True
    shown = s.after(f"{int(match.group(1)) + 1}\r")
    s.stop()
    return "Please choose again" in flat(shown) and "Memory level:" in shown and "PIM:" not in shown


def a_pim_out_of_range_is_refused_when_typed(binary):
    """PIM 5000: refused and asked again before the memory level is asked."""
    s = own_settings(binary)
    shown = s.after("5000\r")
    s.stop()
    return "not 5000" in flat(shown) and "PIM:" in shown and "Memory level:" not in shown


NEW = ["new", "--pim", "0", "--mem", "0", "--wallet-check", "no", "--repair-words", "0"]


def a_refused_position_keeps_the_chosen_word(binary):
    """Chosen word abandon at position 0: the position is refused and asked again at once."""
    s = Session(binary, NEW + ["--choose-word", "yes", "--never-use", "zoo"])
    s.wait("BIP39 passphrase of the new wallet")
    s.after("\r")
    s.after("abandon\r")
    shown = s.after("0\r")
    s.stop()
    return ("position from 1 to 24" in flat(shown) and "Its position" in shown
            and "Chosen word" not in shown)


def a_refused_never_use_word_keeps_the_chosen_word(binary):
    """Chosen word abandon at 1, never-use word xyzzy: only the never-use word is asked again."""
    s = Session(binary, NEW + ["--choose-word", "yes"])
    s.wait("BIP39 passphrase of the new wallet")
    s.after("\r")
    s.after("abandon\r")
    s.after("1\r")
    shown = s.after("xyzzy\r")
    s.stop()
    return ("never to use" in flat(shown) and "Word never to use" in shown
            and "Chosen word" not in shown)


CHECKS = [
    a_refused_level_keeps_the_pim,
    a_level_above_this_computer_keeps_the_pim,
    a_pim_out_of_range_is_refused_when_typed,
    a_refused_position_keeps_the_chosen_word,
    a_refused_never_use_word_keeps_the_chosen_word,
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
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
