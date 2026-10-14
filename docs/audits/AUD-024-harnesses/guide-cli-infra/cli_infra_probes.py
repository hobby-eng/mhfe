"""AUD-024 (guide-cli-infra) probes of the mhfe command-line infrastructure at commit b6fca69.

Each probe runs the given release binary with public data only and stops it before any secret
could be accepted, so no Argon2 round at suite cost runs (only the checks at start, which use
reduced-cost public vectors). Every probe prints one PASS or DEFECT line; the script exits 1 when
any probe shows its defect and 0 when none does.

  P1  repair and repair-words, without --stdin, read an endless pipe ("yes") as answers of a
      person and ask again without end (CORE-42, CORE-50; AUD-023-UI006 related).
  P2  the own-settings questions: a valid PIM is asked again after a refused memory level, and an
      out-of-range PIM is refused only after the memory level is typed (CORE-42).
  P3  one answer limit, two values: a hidden prompt takes an 8,192-byte line, while --stdin
      refuses it as "longer than 8191 bytes"; the hidden prompt refuses 8,193 bytes as "longer
      than 8192 bytes" (CORE-10).
"""
import os, pty, re, select, signal, subprocess, sys, time

MHFE = os.path.abspath(sys.argv[1])
ENCRYPT_OPTIONS = ["--pim", "0", "--mem", "0", "--same-length", "no", "--new-password", "own",
                   "--repair-words", "0"]
defects = 0


def report(name, defect, detail):
    global defects
    defects += bool(defect)
    print(f"{name}: {'DEFECT' if defect else 'PASS'}: {detail}")


def plain(data):
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", data.decode("utf-8", "replace"))


class Pty:
    """A process in a pseudo-terminal, read as it writes."""

    def __init__(self, arguments, term="xterm-256color"):
        env = dict(os.environ, TERM=term)
        env.pop("NO_COLOR", None)
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execve(MHFE, [MHFE, *arguments], env)
        self.out = b""
        self.sent = 0

    def pump(self, seconds):
        end = time.time() + seconds
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    self.out += os.read(self.fd, 65536)
                except OSError:
                    return

    def wait_for(self, marker, seconds=15, since=None):
        """Whether `marker` arrives, in what was written from `since` (the last send) on."""
        start = self.sent if since is None else since
        end = time.time() + seconds
        while time.time() < end:
            if marker.encode() in self.out[start:]:
                return True
            self.pump(0.1)
        return False

    def send(self, data):
        # Beyond the 200 ms in which keys count as typed ahead.
        time.sleep(0.4)
        self.sent = len(self.out)
        view = memoryview(data)
        while view:
            written = os.write(self.fd, view[:1024])
            view = view[written:]
            self.pump(0.01)

    def running(self):
        return os.waitpid(self.pid, os.WNOHANG)[0] == 0

    def kill(self):
        if self.running():
            os.kill(self.pid, signal.SIGKILL)
            os.waitpid(self.pid, 0)


def p1_endless_pipe():
    for command in (["repair-words", "--count", "4"], ["repair"]):
        yes = subprocess.Popen(["yes"], stdout=subprocess.PIPE)
        started = time.time()
        tool = subprocess.Popen([MHFE, *command], stdin=yes.stdout, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE)
        yes.stdout.close()
        lines = 0
        while time.time() - started < 3 and tool.poll() is None:
            chunk = tool.stderr.read1(1 << 16)
            if not chunk:
                break
            lines += chunk.count(b"\n")
        still = tool.poll() is None
        tool.kill(); tool.wait(); yes.kill(); yes.wait()
        report(f"P1 yes | mhfe {' '.join(command)}", still,
               f"still running after 3 s: {still}; {lines:,} lines of messages")


def p2_settings_retry():
    tool = Pty(["encrypt"])
    ok = tool.wait_for("Which settings")
    tool.send(b"2")
    ok &= tool.wait_for("PIM: ")
    tool.send(b"1\r")
    ok &= tool.wait_for("Memory level: ")
    mark = len(tool.out)
    tool.send(b"30\r")
    tool.pump(1.5)
    after = plain(tool.out[mark:])
    tool.kill()
    asked_again = "PIM: " in after and "memory level must be" in after
    report("P2a valid PIM, level 30", asked_again or not ok,
           f"prompts reached: {ok}; the valid PIM 1 is asked again: {asked_again}")
    tool = Pty(["encrypt"])
    ok = tool.wait_for("Which settings")
    tool.send(b"2")
    ok &= tool.wait_for("PIM: ")
    mark = len(tool.out)
    tool.send(b"5000\r")
    tool.pump(1.5)
    after = plain(tool.out[mark:])
    tool.kill()
    level_first = "Memory level: " in after and "PIM must be" not in after
    report("P2b PIM 5000", level_first or not ok,
           f"prompts reached: {ok}; the memory level is asked before PIM 5000 is refused: "
           f"{level_first}")


def p3_line_limits():
    limit = 8192
    script = subprocess.run([MHFE, "encrypt", "--stdin", *ENCRYPT_OPTIONS],
                            input=b"a" * limit + b"\n", capture_output=True, timeout=60)
    script_text = plain(script.stderr).replace("\n", " ")
    script_refused = re.search(r"longer than (\d+) bytes", script_text)
    tool = Pty(["encrypt", *ENCRYPT_OPTIONS])
    ok = tool.wait_for("seed phrase")
    mark = len(tool.out)
    tool.send(b"a" * limit + b"\r")
    tool.pump(2)
    shown = plain(tool.out[mark:])
    tool.kill()
    terminal_refused = re.search(r"longer than (\d+) bytes", shown)
    tool = Pty(["encrypt", *ENCRYPT_OPTIONS])
    tool.wait_for("seed phrase")
    mark = len(tool.out)
    tool.send(b"a" * (limit + 1) + b"\r")
    tool.pump(2)
    longer = re.search(r"longer than (\d+) bytes", plain(tool.out[mark:]))
    tool.kill()
    differ = bool(script_refused) and not terminal_refused and bool(longer)
    report("P3 one answer limit", differ or not ok,
           f"--stdin, {limit:,} bytes: exit {script.returncode}, "
           f"{'refused as longer than ' + script_refused.group(1) if script_refused else 'not refused for length'}; "
           f"hidden prompt, {limit:,} bytes: "
           f"{'refused as longer than ' + terminal_refused.group(1) if terminal_refused else 'taken as a line'}; "
           f"hidden prompt, {limit + 1:,} bytes: "
           f"{'refused as longer than ' + longer.group(1) if longer else 'not refused for length'}")


p1_endless_pipe()
p2_settings_retry()
p3_line_limits()
print("DEFECT REPRODUCED" if defects else "DEFECT NOT REPRODUCED")
sys.exit(1 if defects else 0)
