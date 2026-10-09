#!/usr/bin/env python3
"""Small public-data native boundary probes for AUD-016; no Argon2 operation runs."""

import argparse
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import struct
import subprocess
import tempfile
import termios
import time

ROOT = Path(__file__).resolve().parents[4]
FIXTURE = ROOT / "tests/fixtures/suite3-vectors/zero-12.json"
CONTAINER = json.loads(FIXTURE.read_text())["container"].encode()
PUBLIC_PHRASE = ("abandon " * 11 + "about").encode()
MEMORY_LIMIT = 512 * 1024 * 1024
WAIT_SECONDS = 8


def limits():
    resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT, MEMORY_LIMIT))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class Terminal:
    def __init__(self, program, arguments, term="xterm-256color", memlock=None):
        self.master, slave = os.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 80, 0, 0))
        self.original = termios.tcgetattr(slave)
        self.slave = slave
        environment = os.environ.copy()
        environment.update(TERM=term, CLICOLOR_FORCE="1")
        environment.pop("NO_COLOR", None)

        def prepare():
            limits()
            if memlock is not None:
                resource.setrlimit(resource.RLIMIT_MEMLOCK, (memlock, memlock))
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

        self.process = subprocess.Popen(
            [program, *arguments], stdin=slave, stdout=slave, stderr=slave,
            env=environment, preexec_fn=prepare, cwd=ROOT,
        )
        self.output = bytearray()

    def read(self, seconds=0.15):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            ready, _, _ = select.select([self.master], [], [], max(0, until - time.monotonic()))
            if not ready:
                break
            try:
                block = os.read(self.master, 65536)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not block:
                break
            self.output.extend(block)

    def until(self, wanted):
        began = len(self.output)
        deadline = time.monotonic() + WAIT_SECONDS
        while time.monotonic() < deadline:
            self.read()
            plain = re.sub(rb"\x1b\[[0-9;]*m", b"", bytes(self.output[began:]))
            if wanted in plain:
                return
            if self.process.poll() is not None:
                break
        raise AssertionError(f"Prompt did not arrive: {wanted!r}; output tail {bytes(self.output[-800:])!r}")

    def send(self, text):
        os.write(self.master, text)

    def finish(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise AssertionError("Cancellation exceeded three seconds")
        self.read()
        restored = termios.tcgetattr(self.slave) == self.original
        os.close(self.master)
        os.close(self.slave)
        return restored


def path_controls(program):
    # No page or checksum file is needed: the missing checksum error prints the parent path.
    with tempfile.TemporaryDirectory(prefix="aud016-native-") as temporary:
        directory = Path(temporary) / "x\x1b]0;AUD016-PATH\x07y"
        directory.mkdir()
        terminal = Terminal(program, ["serve", "--no-browser", str(directory / "tool.html")])
        try:
            terminal.process.wait(timeout=WAIT_SECONDS)
            terminal.read()
        finally:
            restored = terminal.finish()
        raw = bytes(terminal.output)
        sequence = b"\x1b]0;AUD016-PATH\x07"
        print(json.dumps({
            "case": "path-controls", "exitCode": terminal.process.returncode,
            "rawTerminalSequenceEmitted": sequence in raw,
            "terminalRestored": restored,
            "outputEscaped": raw.decode(errors="replace").replace(temporary, "/tmp/aud016-native-TEMP"),
        }, ensure_ascii=True))
        assert sequence not in raw, "AUD-015-SEC002 remains reachable through the file parent path"


def fingerprint_redaction(program):
    result = subprocess.run(
        [program, "check", "--stdin", "--fingerprint", "--pim", "0"],
        input=CONTAINER + b"\nAUD016 public synthetic password\n" + PUBLIC_PHRASE + b"\n",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=limits,
        env={**os.environ, "NO_COLOR": "1"}, timeout=WAIT_SECONDS, cwd=ROOT,
    )
    # The public phrase may wrap in the error; join only whitespace for the containment check.
    flattened = b" ".join(result.stderr.split())
    print(json.dumps({
        "case": "fingerprint-redaction", "exitCode": result.returncode,
        "publicPhraseEmittedInError": PUBLIC_PHRASE in flattened,
        "stdoutBytes": len(result.stdout),
        "stderrEscaped": result.stderr.decode(errors="replace"),
    }, ensure_ascii=True))
    assert PUBLIC_PHRASE not in flattened, "The invalid public field error repeats an entire public seed phrase"


def dumb_container(program):
    terminal = Terminal(program, ["check", "--fingerprint", "--pim", "0"], term="dumb")
    try:
        terminal.until(b"Container, 24 words")
        began = len(terminal.output)
        terminal.send(CONTAINER + b"\n")
        terminal.until(b"Container password (hidden): ")
    finally:
        restored = terminal.finish()
    raw = bytes(terminal.output)
    fragment = raw[began:]
    # The editor emits each input character with hint rows between them. Remove only those
    # rows and its cursor codes, retaining the input characters and normal result lines.
    rendered = re.sub(rb"\r\r?\n  \x1b\[90m[^\r\n]*?\x1b\[0m", b"", fragment)
    rendered = re.sub(rb"\x1b\[[0-?]*[ -/]*[@-~]", b"", rendered).replace(b" \x08", b"")
    print(json.dumps({
        "case": "dumb-container", "exitCode": terminal.process.returncode,
        "containerEchoed": CONTAINER in rendered,
        "alternateScreenEntered": b"\x1b[?1049h" in raw,
        "terminalRestored": restored,
        "renderedInputEscaped": rendered.decode(errors="replace"),
    }, ensure_ascii=True))
    assert CONTAINER not in rendered, "A container is echoed onto the main screen without a private screen"


def unicode_cursor(program):
    terminal = Terminal(program, ["check", "--fingerprint", "--pim", "0"])
    try:
        terminal.until(b"Container, 24 words")
        terminal.send(CONTAINER + b"\r")
        terminal.until(b"Container password: ")
        began = len(terminal.output)
        terminal.send("界a".encode())
        terminal.read()
        terminal.send(b"\x7f")
        terminal.read()
        fragment = bytes(terminal.output[began:])
        columns = [int(value) for value in re.findall(rb"\x1b\[(\d+)G", fragment)]
    finally:
        restored = terminal.finish()
    # U+754C has display width two in ordinary xterm-compatible terminals. Deleting only 'a'
    # must retain those two cells after the ASCII prompt, then use 1-based cursor positioning.
    expected = len("Container password: ") + 2 + 1
    observed = columns[-1] if columns else None
    print(json.dumps({
        "case": "unicode-cursor", "exitCode": terminal.process.returncode,
        "expectedColumnAfterDeletingAscii": expected,
        "observedCursorColumn": observed, "terminalRestored": restored,
        "fragmentEscaped": fragment.decode(errors="replace"),
    }, ensure_ascii=True))
    assert observed == expected, "Allowed wide password characters receive one-column cursor accounting"


def low_memlock(program):
    lock_limit = 4096
    probe_path = ROOT / "docs/audits/AUD-016-evidence/native-lock-claim"

    def prepare():
        limits()
        resource.setrlimit(resource.RLIMIT_MEMLOCK, (lock_limit, lock_limit))

    result = subprocess.run([str(probe_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            preexec_fn=prepare, timeout=WAIT_SECONDS, cwd=ROOT)
    print(json.dumps({"case": "low-memlock-library", "rlimitMemlockBytes": lock_limit,
                      "probeSha256": hashlib.sha256(probe_path.read_bytes()).hexdigest(),
                      "exitCode": result.returncode,
                      "stdout": result.stdout.decode(errors="replace"),
                      "stderr": result.stderr.decode(errors="replace")}, ensure_ascii=True))
    terminal = Terminal(program, ["encrypt", "--pim", "0", "--new-password", "own"],
                        memlock=lock_limit)
    try:
        terminal.until(b"Original seed phrase: ")
        terminal.send(b"abandon")
        terminal.read()
        status = Path(f"/proc/{terminal.process.pid}/status").read_text()
        vm_locked_kib = int(re.search(r"^VmLck:\s+(\d+) kB$", status, re.M).group(1))
    finally:
        restored = terminal.finish()
    plain = re.sub(rb"\x1b\[[0-9;]*m", b"", bytes(terminal.output))
    claimed = b"kept in locked memory, out of swap" in plain
    print(json.dumps({"case": "low-memlock-cli", "rlimitMemlockBytes": lock_limit,
                      "claimsSecretsLocked": claimed, "vmLockedKiBWhileInputContainsPublicWord": vm_locked_kib,
                      "exitCode": terminal.process.returncode, "terminalRestored": restored}, ensure_ascii=True))
    assert not claimed or vm_locked_kib > 0, "The CLI claims locked secrets with zero locked pages while typing"
    assert result.returncode == 0, "The actual CLI-sized library buffer cannot be locked although LockProbe passes"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("case", choices=["path-controls", "fingerprint-redaction", "dumb-container", "unicode-cursor", "low-memlock"])
    parser.add_argument("program", nargs="?", default="target/release/mhfe")
    arguments = parser.parse_args()
    program = str((ROOT / arguments.program).resolve())
    print(json.dumps({"binarySha256": hashlib.sha256(Path(program).read_bytes()).hexdigest(),
                      "fixtureSha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest()}))
    cases = {"path-controls": path_controls, "fingerprint-redaction": fingerprint_redaction,
             "dumb-container": dumb_container, "unicode-cursor": unicode_cursor, "low-memlock": low_memlock}
    cases[arguments.case](program)


if __name__ == "__main__":
    main()
