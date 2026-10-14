#!/usr/bin/env python3
"""AUD-024 secrets-native harness: how a line that cannot be an answer is refused.

`mhfe encrypt --pim 0 --mem 0` runs in a pseudo-terminal up to its first secret, the original
seed phrase, on the private screen. Three answers are typed, each in a fresh run:
  A. a phrase of 3 public words ("abandon abandon about"), which the phrase rules refuse;
  B. one invalid UTF-8 byte (0xff) and Enter;
  C. 8,200 letters "a" without Enter, more than the 8,192-byte line.
The probe reports whether the tool asked again (the prompt appears a second time and the tool is
still running) or ended, with its exit status. Public data only; no Argon2 round beyond the
startup checks runs: no phrase is ever accepted. Each run is stopped with SIGTERM at the end.

D. With --stdin, a first line that is the byte 0xff: README's exit-code table gives 2 for invalid
input; the control E, a phrase of three words, gets 2.

Exits 1 when B or C end the command instead of asking again, or D does not exit with 2 (the defect
of AUD-024), 0 otherwise.
"""
import os
import pty
import select
import signal
import subprocess
import sys
import time

PROMPT = b"Original seed phrase"


def read_for(master, seconds):
    data = b""
    end = time.time() + seconds
    while time.time() < end:
        ready, _, _ = select.select([master], [], [], 0.05)
        if ready:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            data += chunk
    return data


def run(label, answer):
    binary = sys.argv[1]
    master, slave = pty.openpty()
    env = {k: v for k, v in os.environ.items() if k not in ("NO_COLOR", "CLICOLOR_FORCE")}
    env["TERM"] = "xterm-256color"
    process = subprocess.Popen(
        [binary, "encrypt", "--pim", "0", "--mem", "0"], stdin=slave, stdout=slave,
        stderr=slave, env=env, start_new_session=True,
    )
    os.close(slave)
    seen = b""
    end = time.time() + 30
    while PROMPT not in seen and time.time() < end:
        seen += read_for(master, 0.2)
    before = seen.count(PROMPT)
    for start in range(0, len(answer), 256):
        os.write(master, answer[start:start + 256])
        seen += read_for(master, 0.02)
    seen += read_for(master, 2.0)
    status = process.poll()
    asked_again = status is None and seen.count(PROMPT) > before
    text = seen.decode("utf-8", "replace")
    error = [line.strip() for line in text.replace("\r", "\n").split("\n") if "Error" in line]
    print(f"{label}: asked again: {asked_again}; still running: {status is None}; "
          f"exit status: {status}; error lines: {error[-1:] if error else []}")
    if status is None:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=10)
    os.close(master)
    return asked_again


def script(label, line):
    env = {**os.environ, "NO_COLOR": "1"}
    run = subprocess.run([sys.argv[1], "encrypt", "--stdin", "--pim", "0", "--mem", "0"],
                         input=line, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env)
    last = run.stderr.decode("utf-8", "replace").strip().splitlines()[-1:]
    print(f"{label}: exit status {run.returncode}; last line: {last}")
    return run.returncode


def main():
    run("A. three words", b"abandon abandon about\r")
    b = run("B. invalid UTF-8", b"\xff\r")
    c = run("C. 8,200 bytes", b"a" * 8200)
    d = script("D. --stdin, 0xff", b"\xff\n")
    script("E. --stdin, three words (control)", b"abandon abandon about\n")
    failed = not b or not c or d != 2
    print("FAIL: a line that cannot be an answer ends the command, or exits as an internal error"
          if failed else "PASS: such a line is asked again, and a script gets exit code 2")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
