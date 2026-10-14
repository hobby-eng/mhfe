#!/usr/bin/env python3
"""AUD-024 secrets-native harness: write errors on standard error.

Part 1: `mhfe password` and `mhfe repair-words --stdin --count 4` (public phrase: 23 x abandon,
art) with standard error on /dev/full (ENOSPC). Expected: a documented exit code (README's table:
0 to 5 or 130), not an abort (SIGABRT, 134).

Part 2: a write error on standard error at a terminal, while the private screen is shown.

`mhfe encrypt --pim 0 --mem 0` runs in a pseudo-terminal. Standard input is the terminal opened
blocking; standard output and standard error are the same terminal opened a second time with
O_NONBLOCK, a separate open file description (as a terminal left non-blocking by another program
would be). The probe waits for the private screen's prompt for the original seed phrase, stops
reading the terminal and types "ab" and two Backspaces again and again: every key redraws the
word hint, so the terminal's output buffer fills and a write returns EAGAIN. The probe then reads
everything and reports how the tool ended and whether it left the alternate screen. Public data
only: the letters "ab". No Argon2 round beyond the startup checks runs: the tool never gets a
phrase.
"""
import fcntl
import os
import pty
import select
import signal
import subprocess
import sys
import termios
import time

ENTER_ALTERNATE = b"\x1b[?1049h"
LEAVE_ALTERNATE = b"\x1b[?1049l"


def read_available(master, timeout):
    data = b""
    end = time.time() + timeout
    while time.time() < end:
        ready, _, _ = select.select([master], [], [], 0.05)
        if not ready:
            continue
        try:
            chunk = os.read(master, 65536)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
    return data


def full_device(binary):
    """Part 1; returns the commands that aborted."""
    zero24 = ("abandon " * 23 + "art\n").encode()
    env = {**os.environ, "NO_COLOR": "1"}
    aborted = []
    for args, stdin in ((["password"], b""), (["repair-words", "--stdin", "--count", "4"], zero24)):
        with open("/dev/full", "wb") as full:
            run = subprocess.run([binary, *args], input=stdin, stdout=subprocess.DEVNULL,
                                 stderr=full, env=env)
        print(f"{' '.join(args)} 2>/dev/full: exit status {run.returncode}")
        if run.returncode in (-signal.SIGABRT, 134):
            aborted.append(" ".join(args))
    return aborted


def private_screen(binary):
    """Part 2; returns whether the tool aborted and whether it left the alternate screen."""
    master, slave = pty.openpty()
    name = os.ttyname(slave)
    output = os.open(name, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)

    def child_setup():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    env = {key: value for key, value in os.environ.items() if key not in ("NO_COLOR", "CLICOLOR_FORCE")}
    env["TERM"] = "xterm-256color"
    process = subprocess.Popen(
        [binary, "encrypt", "--pim", "0", "--mem", "0"],
        stdin=slave, stdout=output, stderr=output, env=env, preexec_fn=child_setup,
        close_fds=True,
    )
    os.close(slave)
    os.close(output)
    seen = b""
    end = time.time() + 30
    while b"Original seed phrase" not in seen and time.time() < end and process.poll() is None:
        seen += read_available(master, 0.2)
    print(f"prompt reached: {b'Original seed phrase' in seen}")
    print(f"alternate screen entered before the prompt: {ENTER_ALTERNATE in seen}")
    # Stop reading; type keys whose echo and hints fill the terminal's output buffer.
    sent = 0
    for _ in range(4000):
        if process.poll() is not None:
            break
        try:
            os.write(master, b"ab\x7f\x7f")
            sent += 4
        except OSError:
            break
        time.sleep(0.002)
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        pass
    rest = read_available(master, 3)
    seen += rest
    code = process.poll()
    if code is None:
        print("the tool is still running: stopping it (no write error reached)")
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=10)
        code = process.returncode
    after_last_enter = seen[seen.rfind(ENTER_ALTERNATE):] if ENTER_ALTERNATE in seen else b""
    print(f"keys typed: {sent} bytes")
    print(f"exit status: {code} ({'SIGABRT' if code == -signal.SIGABRT else 'not SIGABRT'})")
    print(f"'failed printing to stderr' in the output: {b'failed printing to stderr' in seen}")
    print(f"alternate screen left after it was entered: {LEAVE_ALTERNATE in after_last_enter}")
    print(f"bytes read from the terminal in all: {len(seen)}")
    # The terminal settings the tool left: echo and line mode, as a shell needs them.
    again = os.open(name, os.O_RDWR | os.O_NOCTTY)
    lflag = termios.tcgetattr(again)[3]
    os.close(again)
    print(f"terminal left with echo: {bool(lflag & termios.ECHO)}, line mode: {bool(lflag & termios.ICANON)}")
    return code == -signal.SIGABRT, LEAVE_ALTERNATE in after_last_enter


def main():
    binary = sys.argv[1]
    aborted = full_device(binary)
    pty_aborted, left = private_screen(binary)
    failed = bool(aborted) or pty_aborted or not left
    if failed:
        print(f"FAIL: aborted on a full standard error: {aborted}; aborted at the terminal: "
              f"{pty_aborted}; alternate screen left: {left}")
    else:
        print("PASS: write errors on standard error end the tool with a documented exit code")
    sys.exit(1 if failed else 0)
    os.close(master)


if __name__ == "__main__":
    main()
