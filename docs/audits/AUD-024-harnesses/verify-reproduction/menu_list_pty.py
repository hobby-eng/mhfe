#!/usr/bin/env python3
"""AUD-024 harness (verify-reproduction), commit b6fca69: a write error on standard error while a list is
shown, in the start menu (`mhfe` without arguments at a terminal), which reads keys with the
terminal switched to single keys without echo (hidden_input::with_keys).

Standard input is the pseudo-terminal opened blocking; standard output and error are the same
terminal opened a second time with O_NONBLOCK, as in stderr_write_errors.py. At the menu the probe
stops reading and sends the Down arrow again and again: every key redraws the list, so the output
buffer fills and a write returns EAGAIN. It reports the exit status and whether the terminal was
left with echo and line mode. No command is chosen; nothing secret is typed; no Argon2 runs beyond
the startup checks. Exits 1 when the tool ends with SIGABRT or leaves the terminal without echo or
line mode, 0 otherwise.

    python3 -B docs/audits/AUD-024-harnesses/verify-reproduction/menu_list_pty.py <mhfe>
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


def main():
    binary = sys.argv[1]
    master, slave = pty.openpty()
    name = os.ttyname(slave)
    output = os.open(name, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)

    def child_setup():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    env = {k: v for k, v in os.environ.items() if k not in ("NO_COLOR", "CLICOLOR_FORCE")}
    env["TERM"] = "xterm-256color"
    process = subprocess.Popen([binary], stdin=slave, stdout=output, stderr=output, env=env,
                               preexec_fn=child_setup, close_fds=True)
    os.close(output)
    seen = b""
    end = time.time() + 30
    while b"Esc quits" not in seen and time.time() < end and process.poll() is None:
        seen += read_available(master, 0.2)
    print(f"menu shown: {b'Esc quits' in seen}")
    time.sleep(0.4)  # past TYPED_AHEAD, so that the keys count
    sent = 0
    for _ in range(4000):
        if process.poll() is not None:
            break
        try:
            os.write(master, b"\x1b[B")
            sent += 3
        except OSError:
            break
        time.sleep(0.002)
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        pass
    seen += read_available(master, 3)
    code = process.poll()
    if code is None:
        print("still running: stopped with SIGTERM (no write error reached)")
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=10)
        code = process.returncode
    lflag = termios.tcgetattr(slave)[3]
    os.close(slave)
    os.close(master)
    print(f"keys sent: {sent} bytes")
    print(f"exit status: {code} ({'SIGABRT' if code == -signal.SIGABRT else 'not SIGABRT'})")
    print(f"terminal left with echo: {bool(lflag & termios.ECHO)}, "
          f"line mode: {bool(lflag & termios.ICANON)}")
    failed = code == -signal.SIGABRT or not (lflag & termios.ECHO) or not (lflag & termios.ICANON)
    if failed:
        print("FAIL: a write error on standard error at the menu aborted the tool or left the "
              "terminal without echo or line mode")
    else:
        print("PASS: the tool ended without an abort and left the terminal as it found it")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
