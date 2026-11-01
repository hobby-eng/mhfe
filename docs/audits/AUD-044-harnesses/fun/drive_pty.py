#!/usr/bin/env python3
"""AUD-044 fun probe: drives one command of the reduced-cost program at a pseudo-terminal. Public
test data only.

    python3 -I drive_pty.py '<json list of [pattern, answer]>' <program> <arguments...>

Each answer is sent once its pattern has come; the transcript, without control sequences, goes to
standard output, and the exit code follows."""
import json, os, pty, re, select, sys, time

steps = json.loads(sys.argv[1])
argv = sys.argv[2:]
pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm"
    os.environ["NO_COLOR"] = "1"
    os.execv(argv[0], argv)

text = ""
seen = 0
def pump(seconds):
    global text
    end = time.time() + seconds
    while time.time() < end:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try:
                chunk = os.read(fd, 65536).decode("utf-8", "replace")
            except OSError:
                return False
            if not chunk:
                return False
            text += chunk
    return True

alive = True
for pattern, answer in steps:
    end = time.time() + 40
    found = None
    while time.time() < end and alive:
        alive = pump(0.2)
        found = re.compile(pattern).search(text, seen)
        if found:
            break
    if not found:
        print(f"[did not reach {pattern!r}]")
        break
    seen = found.end()
    time.sleep(0.15)
    pump(0.1)
    os.write(fd, answer.encode())
while alive and pump(0.3):
    done, status = os.waitpid(pid, os.WNOHANG)
    if done:
        break
else:
    status = None
if status is None:
    try:
        _, status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        status = 0
plain = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[=>]", "", text).replace("\r", "")
print(plain)
print("[exit]", os.waitstatus_to_exitcode(status) if status is not None else "?")
