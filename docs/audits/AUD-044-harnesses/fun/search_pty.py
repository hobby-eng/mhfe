#!/usr/bin/env python3
"""AUD-044 fun probe: the missing-word search of `mhfe repair` at a terminal, on the reduced-cost
program, with a fingerprint that two candidates share. Public test data only.

    python3 -I search_pty.py <mhfe> "<written container>" <fingerprint>
"""
import os, pty, re, select, sys, time

program, written, fingerprint = sys.argv[1:4]
pid, fd = pty.fork()
if pid == 0:
    os.environ["TERM"] = "xterm"
    os.environ["NO_COLOR"] = "1"
    os.execv(program, [program, "repair"])

text = ""
def read_until(pattern, seconds=60):
    global text
    end = time.time() + seconds
    while time.time() < end:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(fd, 65536).decode("utf-8", "replace")
            except OSError:
                return False
            text += chunk
            if re.search(pattern, text[-4000:]):
                return True
    return False

def send(line):
    os.write(fd, line.encode())

steps = [
    ("Container", written + "\r"),
    ("Repair words", "\r"),
    ("what do you know", "\r"),
    ("fingerprint: ", fingerprint + "\r"),
    ("passphrase used", "\r"),
]
for pattern, answer in steps:
    if not read_until(pattern):
        print("did not reach", pattern)
        break
    time.sleep(0.3)
    send(answer)
read_until("Use the found container phrase", 120)
time.sleep(0.5)
plain = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\r", "", text)
start = plain.rfind("Found container phrase")
print(plain[start:start + 1600] if start >= 0 else plain[-1500:])
send("\x03")
