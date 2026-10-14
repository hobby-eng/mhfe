#!/usr/bin/env python3
"""AUD-024 probe: drives `mhfe repair` at a pseudo-terminal with the public test phrase, one word
typed as ?, and its two repair words, and reports whether the repaired container is drawn in a
frame. Exits 1 when the frame is drawn (the CORE-36 breach), 0 when it is not, 2 on a probe fault."""
import os, pty, select, sys, time

sys.excepthook = lambda kind, value, trace: (print(f"--- probe fault: {kind.__name__}: {value}"), os._exit(2))

BINARY = sys.argv[1]
PHRASE = ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
          "abandon about")
DAMAGED = PHRASE.replace("about", "?")
CARD = "access adapt"

def read_for(fd, seconds):
    out = b""
    end = time.time() + seconds
    while time.time() < end:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
    return out

pid, fd = pty.fork()
if pid == 0:
    env = dict(os.environ, TERM="xterm-256color", NO_COLOR="1", COLUMNS="100", LINES="40")
    env.pop("CI", None)
    os.execve(BINARY, [BINARY, "repair"], env)
transcript = read_for(fd, 2.0)
steps = [DAMAGED, CARD, "", "", "", ""]
for step in steps:
    os.write(fd, step.encode() + b"\r")
    transcript += read_for(fd, 1.5)
os.write(fd, b"\x03")
transcript += read_for(fd, 1.0)
try:
    _, status = os.waitpid(pid, 0)
except ChildProcessError:
    status = None
text = transcript.decode("utf-8", "replace")
sys.stdout.write(text.replace("\x1b", "<ESC>"))
print("\n--- exit status:", status)
framed = [line for line in text.splitlines() if "┌" in line or "└" in line or line.lstrip("\x1b[0123456789;?hlHJK").startswith("│")]
print("--- frame lines found:", len(framed))
for line in framed:
    print(repr(line))
if "Repaired container" not in text:
    print("--- probe fault: the run never showed the repaired container")
    sys.exit(2)
sys.exit(1 if framed else 0)
