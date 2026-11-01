#!/usr/bin/env python3
"""Opens a program's start menu in a pseudo-terminal and prints its screen. Probe of AUD-044."""
import os, pty, re, select, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.environ.update({"TERM": "xterm", "NO_COLOR": "1", "COLUMNS": "100", "LINES": "40"})
    os.execv(sys.argv[1], [sys.argv[1]])
output = b""
end = time.time() + 3
sent = False
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        output += data
    elif not sent and output:
        os.write(fd, b"\x1b")
        sent = True
try:
    os.close(fd)
except OSError:
    pass
text = output.decode("utf-8", "replace")
text = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", text)
print(text.replace("\r", ""))
