#!/usr/bin/env python3
"""Runs a command in a pseudo-terminal with TERM from the first argument and prints the bytes it
writes, the alternate-screen switches among them. Probe of audit AUD-044."""
import os, pty, re, select, sys, time
term, keys, command = sys.argv[1], sys.argv[2].encode().decode("unicode_escape").encode("latin-1"), sys.argv[3:]
pid, fd = pty.fork()
if pid == 0:
    os.environ.update({"TERM": term, "NO_COLOR": "1"})
    os.execv(command[0], command)
output = b""
end = time.time() + 6
sent = False
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.3)
    if r:
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        output += data
    elif not sent and output:
        os.write(fd, keys)
        sent = True
_, status = os.waitpid(pid, os.WNOHANG)
print("alternate screen entered:", b"\x1b[?1049h" in output)
text = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", output.decode("utf-8", "replace")).replace("\r", "")
print(text[:1200])
