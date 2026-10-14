#!/usr/bin/env python3
"""AUD-024 verifier: where a line read from standard input is left after the program wiped its copy.

Runs the probe through a pipe (as with --stdin) and through a pseudo-terminal in raw mode (as at a
hidden prompt), the text pasted in one write or typed one key at a time. Exits 1 when the std
paths leave a whole copy inside std's buffer, 0 otherwise, 2 when the probe could not run."""
import os, pty, subprocess, sys, time, tty

probe = sys.argv[1]
TEXT = b"public test password"
REVERSED = TEXT[::-1].decode()
TAIL_REVERSED = b"t password"[::-1].decode()
found_in_std = False

def show(out):
    global found_in_std
    print(out, end="")
    for line in out.splitlines():
        if line.strip().startswith("whole-text copies") and not line.rstrip().endswith("inside std's buffer: 0"):
            found_in_std = True

print("== pipe (as --stdin): 'public test password\\nsecond line\\n' in one write")
for mode in ["bytes", "line", "descriptor"]:
    run = subprocess.run([probe, mode, REVERSED, TAIL_REVERSED], input=TEXT + b"\nsecond line\n",
                         capture_output=True)
    if run.returncode != 0:
        print(run.stderr.decode()); sys.exit(2)
    show(run.stdout.decode())

def on_pty(mode, typed):
    leader, follower = pty.openpty()
    tty.setraw(follower)  # no echo, no line mode, as a hidden prompt switches the terminal
    child = subprocess.Popen([probe, mode, REVERSED, TAIL_REVERSED], stdin=follower,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.close(follower)
    time.sleep(0.3)
    if typed:
        for byte in TEXT + b"\r":
            os.write(leader, bytes([byte]))
            time.sleep(0.03)
    else:
        os.write(leader, TEXT + b"\r")
    out, err = child.communicate(timeout=60)
    os.close(leader)
    if child.returncode != 0:
        print(err.decode()); sys.exit(2)
    show(out.decode())

for typed in [False, True]:
    print(f"== pseudo-terminal in raw mode, {'typed one key at a time' if typed else 'pasted in one write'}, then Enter (CR)")
    for mode in ["bytes", "descriptor"]:
        on_pty(mode, typed)

if found_in_std:
    print("FAIL: a whole copy of the line is left inside the standard library's stdin buffer after the program wiped its own")
    sys.exit(1)
print("PASS: no whole copy left in std's buffer")
