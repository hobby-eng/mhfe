#!/usr/bin/env python3
"""AUD-024 harness: how `mhfe serve` and packaging/mhfe-fast-mode.py end on Ctrl+C. Serves a
one-line scratch page from a temporary folder on 127.0.0.1 with --no-browser, sends SIGINT once the
launcher says it is running, and compares exit codes and last lines. Exits 1 when they differ.

    python3 launcher-ctrl-c.py <path to mhfe> <path to packaging/mhfe-fast-mode.py>
"""
import hashlib
import os
import re
import signal
import subprocess
import sys
import tempfile
import time

mhfe, launcher = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
results = {}
with tempfile.TemporaryDirectory() as folder:
    page = b"<!doctype html><title>t</title>\n"
    with open(os.path.join(folder, "tool.html"), "wb") as file:
        file.write(page)
    with open(os.path.join(folder, "mhfe-fast-mode.sha256"), "w") as file:
        file.write(f"{hashlib.sha256(page).hexdigest()}  tool.html\n")
    for name, command in (("mhfe serve", [mhfe, "serve", "--no-browser", "tool.html"]),
                          ("mhfe-fast-mode.py", [sys.executable, launcher, "--no-browser",
                                                 "tool.html"])):
        process = subprocess.Popen(command, cwd=folder, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, env=dict(os.environ, NO_COLOR="1"))
        os.set_blocking(process.stdout.fileno(), False)
        output = b""
        deadline = time.time() + 15
        while time.time() < deadline and b"running" not in output:
            output += process.stdout.read() or b""
            time.sleep(0.1)
        process.send_signal(signal.SIGINT)
        code = process.wait(timeout=15)
        os.set_blocking(process.stdout.fileno(), True)
        output += process.stdout.read() or b""
        text = re.sub(rb"\x1b\[[0-9;?]*[A-Za-z]", b"", output).decode("utf-8", "replace")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        results[name] = (code, lines[-1] if lines else "")
        print(f"{name}: exit {code}; last line: {results[name][1]!r}")
differ = results["mhfe serve"] != results["mhfe-fast-mode.py"]
print(("FAIL: the launchers end differently on Ctrl+C" if differ
       else "PASS: both launchers end alike on Ctrl+C"))
sys.exit(1 if differ else 0)
