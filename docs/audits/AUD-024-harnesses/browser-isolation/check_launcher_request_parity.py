"""AUD-024 browser-isolation check: the Python fast-mode launcher answers every request head as
mhfe serve does, as SECURITY.md ("The fast-mode launcher") and the launcher's docstring say, and
both accept a Host header only when it is exactly 127.0.0.1:<port>. Both launchers serve a public
test page with --no-browser; each case sends one raw request to each and compares the status lines.
Exits 1 when they differ, or when either accepts a Host header that is not exact.

    MHFE=<mhfe built from the snapshot> python3 docs/audits/AUD-024-harnesses/browser-isolation/check_launcher_request_parity.py
"""
import hashlib
import os
import re
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
# Made absolute here, as each launcher runs in a folder of its own.
MHFE = os.path.abspath(os.environ.get("MHFE", os.path.join(ROOT, "target", "release", "mhfe")))
LAUNCHER = os.path.join(ROOT, "packaging", "mhfe-fast-mode.py")


def start(command, folder):
    process = subprocess.Popen(command, cwd=folder, stderr=subprocess.PIPE,
                               stdout=subprocess.DEVNULL, env=dict(os.environ, NO_COLOR="1"))
    deadline = time.time() + 10
    text = b""
    while time.time() < deadline:
        text += process.stderr.read1(4096)
        match = re.search(rb"127\.0\.0\.1:(\d+)/", text)
        if match:
            return process, int(match.group(1))
    process.kill()
    raise RuntimeError("no address: " + text.decode(errors="replace"))


def status(port, raw):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        connection.sendall(raw)
        answer = b""
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            answer += chunk
    return answer.split(b"\r\n", 1)[0].decode()


CASES = {
    "control: the exact Host": (b"GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n", True),
    "a Host value ending in U+001F": (b"GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\x1f\r\n\r\n", False),
    "a Host field name led by U+001C": (b"GET / HTTP/1.1\r\n\x1cHost: 127.0.0.1:%d\r\n\r\n", False),
    "a request line ending in two CR": (b"GET / HTTP/1.1\r\r\nHost: 127.0.0.1:%d\r\n\r\n", None),
    "a UTF-8 header value": ("GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-Name: é\r\n\r\n".encode(), None),
    "a bare-LF end before a CRLF end": (b"GET / HTTP/1.1\nHost: 127.0.0.1:%d\n\nHost: x\r\n\r\n", None),
}


def main():
    failed = False
    with tempfile.TemporaryDirectory() as folder:
        page = b"<!doctype html><title>tool</title>"
        with open(os.path.join(folder, "tool.html"), "wb") as file:
            file.write(page)
        with open(os.path.join(folder, "mhfe-fast-mode.sha256"), "w") as file:
            file.write(hashlib.sha256(page).hexdigest() + "  tool.html\n")
        rust, rust_port = start([MHFE, "serve", "--no-browser", "tool.html"], folder)
        python, python_port = start([sys.executable, LAUNCHER, "--no-browser", "tool.html"], folder)
        try:
            for name, (request, served) in CASES.items():
                answers = (status(rust_port, request % rust_port), status(python_port, request % python_port))
                same = answers[0] == answers[1]
                exact = served is None or all((answer.endswith("200 OK")) == served for answer in answers)
                ok = same and exact
                failed = failed or not ok
                print("%s %-34s mhfe serve: %-28s python: %s" % (
                    "ok  " if ok else "FAIL", name, answers[0], answers[1]))
        finally:
            for process in (rust, python):
                process.terminate()
                process.wait(timeout=10)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
