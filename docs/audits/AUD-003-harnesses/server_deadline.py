"""Check the documented total response deadline with an 8 MiB synthetic page and one client."""

import hashlib
from pathlib import Path
import re
import select
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[3]
FOLDER = ROOT / "docs/audits/AUD-003-evidence/server-deadline"
FOLDER.mkdir(exist_ok=True)
page = b"<!doctype html><!--" + b"x" * (8 * 1024 * 1024) + b"-->"
(FOLDER / "page.html").write_bytes(page)
(FOLDER / "mhfe-fast-mode.sha256").write_text(hashlib.sha256(page).hexdigest() + "  page.html\n")
process = subprocess.Popen(
    [str(ROOT / "target/debug/mhfe"), "serve", str(FOLDER / "page.html"), "--no-browser"],
    cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
)
connection = None


def threads():
    status = Path(f"/proc/{process.pid}/status").read_text()
    return int(re.search(r"^Threads:\s+(\d+)", status, re.M)[1])


try:
    output = bytearray()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if select.select([process.stderr], [], [], 0.1)[0]:
            output.extend(process.stderr.read1(4096))
            match = re.search(rb"http://127\.0\.0\.1:(\d+)", output)
            if match:
                port = int(match[1])
                break
    else:
        raise AssertionError(repr(output))
    baseline = threads()
    connection = socket.socket()
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    connection.settimeout(3)
    connection.connect(("127.0.0.1", port))
    connection.sendall(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode())
    # Do not consume the answer: the documented ten-second total deadline should close it.
    started = time.monotonic()
    time.sleep(13)
    print(f"Elapsed: {time.monotonic() - started:.2f} s; baseline threads: {baseline}; now: {threads()}")
    print("An extra answer thread after 13 s means the documented 10 s total response deadline is absent.")
    assert threads() == baseline, "The answer thread outlived the total response deadline"
finally:
    if connection is not None:
        connection.close()
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
