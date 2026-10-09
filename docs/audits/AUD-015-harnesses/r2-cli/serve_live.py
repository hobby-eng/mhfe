"""AUD-015 R2 probe: the rules of `mhfe serve` (SECURITY.md, "The fast-mode launcher") on the built
tool, over its real localhost socket.

    python3 docs/audits/AUD-015-harnesses/r2-cli/serve_live.py [path/to/mhfe]

A synthetic page and its checksum file are written to a temporary folder; `mhfe serve --no-browser`
serves it in a pseudo-terminal and prints its address. The probe then checks, as a client on
127.0.0.1 only:

- the listener is bound to 127.0.0.1 (/proc/net/tcp), not to every address;
- GET / with the exact Host header gets 200, the page byte for byte and the seven security headers;
  HEAD gets the headers and the length without the body;
- another Host (localhost:<port>, the port alone, a second Host header, none) gets 403;
- another path gets 404 and another method 405; a request head over 16 KiB gets 400;
- with 16 connections held open and idle, a 17th is closed at once without an answer, and once the
  idle ones reach their 10-second deadline the page is served again.

Ctrl+C then ends the server. Exit 0 when every rule holds, 1 otherwise. No secret is involved.
"""

import hashlib
import re
import socket
import sys
import tempfile
import time
from pathlib import Path

from pty_session import Session, program

HEADERS = [
    b"Cross-Origin-Opener-Policy: same-origin",
    b"Cross-Origin-Embedder-Policy: require-corp",
    b"Content-Security-Policy: frame-ancestors 'none'",
    b"X-Frame-Options: DENY",
    b"X-Content-Type-Options: nosniff",
    b"Referrer-Policy: no-referrer",
    b"Cache-Control: no-store",
]
PAGE = b"<!doctype html><title>AUD-015 synthetic page</title><p>public</p>"


def ask(port, request, timeout=5):
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as connection:
        connection.sendall(request)
        answer = b""
        while True:
            try:
                part = connection.recv(65536)
            except socket.timeout:
                break
            except ConnectionResetError:
                # The server closed with request bytes still unread: the kernel resets the
                # connection, which may drop an answer already sent.
                return answer + b"<reset>"
            if not part:
                break
            answer += part
    return answer


def bound_to_loopback_only(port):
    hex_port = f"{port:04X}"
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
        fields = line.split()
        local, state = fields[1], fields[3]
        if local.endswith(":" + hex_port) and state == "0A":  # LISTEN
            return local.split(":")[0] == "0100007F"
    return None


def main():
    tool = program(sys.argv)
    results = []

    def check(label, holds):
        results.append(holds)
        print(f"{'PASS' if holds else 'FAIL'}: {label}")

    with tempfile.TemporaryDirectory(prefix="aud015-r2-serve-live-") as folder:
        folder = Path(folder)
        (folder / "tool.html").write_bytes(PAGE)
        digest = hashlib.sha256(PAGE).hexdigest().encode()
        (folder / "mhfe-fast-mode.sha256").write_bytes(digest + b"  tool.html\n")
        session = Session(tool, ["serve", "--no-browser", str(folder / "tool.html")], colour=False)
        try:
            session.wait_for(b"Fast mode is running.")
            port = int(re.search(rb"http://127\.0\.0\.1:(\d+)/", session.output).group(1))
            host = f"127.0.0.1:{port}".encode()
            check("listening on 127.0.0.1 only", bound_to_loopback_only(port) is True)

            answer = ask(port, b"GET / HTTP/1.1\r\nHost: " + host + b"\r\n\r\n")
            head, _, body = answer.partition(b"\r\n\r\n")
            check("GET / with the exact Host: 200", head.startswith(b"HTTP/1.1 200 OK"))
            check("GET /: the page byte for byte", body == PAGE)
            check("GET /: every security header", all(h in head for h in HEADERS))
            answer = ask(port, b"HEAD / HTTP/1.1\r\nHost: " + host + b"\r\n\r\n")
            check("HEAD /: headers and length, no body",
                  answer.startswith(b"HTTP/1.1 200 OK")
                  and f"Content-Length: {len(PAGE)}".encode() in answer
                  and answer.endswith(b"\r\n\r\n"))
            for label, hosts in [
                ("Host localhost:<port>", [f"localhost:{port}".encode()]),
                ("Host 127.0.0.1 without the port", [b"127.0.0.1"]),
                ("two Host headers", [host, host]),
                ("no Host header", []),
            ]:
                request = b"GET / HTTP/1.1\r\n" + b"".join(b"Host: " + h + b"\r\n" for h in hosts)
                answer = ask(port, request + b"\r\n")
                check(f"{label}: 403", answer.startswith(b"HTTP/1.1 403"))
            answer = ask(port, b"GET /tool.html HTTP/1.1\r\nHost: " + host + b"\r\n\r\n")
            check("another path: 404", answer.startswith(b"HTTP/1.1 404"))
            answer = ask(port, b"POST / HTTP/1.1\r\nHost: " + host + b"\r\nContent-Length: 1\r\n\r\nx")
            check("POST: 405", answer.startswith(b"HTTP/1.1 405"))
            answer = ask(port, b"GET / HTTP/1.1\r\nHost: " + host + b"\r\n"
                         + b"X-Filler: " + b"a" * 17000 + b"\r\n\r\n")
            check("a request head over 16 KiB: 400, or reset without a page",
                  answer.startswith(b"HTTP/1.1 400") or answer == b"<reset>")

            idle = [socket.create_connection(("127.0.0.1", port), timeout=5) for _ in range(16)]
            time.sleep(0.5)
            started = time.monotonic()
            answer = ask(port, b"GET / HTTP/1.1\r\nHost: " + host + b"\r\n\r\n", timeout=3)
            check("a 17th connection beside 16 idle ones: closed without an answer",
                  answer == b"" and time.monotonic() - started < 2.5)
            time.sleep(11)
            answer = ask(port, b"GET / HTTP/1.1\r\nHost: " + host + b"\r\n\r\n")
            check("after the idle connections' 10-second deadline: served again",
                  answer.startswith(b"HTTP/1.1 200 OK"))
            for connection in idle:
                connection.close()
            check("nothing about the requests was logged", b"GET" not in session.output)
        finally:
            code, _ = session.finish()
    print(f"server exit code after Ctrl+C: {code}")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
