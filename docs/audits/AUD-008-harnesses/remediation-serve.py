#!/usr/bin/env python3
"""Verify the real CLI still serves a public page to concurrent localhost clients."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-008-evidence"
PAGE = b"<!doctype html><title>Public AUD-008 localhost fixture</title>"
CLIENTS = 4
TIMEOUT = 10


def main():
    with tempfile.TemporaryDirectory(prefix="remediation-serve-", dir=EVIDENCE) as folder:
        directory = Path(folder)
        (directory / "public.html").write_bytes(PAGE)
        (directory / "mhfe-fast-mode.sha256").write_text(
            hashlib.sha256(PAGE).hexdigest() + "  public.html\n"
        )
        child = subprocess.Popen(
            [str(ROOT / "target/debug/mhfe"), "serve", "--no-browser", str(directory / "public.html")],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=dict(os.environ, NO_COLOR="1"),
        )
        try:
            selector = selectors.DefaultSelector()
            selector.register(child.stdout, selectors.EVENT_READ)
            output = b""
            deadline = time.monotonic() + TIMEOUT
            match = None
            while time.monotonic() < deadline and match is None:
                for key, _ in selector.select(max(0, deadline - time.monotonic())):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        raise AssertionError("serve stopped before publishing its address")
                    output += chunk
                    match = re.search(rb"http://127\.0\.0\.1:(\d+)/", output)
            selector.close()
            assert match is not None, "serve did not publish a localhost address"
            port = int(match[1])

            def request(_):
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=TIMEOUT)
                try:
                    connection.request("GET", "/")
                    response = connection.getresponse()
                    assert response.status == 200
                    assert response.read() == PAGE
                    assert response.getheader("Cross-Origin-Opener-Policy") == "same-origin"
                    assert response.getheader("Cross-Origin-Embedder-Policy") == "require-corp"
                    assert response.getheader("Cache-Control") == "no-store"
                finally:
                    connection.close()

            with ThreadPoolExecutor(max_workers=CLIENTS) as pool:
                list(pool.map(request, range(CLIENTS)))
            print(f"PASS: real serve CLI answers {CLIENTS} concurrent localhost clients with isolation headers")
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
                try:
                    child.wait(timeout=TIMEOUT)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            child.stdout.close()


if __name__ == "__main__":
    main()
