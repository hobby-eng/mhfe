"""`mhfe serve`, the fast mode.

It starts with its title and shows the page's digest on a line of its own, within 78 columns; the
address stays on the screen when the browser opener fails; and on Linux it pauses between attempts
when no file descriptor is left for a connection.
"""

import contextlib
import hashlib
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from .constants import PROGRAM
from .session import tool_environment

# The page `mhfe serve` is given, public, and the line that says it serves it.
SERVED_PAGE = b"<!doctype html><title>public test page</title>"
SERVE_RUNNING = "Fast mode is running"
# How long `mhfe serve` is left without a file descriptor for a connection, and the processor time
# it may take in that while: a pause between attempts keeps it near zero, a loop that spins takes
# all of it.
WITHOUT_DESCRIPTORS_SECONDS = 2
SPIN_LIMIT_SECONDS = 0.5
# utime and stime, the processor time in user and kernel mode in clock ticks of
# os.sysconf("SC_CLK_TCK"): fields 14 and 15 of /proc/<pid>/stat (proc(5)), counted here from the
# third, the first after the ")" that ends the command name, which may itself hold spaces.
UTIME_FIELD, STIME_FIELD = 11, 12


@contextlib.contextmanager
def serving(folder, arguments=("--no-browser",), prefix=(), environment=None):
    """Runs `mhfe serve` with `arguments` on a public page in `folder`, with the checksum file it
    needs beside it, after the command `prefix` (such as prlimit), until it says it is running;
    yields the process, the lines it wrote on standard error until then and the page's SHA-256,
    and stops it afterwards."""
    page = Path(folder) / "tool.html"
    page.write_bytes(SERVED_PAGE)
    digest = hashlib.sha256(SERVED_PAGE).hexdigest()
    (Path(folder) / "mhfe-fast-mode.sha256").write_text(f"{digest}  tool.html\n")
    process = subprocess.Popen([*prefix, PROGRAM, "serve", *arguments, str(page)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, env=environment or tool_environment())
    try:
        lines = []
        for raw in process.stderr:
            lines.append(raw.decode().rstrip("\n"))
            if SERVE_RUNNING in lines[-1]:
                break
        yield process, lines, digest
    finally:
        process.terminate()
        process.wait(10)


def check_serve_output():
    """`mhfe serve` starts with its title line, says the page's SHA-256 was verified and shows
    the digest on a line of its own, never split, every line within 78 columns
    (AUD-023-UI007)."""
    with tempfile.TemporaryDirectory() as folder, serving(folder) as (_, lines, digest):
        pass
    shown = [line for line in lines if line]
    assert shown[0] == "MHFE · Fast mode", f"serve: the first line is {shown[0]!r}"
    assert any(line.split() == ["SHA-256", digest] for line in shown), f"serve: {shown!r}"
    for line in shown:
        assert len(line) <= 78, f"serve: a line of {len(line)} columns: {line!r}"
    print("serve: a title line, the digest on a line of its own, every line within 78 columns")
    if sys.platform == "linux":
        check_serve_address_with_a_failing_opener()
        check_serve_without_descriptors()


def check_serve_without_descriptors():
    """With no file descriptor left for a connection, `mhfe serve` pauses between attempts rather
    than spinning at full processor time (AUD-023-FUN003): under prlimit --nofile=4 a request
    cannot be accepted, and the server's processor time stays small."""
    if shutil.which("prlimit") is None:
        print("serve without descriptors: prlimit is missing, not checked")
        return
    limit = SPIN_LIMIT_SECONDS * os.sysconf("SC_CLK_TCK")
    with tempfile.TemporaryDirectory() as folder, \
            serving(folder, prefix=("prlimit", "--nofile=4")) as (process, lines, _):
        found = re.search(r"127\.0\.0\.1:(\d+)", "\n".join(lines))
        assert found is not None, f"serve without descriptors: no address in {lines!r}"
        for _ in range(3):
            try:
                socket.create_connection(("127.0.0.1", int(found.group(1))), timeout=1).close()
            except OSError:
                pass
        time.sleep(WITHOUT_DESCRIPTORS_SECONDS)
        fields = Path(f"/proc/{process.pid}/stat").read_text().rsplit(")", 1)[1].split()
        ticks = int(fields[UTIME_FIELD]) + int(fields[STIME_FIELD])
    assert ticks < limit, f"serve without descriptors: {ticks} ticks of processor time"
    print("serve without descriptors: it waits between attempts instead of spinning")


def check_serve_address_with_a_failing_opener():
    """An opener that starts but fails still leaves the address on the screen (AUD-023-UI010):
    xdg-open is a stand-in that exits with code 3."""
    with tempfile.TemporaryDirectory() as folder:
        opener = Path(folder) / "xdg-open"
        opener.write_text("#!/bin/sh\nexit 3\n")
        opener.chmod(0o755)
        environment = {**tool_environment(), "PATH": folder}
        with serving(folder, arguments=(), environment=environment) as (_, lines, _):
            pass
    assert any("http://127.0.0.1:" in line for line in lines), f"serve: no address in {lines!r}"
    print("serve: the address is shown when the browser opener fails")
