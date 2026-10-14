#!/usr/bin/env python3
"""AUD-024, role gap-1-fast-mode-launchers-real-browser, reviewed commit b6fca69.

The two other documented starts of the fast mode, with a stand-in for the system's browser opener:

1. `mhfe serve <page>` without --no-browser: README.md:503-504 says it "opens it". A stand-in
   `xdg-open` placed first on PATH records the address it is given and opens nothing.
2. `mhfe` started without arguments in a terminal, beside a page and its mhfe-fast-mode.sha256:
   README.md:505 says the page appears "as the menu's first entry". The menu runs its startup
   checks (a few MiB), the probe reads its screen, checks the first entry and presses Enter, and the
   stand-in opener records the address the entry serves.

Each served address is then asked for "/" with the Host header a browser sends, and the answer must
be 200 with the seven security headers of src/bin/mhfe/serve.rs. Linux or macOS only (pty).

    python3 docs/audits/AUD-024-harnesses/gap-1-fast-mode-launchers-real-browser/opener-and-menu.py \
        <mhfe binary> <folder with a page and its mhfe-fast-mode.sha256> <scratch folder>

Exits 1 when a check fails.
"""

import fcntl
import http.client
import os
import pty
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import termios
import time

SEVEN = {
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-embedder-policy": "require-corp",
    "content-security-policy": "frame-ancestors 'none'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
}
FAILURES = []


def expect(condition, text):
    print(("ok    " if condition else "FAIL  ") + text)
    if not condition:
        FAILURES.append(text)


def ask(address):
    """Status and headers of GET / at `address`, with the Host header a browser sends."""
    match = re.match(r"http://(127\.0\.0\.1):(\d+)/$", address)
    connection = http.client.HTTPConnection(match.group(1), int(match.group(2)), timeout=10)
    connection.request("GET", "/", headers={"Host": "127.0.0.1:" + match.group(2)})
    response = connection.getresponse()
    body = response.read()
    headers = {name.lower(): value for name, value in response.getheaders()}
    connection.close()
    return response.status, headers, len(body)


def check_served(address, label):
    status, headers, length = ask(address)
    print("      {}: status {}, {} bytes".format(label, status, length))
    expect(status == 200, "{}: the address answers 200".format(label))
    for name, value in SEVEN.items():
        expect(headers.get(name) == value, "{}: {}: {}".format(label, name, value))


def wait_for_file(path, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if os.path.exists(path) and os.path.getsize(path) > 0:
            with open(path) as file:
                return file.read().strip()
        time.sleep(0.2)
    return None


def menu_text(tool, environment):
    """The menu's first screen of the mhfe in `tool`, 120 columns wide, then Ctrl+C."""
    pid, fd = pty.fork()
    if pid == 0:
        os.environ.clear()
        os.environ.update(environment)
        os.environ["TERM"] = "xterm-256color"
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        os.chdir(tool)
        os.execv(os.path.join(tool, "mhfe"), [os.path.join(tool, "mhfe")])
    screen = b""
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            try:
                screen += os.read(fd, 65536)
            except OSError:
                break
    os.kill(pid, signal.SIGINT)
    time.sleep(1)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", screen.decode("utf-8", "replace"))


def main(mhfe, page_folder, work):
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    stub_folder = os.path.join(work, "stub")
    os.makedirs(stub_folder)
    opened = os.path.join(work, "opened.txt")
    stub = os.path.join(stub_folder, "xdg-open")
    with open(stub, "w") as file:
        file.write('#!/bin/sh\nprintf "%s\\n" "$1" >> "{}"\nexit 0\n'.format(opened))
    os.chmod(stub, 0o755)
    # The program and the page side by side, as a release archive beside a tool would be.
    tool = os.path.join(work, "tool")
    shutil.copytree(page_folder, tool)
    shutil.copy2(mhfe, os.path.join(tool, "mhfe"))
    page = [name for name in os.listdir(tool) if name.endswith(".html")][0]
    environment = dict(os.environ, PATH=stub_folder + os.pathsep + os.environ["PATH"], NO_COLOR="1")
    environment.pop("DISPLAY", None)
    environment.pop("WAYLAND_DISPLAY", None)

    print("=== mhfe serve <page> with the system opener")
    child = subprocess.Popen(
        [os.path.join(tool, "mhfe"), "serve", os.path.join(tool, page)],
        env=environment, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True,
    )
    lines = []
    address = None
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and address is None:
        line = child.stderr.readline()
        if not line:
            break
        lines.append(line.rstrip("\n"))
        found = re.search(r"Opened (http://127\.0\.0\.1:\d+/); if no browser shows it", line)
        if found:
            address = found.group(1)
    print("      output: " + " | ".join(lines))
    expect(address is not None, "serve says it opened the address")
    recorded = wait_for_file(opened, 10)
    print("      the opener was given: {}".format(recorded))
    expect(recorded == address, "the system opener was given the printed address")
    if address:
        check_served(address, "serve")
    child.send_signal(signal.SIGINT)
    try:
        child.wait(5)
    except subprocess.TimeoutExpired:
        child.kill()
    print("      exit after Ctrl+C: {}".format(child.returncode))
    os.remove(opened)

    print("=== mhfe without arguments, beside the page")
    pid, fd = pty.fork()
    if pid == 0:
        os.environ.clear()
        os.environ.update(environment)
        os.environ["TERM"] = "xterm-256color"
        # 40 rows of 120 columns, so that the command column shows the page's whole name.
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        os.chdir(tool)
        os.execv(os.path.join(tool, "mhfe"), [os.path.join(tool, "mhfe")])
    screen = b""

    def read_for(seconds):
        nonlocal screen
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                try:
                    screen += os.read(fd, 65536)
                except OSError:
                    return

    read_for(6)
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", screen.decode("utf-8", "replace"))
    entries = [line.strip() for line in text.splitlines() if line.strip()]
    print("      menu screen:")
    for line in entries[:16]:
        print("        " + line)
    # The menu cuts its command column at 78 columns (choice.rs), so a page name longer than
    # "tool.html" shows cut with "…": the entry is found by its start.
    fast = [index for index, line in enumerate(entries) if "mhfe serve " in line]
    other = [index for index, line in enumerate(entries) if "mhfe new" in line]
    expect(bool(fast), "the menu offers mhfe serve for the page beside the program")
    expect(bool(fast) and bool(other) and fast[0] < other[0], "the fast mode is the first entry")
    if fast:
        os.write(fd, b"\r")
        recorded = wait_for_file(opened, 15)
        read_for(1)
        print("      the opener was given: {}".format(recorded))
        expect(recorded is not None, "the menu entry opened an address")
        if recorded:
            check_served(recorded, "menu entry")
    os.kill(pid, signal.SIGINT)
    time.sleep(1)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)

    print("=== mhfe without arguments, beside a page whose checksum file is wrong")
    with open(os.path.join(tool, "mhfe-fast-mode.sha256"), "w") as file:
        file.write("0" * 64 + "  " + page + "\n")
    text = menu_text(tool, environment)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in lines[:8]:
        print("        " + line)
    expect(any("The fast mode is not offered." in line for line in lines),
           "the menu says that the fast mode is not offered")
    expect(any("SHA-256" in line for line in lines), "the menu says why (the SHA-256)")
    expect(not any("mhfe serve " in line for line in lines), "the menu has no fast-mode entry")
    shutil.copy2(os.path.join(page_folder, "mhfe-fast-mode.sha256"), tool)

    print("=== mhfe-fast-mode.py without a file, beside the page")
    script = os.path.join(tool, "mhfe-fast-mode.py")
    shutil.copy2(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..",
                              "packaging", "mhfe-fast-mode.py"), script)
    child = subprocess.Popen([sys.executable, script, "--no-browser"], env=environment,
                             stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True)
    address = None
    lines = []
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and address is None:
        line = child.stderr.readline()
        if not line:
            break
        lines.append(line.rstrip("\n"))
        found = re.search(r"Open (http://127\.0\.0\.1:\d+/) in your browser", line)
        if found:
            address = found.group(1)
    print("      output: " + " | ".join(lines))
    expect(address is not None and any(page + " verified" in line for line in lines),
           "the Python launcher serves the page its checksum file names")
    if address:
        check_served(address, "python launcher without a file")
    child.send_signal(signal.SIGINT)
    try:
        child.wait(5)
    except subprocess.TimeoutExpired:
        child.kill()
    print("RESULT: " + ("PASS" if not FAILURES else "FAIL ({})".format(len(FAILURES))))
    return 0 if not FAILURES else 1


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(__doc__.strip().splitlines()[-3])
        sys.exit(2)
    sys.exit(main(*sys.argv[1:]))
