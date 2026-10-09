#!/usr/bin/env python3
"""AUD-010 secrets-security probe (CHECK-SEC-003, CHECK-SEC-005): the process protections of the
command-line tool at the moment it waits for its first secret.

Starts the release build `target/release/mhfe <command> --stdin` with standard input on a pipe that
the probe holds open and never writes, so that the tool runs its checks at start and its
isolation and then waits in the read of the first answer; nothing secret is ever given. While it
waits, the probe reads from /proc, for the process and each of its threads:

  P1 core dumps are off: "Max core file size" 0 and 0 in /proc/PID/limits;
  P2 the process is not dumpable: the kernel refuses this probe, a process of the same user,
     to read /proc/PID/ns/net and /proc/PID/environ (ptrace access mode checks);
  P3 every thread has no_new_privs and a seccomp filter (NoNewPrivs 1, Seccomp 2);
  P4 the process is in a network namespace of its own: /proc/PID/net/dev lists only "lo" and
     /proc/PID/net/route has no IPv4 route.

Linux only. The tool is stopped with SIGKILL afterwards. Exits 1 when a check fails, 2 when the
probe cannot run (no release build, not Linux).

    python3 docs/audits/AUD-010-harnesses/secrets-security/cli-process-protection.py
"""

import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
BINARY = ROOT / "target" / "release" / "mhfe"
# How long the tool may take for its checks at start before it waits for input.
START_SECONDS = 20
COMMANDS = [["encrypt", "--stdin"], ["decrypt", "--stdin"]]


def waiting_for_input(pid):
    """Whether the main thread sleeps in a read: its state is S and the wait channel a read."""
    try:
        status = Path(f"/proc/{pid}/status").read_text()
    except OSError:
        return False
    state = next((line.split()[1] for line in status.splitlines() if line.startswith("State:")), "")
    # wchan names the kernel function a sleeping task waits in; reading it needs no ptrace access.
    try:
        wchan = Path(f"/proc/{pid}/wchan").read_text()
    except OSError:
        wchan = ""
    return state == "S" and ("pipe" in wchan or "read" in wchan or wchan in ("", "0"))


def field(text, name):
    return next((line.split(":", 1)[1].strip() for line in text.splitlines() if line.startswith(name + ":")), None)


def probe(command):
    failures = []
    read_end, write_end = os.pipe()
    with tempfile.TemporaryDirectory() as folder:
        output = open(Path(folder) / "output", "wb")
        tool = subprocess.Popen(
            [str(BINARY), *command],
            stdin=read_end,
            stdout=output,
            stderr=subprocess.STDOUT,
            cwd=folder,
            env={**os.environ, "NO_COLOR": "1"},
        )
        os.close(read_end)
        try:
            deadline = time.monotonic() + START_SECONDS
            while time.monotonic() < deadline and tool.poll() is None:
                if waiting_for_input(tool.pid):
                    # Twice, a moment apart, so that a short sleep inside the checks is not taken
                    # for the wait.
                    time.sleep(0.5)
                    if waiting_for_input(tool.pid):
                        break
                time.sleep(0.1)
            if tool.poll() is not None:
                output.flush()
                text = (Path(folder) / "output").read_text(errors="replace")
                return [f"{' '.join(command)}: the tool ended with {tool.returncode}: {text[-300:]}"]
            pid = tool.pid
            name = " ".join(command)

            limits = Path(f"/proc/{pid}/limits").read_text()
            core = next((line for line in limits.splitlines() if line.startswith("Max core file size")), "")
            values = core.split()[4:6]
            print(f"{name}: limits: {' '.join(core.split())}")
            if values != ["0", "0"]:
                failures.append(f"{name}: P1 core file size is {values}")

            for path in (f"/proc/{pid}/ns/net", f"/proc/{pid}/environ"):
                try:
                    if path.endswith("net"):
                        os.readlink(path)
                    else:
                        Path(path).read_bytes()
                    failures.append(f"{name}: P2 {path} was readable: the process is dumpable")
                    print(f"{name}: {path}: readable")
                except PermissionError:
                    print(f"{name}: {path}: refused (not dumpable)")

            for task in sorted(Path(f"/proc/{pid}/task").iterdir()):
                status = (task / "status").read_text()
                values = {key: field(status, key) for key in ("Name", "NoNewPrivs", "Seccomp", "Seccomp_filters")}
                print(f"{name}: thread {task.name}: {values}")
                if values["NoNewPrivs"] != "1" or values["Seccomp"] != "2":
                    failures.append(f"{name}: P3 thread {task.name} is not filtered: {values}")

            try:
                interfaces = [
                    line.split(":")[0].strip()
                    for line in Path(f"/proc/{pid}/net/dev").read_text().splitlines()[2:]
                ]
                routes = Path(f"/proc/{pid}/net/route").read_text().splitlines()[1:]
                print(f"{name}: interfaces {interfaces}, IPv4 routes {len(routes)}")
                if interfaces != ["lo"] or routes:
                    failures.append(f"{name}: P4 network: interfaces {interfaces}, routes {len(routes)}")
            except PermissionError:
                print(f"{name}: /proc/{pid}/net refused; namespace not observable from outside")
                failures.append(f"{name}: P4 the network namespace could not be observed")
        finally:
            tool.send_signal(signal.SIGKILL)
            tool.wait()
            os.close(write_end)
            output.close()
    return failures


def main():
    if not sys.platform.startswith("linux"):
        print("not Linux: nothing to probe")
        return 2
    if not BINARY.is_file():
        print(f"no release build at {BINARY}")
        return 2
    print(f"binary {BINARY}, {BINARY.stat().st_size} bytes")
    failures = []
    for command in COMMANDS:
        failures += probe(command)
    for failure in failures:
        print(f"FAIL {failure}")
    if failures:
        return 1
    print("PASSED: P1 to P4 for every command while it waits for its first secret.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
