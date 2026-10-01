"""AUD-005 command-line probes: colour rules, the weak-password warning and `check --stdin`.

Never runs Argon2. The password probes stop at the memory reservation: the address-space limit
set below makes the 2 GiB work area fail to allocate, so the tool exits with code 4 right after it
has read and judged the password. Public test data only.

Exit code 0 when every expectation holds, 1 otherwise. Two expectations fail on the reviewed
commit df70ca5: the weak-password warning (AUD-005-FUN001) and the hint after a failed memory
reservation (AUD-005-UI001).
"""

import os
from pathlib import Path
import resource
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
BINARY = str(ROOT / "target/release/mhfe")
PHRASE = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# The address space a probe may use: far below the 2 GiB Argon2 work area of the default level.
ADDRESS_SPACE_LIMIT = 1 << 30
# NOT_ENOUGH_RESOURCES in src/bin/mhfe/exit.rs.
EXIT_NOT_ENOUGH_RESOURCES = 4
WEAK_WARNING = b"not four or more words from the EFF dice list"
LEVEL_HINT = b"The highest memory level this computer can use now"

failures = []


def expect(condition, description):
    print(("ok    " if condition else "FAIL  ") + description)
    if not condition:
        failures.append(description)


def limit_address_space():
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_LIMIT, ADDRESS_SPACE_LIMIT))


def encrypt_until_memory(password):
    """Runs `mhfe encrypt --stdin` until it fails to reserve the work area; returns stderr."""
    answers = f"{PHRASE}\n{password}\n{password}\n".encode()
    result = subprocess.run([BINARY, "encrypt", "--stdin"], input=answers, capture_output=True,
                            timeout=30, preexec_fn=limit_address_space)
    if result.returncode != EXIT_NOT_ENOUGH_RESOURCES or b"Accepted" not in result.stderr:
        raise SystemExit(f"probe inconclusive: exit {result.returncode}\n{result.stderr.decode()}")
    return result.stderr


def colour_probes():
    plain = {k: v for k, v in os.environ.items() if k not in ("NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE")}

    def escapes(extra, through_terminal):
        env = {**plain, **extra}
        command = [BINARY, "password", "--words", "0"]
        if through_terminal:
            # util-linux script(1) gives the tool a pseudo-terminal.
            command = ["script", "-qec", " ".join(command), "/dev/null"]
        result = subprocess.run(command, env=env, capture_output=True, timeout=10)
        return (result.stdout + result.stderr).count(b"\x1b[")

    expect(escapes({"TERM": "xterm-256color"}, True) > 0, "colour at a terminal")
    expect(escapes({"TERM": "xterm-256color", "NO_COLOR": "1"}, True) == 0, "NO_COLOR turns colour off")
    expect(escapes({"TERM": "xterm-256color", "CLICOLOR": "0"}, True) == 0, "CLICOLOR=0 turns colour off")
    expect(escapes({"TERM": "dumb"}, True) == 0, "TERM=dumb turns colour off")
    expect(escapes({"TERM": "xterm-256color"}, False) == 0, "no colour in a pipe")
    expect(escapes({"TERM": "xterm-256color", "CLICOLOR_FORCE": "1"}, False) > 0, "CLICOLOR_FORCE turns colour on")


def password_probes():
    expect(WEAK_WARNING in encrypt_until_memory("abacus"), "one dice word is warned about")
    expect(WEAK_WARNING not in encrypt_until_memory("abacus zoom yearbook zipfile"),
           "four different dice words pass without a warning")
    expect(WEAK_WARNING in encrypt_until_memory("abacus abacus abacus abacus"),
           "one dice word typed four times is warned about (AUD-005-FUN001)")


def allocation_failure_probe():
    stderr = encrypt_until_memory("abacus zoom yearbook zipfile")
    expect(b"could not reserve 2 GiB" in stderr, "a failed reservation is reported")
    expect(LEVEL_HINT not in stderr,
           "a failed reservation does not recommend a memory level (AUD-005-UI001)")


def check_stdin_probe():
    result = subprocess.run([BINARY, "check", "--stdin"], input=b"", capture_output=True, timeout=10)
    expect(result.returncode == 2 and b"--address" in result.stderr,
           "check --stdin without a reference option is refused before reading anything")


colour_probes()
password_probes()
allocation_failure_probe()
check_stdin_probe()
if failures:
    print(f"{len(failures)} expectation(s) failed.")
    sys.exit(1)
print("Every expectation holds.")
