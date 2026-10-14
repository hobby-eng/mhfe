"""AUD-024 verification: drives `mhfe check --fingerprint --pim 0` on a pseudo-terminal, as the
terminal suite's check_container_search does (scripts/terminal_suite/repair.py:211-226), up to the
decoy search with the container's own wallet, optionally inside a systemd user scope with a pids
limit (TasksMax). It never types a password: at "Container password:" it presses Ctrl+C, so no
suite-cost Argon2 runs. Public data only: zero-12's container phrase with word 24 typed as ?, and
its published decoy fingerprint 487a156e.

Usage, from the mhfe repository root:
  PYTHONDONTWRITEBYTECODE=1 python3 cli_decoy.py <mhfe binary> [TasksMax]
"""
import sys
import time

binary = sys.argv[1]
tasks = sys.argv[2] if len(sys.argv) > 2 else None
# The suite's constants read the program from the command line; it is given only the binary.
sys.argv = [sys.argv[0], binary]
sys.path.insert(0, "scripts")
from terminal_suite.constants import CANCELLED_SHOWN, CONTAINER_ASKED, CTRL_C, LIST_SHOWN  # noqa: E402
from terminal_suite.repair import (CARD_ASKED, CONTAINER_PASSPHRASE_ASKED, REFERENCE_ASKED,  # noqa: E402
                                   SEARCH_ASKED, ZERO_12_DECOY_FINGERPRINT, container_with)
from terminal_suite.session import Session  # noqa: E402

arguments = ("check", "--fingerprint", "--pim", "0")
if tasks:
    session = Session(("--user", "--scope", "--quiet", "-p", f"TasksMax={tasks}", binary,
                       *arguments), program="systemd-run")
else:
    session = Session(arguments, program=binary)
session.wait_for(CONTAINER_ASKED, limit=60)
session.answer(container_with({24: "?"}) + b"\r", CARD_ASKED)
session.answer(b"\r", SEARCH_ASKED)
session.answer(b"1", REFERENCE_ASKED)
session.answer(ZERO_12_DECOY_FINGERPRINT + b"\r", CONTAINER_PASSPHRASE_ASKED, LIST_SHOWN)
start = len(session.output)
session.press(b"1")  # No passphrase with the container phrase: the search starts.
seen = session.wait_for(b"Container password: ", b"panicked", b"Found word", limit=30)
time.sleep(1.0)
try:
    session.wait_for(b"\x00never", limit=1)
except AssertionError:
    pass
if b"Container password: " in session.output[start:]:
    session.answer(CTRL_C, CANCELLED_SHOWN)  # Never a password: no Argon2 at suite cost.
session.drain_until_exit(10)
code, settings = session.close()
tail = session.output[start:].decode("utf-8", "replace")
print("after the search started:")
print("".join(ch if ch.isprintable() or ch in "\n" else f"\\x{ord(ch):02x}" for ch in tail))
print(f"exit code: {code}")
print(f"terminal settings restored: {settings == session.original}")
