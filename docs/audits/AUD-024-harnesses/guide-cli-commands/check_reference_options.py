#!/usr/bin/env python3
"""AUD-024, role guide-cli-commands, commit b6fca69: every answer of `mhfe check`'s reference
question is also a command-line option (CORE-41).

The probe reads the answers that the question "What should the recovered seed phrase be compared
with?" offers for the public zero-12 container (a 24-word suite 3 container), in a pseudo-terminal,
stopped with Ctrl+C before any Argon2 work, and the options of `mhfe check --help`. Each answer
must have an option that selects it. It also shows that a script cannot select that reference.

Usage, from the repository root:  python3 <this file> <path to the mhfe binary>
Exit 0: every answer has an option. Exit 1: an answer has none (each is printed).
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
PROGRAM = sys.argv[1]
sys.argv = [sys.argv[0], PROGRAM]
sys.path.insert(0, str(ROOT / "scripts"))
from terminal_suite.constants import CONTAINER, CONTAINER_ASKED, CTRL_C, LIST_SHOWN  # noqa: E402
from terminal_suite.session import Session, run_plainly  # noqa: E402

CSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b[=>]|\r")
QUESTION = b"What should the recovered seed phrase be compared with?"
# The option that selects each answer, as `check --help` must list it.
OPTION_OF = {
    "A receiving address": "--address",
    "The master key fingerprint": "--fingerprint",
    "The container's built-in check": "--words",
    "The phrase + passphrase check": None,  # filled from the help below, if any option names it
}

session = Session(("check", "--pim", "0", "--mem", "0"), program=PROGRAM)
session.wait_for(CONTAINER_ASKED)
session.answer(CONTAINER.encode() + b"\r", b"ontainer password: ")
session.answer(b"public test password\r", QUESTION, LIST_SHOWN)
session.type(CTRL_C)
session.drain_until_exit(10)
code, _ = session.close()
shown = CSI.sub(b"", session.output[session.output.rfind(QUESTION):]).decode("utf-8", "replace")
print("===== the reference question at a terminal (stopped with Ctrl+C, exit", code, ") =====")
print(shown.strip())
answers = [label for label in OPTION_OF if label in shown]
print("answers offered:", answers)

help_text = subprocess.run([PROGRAM, "check", "--help"], capture_output=True, text=True,
                           env={"NO_COLOR": "1", "PATH": "/usr/bin:/bin"}).stdout
options = sorted(set(re.findall(r"^\s+(--[a-z-]+)", help_text, re.M)))
print("options of check --help:", options)
flat = " ".join(help_text.split())
for name in options:
    # An option whose own help line names the phrase + passphrase check selects it.
    line = re.search(rf"{re.escape(name)}\b[^\n]*", help_text)
    if line and "phrase + passphrase check" in line.group(0):
        OPTION_OF["The phrase + passphrase check"] = name

missing = [label for label in answers if OPTION_OF[label] is None
           or OPTION_OF[label] not in options]
for label in missing:
    print(f"FAIL: the answer {label!r} has no command-line option")

# A script must name a reference: --address, --fingerprint or --words; none selects the check.
result = run_plainly(("check", "--stdin", "--pim", "0", "--mem", "0"))
print("check --stdin without a reference: exit", result.returncode)
print(result.stderr.decode("utf-8", "replace").strip())
for attempt in (("check", "--wallet-check", "yes"), ("check", "--words", "wallet")):
    result = run_plainly(attempt)
    print(" ".join(attempt), "-> exit", result.returncode, "|",
          " ".join(result.stderr.decode("utf-8", "replace").split())[:160])
sys.exit(1 if missing else 0)
