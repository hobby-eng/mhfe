#!/usr/bin/env python3
"""AUD-024, role guide-cli-commands, commit b6fca69: the container password prompt of `mhfe encrypt`
says which secret it is and what it does (CORE-39) at TERM=xterm-256color and at TERM=dumb.

Each session types the public zero-12 phrase and stops with Ctrl+C at the password prompt, before
any Argon2 work.

Usage, from the repository root:  python3 <this file> <path to the mhfe binary>
Exit 0: both prompts say what the password does. Exit 1: one does not.
"""
import re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[4]
PROGRAM = sys.argv[1]
sys.argv = [sys.argv[0], PROGRAM]
sys.path.insert(0, str(ROOT / "scripts"))
from terminal_suite.constants import CTRL_C, PHRASE  # noqa: E402
from terminal_suite.session import Session  # noqa: E402
CSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b[=>]|\r")
WHAT = "it is NOT a BIP39 passphrase"
failures = []
for term in ("xterm-256color", "dumb"):
    s = Session(("encrypt", "--pim", "0", "--mem", "0", "--same-length", "no", "--repair-words", "0",
                 "--new-password", "own"), term=term, program=PROGRAM)
    s.wait_for(b"seed phrase: ", b"seed phrase (hidden): ")
    mark = len(s.output)
    s.answer(PHRASE.encode() + b"\r", b"Container password")
    shown = CSI.sub(b"", s.output[mark:]).decode("utf-8", "replace")
    s.type(CTRL_C)
    s.drain_until_exit(10)
    code, _ = s.close()
    tail = shown[shown.rfind("MHFE"):] if "MHFE" in shown else shown
    print(f"===== TERM={term} (exit {code}) =====")
    print(tail.strip()[-500:])
    print(f"says what the password does ({WHAT!r}):", WHAT in shown)
    if WHAT not in shown:
        failures.append(term)
        print(f"FAIL: at TERM={term} the prompt does not say what the container password does")
sys.exit(1 if failures else 0)
