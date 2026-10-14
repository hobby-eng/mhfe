#!/usr/bin/env python3
"""AUD-024: what `mhfe encrypt` and `mhfe rekey` tell a person about a same-length (suite 4)
container, checked against mhfe_spec/README.md:669-671 (a wrong password OR SETTING is not
detected; the container reveals the source's word count) and mhfe SECURITY.md:184-195 (the tool
shows these consequences before the choice).

Every case stops before any Argon2 work: Ctrl+C at the repair-word question or at the password
prompt. Public test data only (the zero-12 phrase and the same-length-zero-12 container).

Usage, from the repository root:  python3 <this file> <path to the mhfe binary>
Exit 0: every check holds. Exit 1: at least one check fails (each failure is printed).
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
PROGRAM = sys.argv[1]
sys.argv = [sys.argv[0], PROGRAM]
sys.path.insert(0, str(ROOT / "scripts"))
from terminal_suite.constants import (CTRL_C, LIST_SHOWN, EXPLAINED, PHRASE,  # noqa: E402
                                      REPAIR_ASKED)
from terminal_suite.session import Session  # noqa: E402

CSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b[=>]|\r")
SUITE4 = json.loads((ROOT / "tests/fixtures/suite4-vectors/same-length-zero-12.json").read_text())

# What the specification asks the person to be told, as patterns over the plain text.
SETTING = re.compile(r"(wrong|mistyped)[^.\n]*(setting|PIM|memory level)", re.I)
WORD_COUNT = re.compile(r"(shows|reveals)[^.\n]*(12 words|word count|length)", re.I)
PASSWORD = re.compile(r"wrong password[^.\n]*not be detected", re.I)

failures = []


def plain(data):
    return CSI.sub(b"", data).decode("utf-8", "replace")


def check(label, text, pattern, wanted=True):
    found = bool(pattern.search(text))
    status = "ok  " if found == wanted else "FAIL"
    print(f"{status} {label}: {'found' if found else 'absent'} /{pattern.pattern}/")
    if found != wanted:
        failures.append(label)


def section(title, text):
    # The typed words' hint rows are left out: the text from the last screen title on.
    start = text.rfind("MHFE \u00b7")
    print(f"\n===== {title} =====")
    print(text[start if start >= 0 else 0:].strip())
    print("===== end =====")


# A. The list at a terminal: before the choice, and after choosing the same length (key 2).
s = Session(("encrypt", "--pim", "0"), program=PROGRAM)
s.wait_for(b"seed phrase: ")
s.answer(PHRASE.encode() + b"\r", LIST_SHOWN)
before = plain(s.output)
mark = len(s.output)
s.answer(b"2", REPAIR_ASKED)
after = plain(s.output[mark:])
s.type(CTRL_C)
s.drain_until_exit(10)
s.close()
section("A1 encrypt, list shown, before any key", before)
section("A2 encrypt, after key 2 (same length), up to the repair-word question", after)
print()
check("A1 before the choice: word count disclosed", before, WORD_COUNT)
check("A1 before the choice: wrong password not detected", before, PASSWORD)
check("A2 after the choice: wrong password not detected", after, PASSWORD)
check("A2 after the choice: wrong setting not detected", after, SETTING)
check("A2 after the choice: word count disclosed", after, WORD_COUNT)

# B. The same list, ? pressed: the explanation exists, but only on request.
s = Session(("encrypt", "--pim", "0"), program=PROGRAM)
s.wait_for(b"seed phrase: ")
s.answer(PHRASE.encode() + b"\r", LIST_SHOWN)
mark = len(s.output)
s.answer(b"?", EXPLAINED)
explained = plain(s.output[mark:])
s.type(CTRL_C)
s.drain_until_exit(10)
s.close()
section("B encrypt, ? pressed at the list", explained)
print()
check("B ? explanation: word count disclosed", explained, WORD_COUNT)
check("B ? explanation: wrong setting not detected", explained, SETTING)

# C. --same-length at a terminal: no list, the consequence line only.
s = Session(("encrypt", "--pim", "0", "--same-length"), program=PROGRAM)
s.wait_for(b"seed phrase: ")
mark = len(s.output)
s.answer(PHRASE.encode() + b"\r", REPAIR_ASKED)
flag = plain(s.output[mark:])
s.type(CTRL_C)
s.drain_until_exit(10)
s.close()
section("C encrypt --same-length, up to the repair-word question", flag)
print()
check("C --same-length: wrong password not detected", flag, PASSWORD)
check("C --same-length: wrong setting not detected", flag, SETTING)
check("C --same-length: word count disclosed", flag, WORD_COUNT)

# D. rekey of a same-length container, up to its password prompt (the replacement comes only after
# a full-cost recovery, which this probe does not run).
s = Session(("rekey", "--pim", "0"), program=PROGRAM)
s.wait_for(b"ontainer phrase", b"seed phrase: ")
mark = len(s.output)
s.answer(SUITE4["container"].encode() + b"\r", b"assword: ")
rekey = plain(s.output[mark:])
s.type(CTRL_C)
s.drain_until_exit(10)
s.close()
section("D rekey of the same-length-zero-12 container, up to the password prompt", rekey)
print()
check("D rekey: wrong setting not detected", rekey, SETTING)
check("D rekey: word count disclosed", rekey, WORD_COUNT)

# E. The long help of --same-length, the place a script's author reads before choosing.
import subprocess  # noqa: E402
from terminal_suite.session import tool_environment  # noqa: E402
helped = subprocess.run([PROGRAM, "encrypt", "--help"], capture_output=True, text=True,
                        env=tool_environment(), timeout=30)
text = " ".join((helped.stdout + helped.stderr).split())
start = text.find("--same-length")
help_text = text[start:start + 900]
section("E encrypt --help, from --same-length on (900 characters)", help_text)
print()
check("E --help: wrong setting not detected", help_text, SETTING)
check("E --help: word count disclosed", help_text, WORD_COUNT)

# F. A script: --stdin --same-length, two different password lines, refused before Argon2.
scripted = subprocess.run(
    [PROGRAM, "encrypt", "--stdin", "--same-length"],
    input=f"{PHRASE}\npublic test password one\npublic test password two\n",
    capture_output=True, text=True, env=tool_environment(), timeout=30)
section(f"F encrypt --stdin --same-length, exit code {scripted.returncode}", scripted.stderr)
print()
check("F script: wrong setting not detected", scripted.stderr, SETTING)
check("F script: word count disclosed", scripted.stderr, WORD_COUNT)

print()
if failures:
    print(f"{len(failures)} check(s) failed: " + "; ".join(failures))
    sys.exit(1)
print("all checks hold")
