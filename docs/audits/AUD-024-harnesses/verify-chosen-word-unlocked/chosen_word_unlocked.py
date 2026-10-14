#!/usr/bin/env python3
"""AUD-024, role verify-chosen-word-unlocked, commit b6fca69: while `mhfe new` asks for the word
never to use, the chosen word must be held only in locked memory (RUST-13; SECURITY.md, "The
secrets the program keeps beyond a moment are held in locked memory").

The real binary runs in a pseudo-terminal with the shim locked_scan.c preloaded (compiled here
into the scratch folder given). The shim records mlock/munlock page by page and, each time the
program blocks reading standard input, scans the program's writable memory for the chosen word as
typed: "ZoO", a public BIP39 word in a mixed case that no word list holds. Stages:
  S1 the chosen-word prompt (nothing typed yet): no copy expected;
  S2 the position prompt, the word typed: positive control, a copy in a LOCKED page;
  S3 the never-use prompt: the word must still be only in LOCKED pages;
  S4 back at the first question after an unusable never-use word ("zooo"): every copy gone.
It stops with Ctrl+C at S4; nothing is drawn and no Argon2 runs beyond the checks at start.

Usage, from the repository root:
  python3 docs/audits/AUD-024-harnesses/verify-chosen-word-unlocked/chosen_word_unlocked.py \
      <mhfe binary> <scratch folder>
Exit 0: no unlocked copy at S3 (and the controls behave). Exit 1: an UNLOCKED, live copy of the
chosen word outside the standard input buffer while the never-use prompt waits. Exit 2: a control
failed (the probe cannot judge).
"""
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PROGRAM, SCRATCH = sys.argv[1], Path(sys.argv[2])
sys.argv = [sys.argv[0], PROGRAM]
sys.path.insert(0, str(ROOT / "scripts"))
from terminal_suite.constants import (CHOSEN_ASKED, CHOSEN_WORD_ASKED, CTRL_C,  # noqa: E402
                                      LIST_SHOWN, NEVER_USE_ASKED, PLACE_ASKED)
from terminal_suite.session import Session  # noqa: E402

MARKER = b"ZoO"
SCRATCH.mkdir(parents=True, exist_ok=True)
shim = SCRATCH / "locked_scan.so"
subprocess.run(["gcc", "-O1", "-shared", "-fPIC", "-o", str(shim), str(HERE / "locked_scan.c"), "-ldl"],
               check=True)
log = SCRATCH / "scan.log"
log.write_text("")
os.environ["LD_PRELOAD"] = str(shim)
os.environ["PROBE_LOG"] = str(log)
os.environ["PROBE_MARKER_HEX"] = MARKER.hex()


def last_scan():
    time.sleep(0.5)
    lines = [line for line in log.read_text().splitlines() if line.startswith("scan ")]
    return lines[-1] if lines else "(no scan)"


def hits(scan):
    return [part for part in scan.split(" [")[1:]]


stages = {}
s = Session(("new", "--pim", "0", "--mem", "0", "--wallet-check", "no", "--repair-words", "0"),
            program=PROGRAM)
s.wait_for(b"passphrase of the new wallet")
s.answer(b"\r", CHOSEN_ASKED, LIST_SHOWN)
s.answer(b"2", CHOSEN_WORD_ASKED)
stages["S1 chosen-word prompt"] = last_scan()
s.answer(MARKER + b"\r", PLACE_ASKED)
stages["S2 position prompt"] = last_scan()
s.answer(b"\r", NEVER_USE_ASKED)
stages["S3 never-use prompt"] = last_scan()
s.answer(b"zooo\r", CHOSEN_ASKED, LIST_SHOWN)
stages["S4 first question again"] = last_scan()
s.type(CTRL_C)
s.drain_until_exit(10)
code = s.process.returncode
os.close(s.master)
os.close(s.slave)

for name, scan in stages.items():
    print(f"{name}: {scan}")
print(f"mhfe exit code after Ctrl+C: {code}")


def live_unlocked(scan):
    return [h for h in hits(scan) if "UNLOCKED" in h and "stdin-buffer" not in h]


def locked(scan):
    return [h for h in hits(scan) if " LOCKED" in h]


controls = []
if hits(stages["S1 chosen-word prompt"]):
    controls.append("S1 has a copy before the word is typed")
if not locked(stages["S2 position prompt"]):
    controls.append("S2 shows no locked copy: the shim does not see the program's locking")
if hits(stages["S4 first question again"]) and live_unlocked(stages["S4 first question again"]):
    controls.append("S4 still holds an unlocked copy: S3's copy may be residue, not a live copy")
for problem in controls:
    print(f"CONTROL FAILED: {problem}")
if controls:
    sys.exit(2)
unlocked = live_unlocked(stages["S3 never-use prompt"])
if unlocked:
    print(f"FAIL: {len(unlocked)} unlocked copy(ies) of the chosen word while the never-use prompt "
          f"waits, wiped by S4: {unlocked}")
    sys.exit(1)
print("PASS: the chosen word is only in locked pages while the never-use prompt waits")
sys.exit(0)
