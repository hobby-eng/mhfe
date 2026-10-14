#!/usr/bin/env python3
"""AUD-024, role guide-cli-commands, commit b6fca69: `mhfe new` asks a wrong or unusable answer
about the chosen word again in one line, keeping the earlier answers (CORE-42).

Two cases in a pseudo-terminal, each stopped with Ctrl+C before anything is drawn (no Argon2
work beyond the checks at start), with public test words only:
  A. position 25, which the library refuses: the position must be asked again at once, and the
     chosen word (a secret, typed on the private screen) must not be asked for again;
  B. a valid chosen word and position, then a word never to use that is not on the BIP39 list:
     only the word never to use may be asked again.

Usage, from the repository root:  python3 <this file> <path to the mhfe binary>
Exit 0: both cases keep the earlier answers. Exit 1: an earlier answer is asked again.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
PROGRAM = sys.argv[1]
sys.argv = [sys.argv[0], PROGRAM]
sys.path.insert(0, str(ROOT / "scripts"))
from terminal_suite.constants import (CHOSEN_ASKED, CHOSEN_WORD_ASKED, CTRL_C,  # noqa: E402
                                      LIST_SHOWN, NEVER_USE_ASKED, PLACE_ASKED)
from terminal_suite.session import Session  # noqa: E402

CSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b[=>]|\r")
ARGUMENTS = ("new", "--pim", "0", "--mem", "0", "--wallet-check", "no", "--repair-words", "0")
failures = []


def plain(data):
    return CSI.sub(b"", data).decode("utf-8", "replace")


def start():
    session = Session(ARGUMENTS, program=PROGRAM)
    session.wait_for(b"passphrase of the new wallet")
    # No passphrase: the question about a chosen word comes next.
    session.answer(b"\r", CHOSEN_ASKED, LIST_SHOWN)
    session.answer(b"2", CHOSEN_WORD_ASKED)
    return session


def stop(session):
    session.type(CTRL_C)
    session.drain_until_exit(10)
    session.close()


# A. A position the library refuses.
s = start()
s.answer(b"zoo\r", PLACE_ASKED)
mark = len(s.output)
asked = s.answer(b"25\r", NEVER_USE_ASKED) or NEVER_USE_ASKED
after_position = plain(s.output[mark:])
mark = len(s.output)
s.answer(b"\r", CHOSEN_ASKED, LIST_SHOWN)
after_never = plain(s.output[mark:])
mark = len(s.output)
s.answer(b"2", CHOSEN_WORD_ASKED)
again = plain(s.output[mark:])
stop(s)
print("===== A: after position 25 =====")
print(after_position.strip()[-400:])
print("===== A: after Enter at the word never to use =====")
print(after_never.strip()[-600:])
print("===== A: after key 2 =====")
print(again.strip()[-200:])
if "Word never to use" in after_position and "needs a position" not in after_position:
    print("FAIL A1: position 25 was not refused where it was typed; the next question came")
    failures.append("A1")
if "Do you want to choose a word" in after_never:
    print("FAIL A2: the refusal went back to the question whether to choose a word")
    failures.append("A2")
if "Chosen word, or Enter for none" in again:
    print("FAIL A3: the chosen word, a secret already typed, is asked for again")
    failures.append("A3")

# B. A word never to use that is not on the list, after a valid word and position.
s = start()
s.answer(b"zoo\r", PLACE_ASKED)
s.answer(b"24\r", NEVER_USE_ASKED)
mark = len(s.output)
s.answer(b"zooo\r", CHOSEN_ASKED, LIST_SHOWN)
after_typo = plain(s.output[mark:])
stop(s)
print("===== B: after the word never to use 'zooo' =====")
print(after_typo.strip()[-600:])
if "Do you want to choose a word" in after_typo:
    print("FAIL B: a wrong word never to use goes back to the chosen word's question")
    failures.append("B")
sys.exit(1 if failures else 0)
