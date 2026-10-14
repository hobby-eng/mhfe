"""AUD-024 verify-decoy-fingerprint-collision: drives `mhfe <command> --pim 0` on a
pseudo-terminal up to the missing-word search with the container's own wallet, with the terminal
suite's session (scripts/terminal_suite). Public data only: "abandon" x 10 "? ?" and the master key
fingerprint a30a4e0f, which both "abandon" x 10 "able ghost" and "abandon" x 10 "best student"
have. It never types a password: after "Use it" it presses Ctrl+C at "Container password:", so no
Argon2 runs. Exits 1 when the tool offers the earlier candidate ("able ghost") as the found
container phrase with no word of a warning about another match; 0 otherwise.

Usage, from the mhfe repository root:
  PYTHONDONTWRITEBYTECODE=1 python3 <this file> <mhfe binary> decrypt --pim 0
"""
import sys

binary, *arguments = sys.argv[1:]
sys.argv = [sys.argv[0], binary]
sys.path.insert(0, "scripts")
from terminal_suite.constants import CANCELLED_SHOWN, CONTAINER_ASKED, CTRL_C, LIST_SHOWN  # noqa: E402
from terminal_suite.repair import (CARD_ASKED, CONTAINER_PASSPHRASE_ASKED, REFERENCE_ASKED,  # noqa: E402
                                   SEARCH_ASKED)
from terminal_suite.session import Session  # noqa: E402

FOUND_ASKED = b"Use the found container phrase?"
WARNINGS = (b"several", b"another candidate", b"also match", b"ambig", b"32 bits", b"32-bit",
            b"more than one", b"both")
session = Session(tuple(arguments), program=binary)
session.wait_for(CONTAINER_ASKED, limit=60)
session.answer(("abandon " * 10 + "? ?").encode() + b"\r", CARD_ASKED)
session.answer(b"\r", SEARCH_ASKED, LIST_SHOWN)
session.answer(b"1", REFERENCE_ASKED)
session.answer(b"a30a4e0f\r", CONTAINER_PASSPHRASE_ASKED, LIST_SHOWN)
start = len(session.output)
session.press(b"1")  # No passphrase with the container phrase: the search runs.
outcome = session.wait_for(FOUND_ASKED, SEARCH_ASKED, limit=600)
found = session.output[start:]
after = b""
if outcome == FOUND_ASKED:
    session.wait_for(LIST_SHOWN, limit=10, since=start)
    use = len(session.output)
    session.press(b"1")  # Use it
    session.wait_for(b"Container password: ", limit=20)
    after = session.output[use:]
    session.answer(CTRL_C, CANCELLED_SHOWN)  # Never a password: no Argon2.
session.drain_until_exit(10)
code, settings = session.close()


def printable(data):
    text = data.decode("utf-8", "replace")
    return "".join(ch if ch.isprintable() or ch == "\n" else f"\\x{ord(ch):02x}" for ch in text)


print("--- from the search's start to the next question:")
print(printable(found))
if after:
    print("--- after 'Use it':")
    print(printable(after))
print(f"exit code of mhfe: {code}")
earlier = outcome == FOUND_ASKED and b"able" in found and b"ghost" in found
warned = any(word in found.lower() for word in WARNINGS)
print(f"offered the earlier candidate (able ghost) as the found container phrase: {earlier}")
print(f"any word of a warning about another match or the fingerprint's strength: {warned}")
sys.exit(1 if earlier and not warned else 0)
