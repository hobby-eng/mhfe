# TOOL-01: public fixtures and cases of the Python PTY test runtime.
"""Accepted spellings are shown before an input screen is cleared.

Only published or zero-entropy phrases and their repair words are used.
Every run stops before encryption or recovery; no full-size Argon2 runs.
"""

import os
import subprocess

from .constants import (
    CANCELLED,
    CONTAINER,
    CTRL_C,
    ENTER,
    LEAVE_PRIVATE,
    PHRASE,
    PROGRAM,
)
from .session import READ_BACK_PROMPT, Session

WRITTEN_OUT = b"Accepted words, written out:"


def abbreviated(words):
    """Prefixes in another case, each accepted by the library parser."""
    return " ".join(word[:4].upper() for word in words.split()).encode()


def finish(session):
    """Cancels before costly work and checks the original terminal mode.
    """
    session.press(CTRL_C)
    assert session.drain_until_exit(10), "spelling: cancellation did not finish"
    code, settings = session.close()
    assert code == CANCELLED, code
    assert settings == session.original, "spelling: terminal mode changed"


def supported_typographic_spellings_are_normalized():
    """Prefixes and ambiguous exact words get an explicit, private
    read-back.
    """
    encrypt = ("encrypt", "--pim", "0", "--mem", "0", "--same-length", "no",
               "--repair-words", "0", "--new-password", "own")
    for phrase in (PHRASE, " ".join(["abandon"] * 23 + ["art"])):
        session = Session(encrypt, auto_read_back=False)
        session.wait_for(b"Original seed phrase")
        # The three-letter exact 'art' is deliberately left in lower
        # case.
        typed = abbreviated(phrase) if phrase == PHRASE else phrase.encode()
        session.answer(typed + ENTER, READ_BACK_PROMPT)
        shown = session.output[session.output.rfind(WRITTEN_OUT):]
        assert b"1. abandon" in shown, shown
        assert (b"about" if phrase == PHRASE else b"24. art") in shown, shown
        session.answer(ENTER, b"Container password")
        finish(session)
        summary = session.output[session.output.rfind(LEAVE_PRIVATE):]
        assert b"abandon" not in summary and WRITTEN_OUT not in summary, summary
    for term in ("xterm-256color", "dumb"):
        session = Session(("check", "--fingerprint", "--pim", "0"),
                          term=term, auto_read_back=False)
        session.wait_for(b"Container, 24 words")
        session.answer(abbreviated(CONTAINER) + ENTER, READ_BACK_PROMPT)
        shown = session.output[session.output.rfind(WRITTEN_OUT):]
        assert CONTAINER.split()[0].encode() in shown, shown
        session.answer(ENTER, b"Container password")
        finish(session)
    reader, writer = os.pipe()
    session = Session(encrypt, stdout=writer, term="dumb", auto_read_back=False)
    os.close(writer)
    session.wait_for(b"Original seed phrase")
    session.answer(abbreviated(PHRASE) + ENTER, b"accepted words were not shown",
                   b"Container password")
    assert b"abandon" not in session.output and WRITTEN_OUT not in session.output
    finish(session)
    os.close(reader)
    check_private_result_refusal()
    check_card_spelling()
    print("spelling: full words before continuing; secrets only on private screens")


def check_card_spelling():
    """The written-out repair words come from the repaired container."""
    made = subprocess.run([PROGRAM, "repair-words", "--stdin", "--count", "2"],
                          input=(CONTAINER + "\n").encode(), capture_output=True,
                          check=True)
    card = made.stdout.decode().strip()
    session = Session(("repair", "--pim", "0"), auto_read_back=False)
    session.wait_for(b"Container, 24 words")
    session.answer(CONTAINER.encode() + ENTER, b"Repair words")
    session.answer(abbreviated(card) + ENTER, READ_BACK_PROMPT)
    shown = session.output[session.output.rfind(WRITTEN_OUT):]
    assert all(word.encode() in shown for word in card.split()), shown
    finish(session)


def check_private_result_refusal():
    """No private result is printed on TERM=dumb before any work begins.
    """
    for command in (("password", "--chars", "16"), ("decrypt", "--pim", "0"),
                    ("encrypt", "--pim", "0"), ("rekey", "--pim", "0")):
        session = Session(command, term="dumb")
        session.wait_for(b"result only on a private screen")
        assert session.drain_until_exit(10), command
        code, settings = session.close()
        assert code == 2 and settings == session.original, command
        assert b"Original seed phrase" not in session.output, command
        assert b"Container, 24 words" not in session.output, command
    print("private results: TERM=dumb refused before input and work, exit 2")
