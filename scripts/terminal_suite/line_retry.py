# TOOL-01: public fixtures and cases of the Python PTY test runtime.
"""A refused line keeps its frame even when a paste pauses before Enter.
"""

import sys

from .constants import (
    ANY_PASSPHRASE_ASKED, CANCELLED, CONTAINER, ENTER,
    FINGERPRINT_ASKED, INVALID_INPUT, KNOWN_PASSPHRASE_ASKED,
    MEMORY_REFUSED, NOT_ENOUGH_RESOURCES, PHRASE, SECRET,
)
from .session import Session, run_plainly


def refused_lines_start_again_without_control_characters():
    """A valid phrase appended to an over-long line cannot become a new
    answer.
    """
    session = Session(("encrypt", "--pim", "0", "--mem", "0",
                       "--same-length", "no", "--repair-words", "0",
                       "--new-password", "own"))
    session.wait_for(b"Original seed phrase")
    session.answer(b"a" * 8193, b"An answer is longer than")
    # This pause exceeds the previous quiet-period drain's 100 ms.
    following = session.idle(PHRASE.encode() + ENTER, 0.5)
    assert b"Container password" not in following, "a refused line's suffix became an answer"
    assert b"Original seed phrase" in following, following
    session.answer(PHRASE.encode() + ENTER, b"Container password")
    code, settings = session.close()
    assert code == CANCELLED and settings == session.original, code
    print("line retry: a delayed suffix is discarded; the next complete answer is accepted")


def public_input_refusals_retry_before_any_recovery():
    """Encoding and passphrase refusals keep earlier answers."""
    expanding = ("\ufdfa" * 341 + "a").encode()
    contracting = ("\uff21" * 341 + "aa").encode()
    assert len(expanding) == 1024 and len(contracting) == 1025
    for named, accepted in [(False, expanding), (False, b""), (True, expanding)]:
        option = "--wallet-check" if named else "--fingerprint"
        capped = sys.platform == "linux"
        session = Session(("check", option, "--pim", "0", "--mem", "0"), capped=capped)
        prompt = KNOWN_PASSPHRASE_ASKED if named else ANY_PASSPHRASE_ASKED
        try:
            session.at_password_prompt()
            session.answer(SECRET + ENTER, prompt if named else FINGERPRINT_ASKED)
            if not named:
                session.answer(b"not-a-fingerprint" + ENTER, FINGERPRINT_ASKED)
                session.answer(b"\xff" + ENTER, b"not valid UTF-8", FINGERPRINT_ASKED)
                session.answer(b"00000000" + ENTER, prompt)
            else:
                session.answer(ENTER, b"check needs one", prompt)
            for excessive in (b"a" * 1025, contracting):
                session.answer(excessive + ENTER, b"passphrase is too long", b"1025 bytes", prompt)
            assert b"Recovering" not in session.output, "recovery began before admission"
            if capped:
                session.answer(accepted + ENTER, MEMORY_REFUSED)
                assert session.drain_until_exit(10), "the bounded reservation refusal did not end"
        finally:
            code, settings = session.close()
        assert code == (NOT_ENOUGH_RESOURCES if capped else CANCELLED), code
        assert settings == session.original, "input retry changed terminal settings"
    for fingerprint, passphrase in [(b"\xff", b""), (b"00000000", b"a" * 1025)]:
        data = b"\n".join([CONTAINER.encode(), SECRET, fingerprint, passphrase]) + b"\n"
        result = run_plainly(
            ("check", "--stdin", "--fingerprint", "--pim", "0", "--mem", "0"), data)
        assert result.returncode == INVALID_INPUT, result.returncode
        assert b"Recovering" not in result.stderr
    print("input retry: invalid visible UTF-8 and long raw passphrases retry; scripts fail early")
