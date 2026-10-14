# TOOL-01: public fixtures and cases of the Python PTY test runtime.
"""A refused line keeps its frame even when a paste pauses before Enter.
"""

from .constants import CANCELLED, ENTER, PHRASE
from .session import Session


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
