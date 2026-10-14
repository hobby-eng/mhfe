"""The container password of `mhfe check`, and the passwords MHFE makes.

Every control character in a password is refused and never written back, a Unicode password and the
longest valid one are accepted, Backspace and Ctrl+U edit the line, and Ctrl+C cancels with exit
code 130, the private screen left and the terminal settings restored. A check word typed as ? or
wrong is repaired only on the person's choice; the words of the BIP39 and EFF lists are hinted
below the line; the summary states the isolation of a command started directly; and a password that
`mhfe encrypt` makes is shown once and typed back.
"""

import os
import re
import sys

from .constants import (ACCEPTED, BACKSPACE, CANCELLED, CANCELLED_SHOWN, CONTAINER,
                        CONTROL_SEQUENCE, CTRL_C, CTRL_U, ENTER, LEAVE_PRIVATE, LIST_SHOWN,
                        LONGEST, MEMORY_REFUSED, NOT_ENOUGH_RESOURCES, OTHER_CONTROLS, PHRASE,
                        REFUSED, REPAIR_ASKED, SECRET, TERMINAL_KEYS)
from .session import Session, shown_privately, typed_echo


def check_password_input():
    """Every control character in a password is refused and never written back, a Unicode password
    and the longest valid one are accepted, Backspace and Ctrl+U edit the line, and Ctrl+C at the
    password ends the tool with exit code 130, the private screen left."""
    for label, key in {**TERMINAL_KEYS, **OTHER_CONTROLS}.items():
        check_password(label, SECRET + key + b"x", REFUSED, not_shown=key)
        print(f"refused: a password with {label}")
    check_password("Unicode", SECRET + "пароль".encode(), ACCEPTED)
    print("accepted: a Unicode password")
    check_password("1024 x U+1D400", LONGEST, ACCEPTED)
    print("accepted: the longest valid password, 4096 bytes before normalization")
    # A TAB would be refused, so the password is accepted only if the key really deleted it.
    check_password("Backspace", SECRET + b"\t" + BACKSPACE, ACCEPTED)
    check_password("Ctrl+U", b"\t" + CTRL_U + SECRET, ACCEPTED)
    print("edited: Backspace and Ctrl+U at the password")

    session = Session()
    session.at_password_prompt()
    session.type(SECRET + CTRL_C)
    session.wait_for(CANCELLED_SHOWN)
    code, settings = session.close()
    assert code == CANCELLED, f"Ctrl+C: exit code {code}"
    assert settings == session.original, "Ctrl+C: the terminal settings were not restored"
    shown_privately("Ctrl+C", session.output, SECRET)
    print("cancelled: Ctrl+C at the password, exit code 130, private screen left, "
          "terminal restored")


def check_password(label, password, expected, not_shown=None):
    session = Session()
    try:
        session.at_password_prompt()
        prompt = len(session.output)
        session.type(password + b"\r")
        seen = session.wait_for(REFUSED, ACCEPTED)
        assert seen == expected, f"{label}: expected {expected!r}, the tool answered {seen!r}"
        if not_shown is not None:
            assert not_shown not in session.output[prompt:], f"{label}: the key was written back"
    finally:
        code, settings = session.close()
    if password.startswith(SECRET):
        shown_privately(label, session.output, SECRET)
    assert settings == session.original, f"{label}: the terminal settings were not restored"
    return code


# The third public vector of MHFE-PASSWORD-CHECK-1, and the question asked about its check word.
CHECK_WORD_PASSWORD = b"jovial trailing chokehold pavilion cresting ninth"
CHECK_WORD_ASKED = b"Repair the password with its check word?"


def check_check_word():
    session = Session()
    try:
        session.at_password_prompt()
        session.answer(CHECK_WORD_PASSWORD.replace(b"chokehold", b"?") + b"\r", CHECK_WORD_ASKED,
                       b"Word 3: chokehold", LIST_SHOWN)
        session.answer(ENTER, ACCEPTED)
    finally:
        code, settings = session.close()
    assert settings == session.original, "check word: the terminal settings were not restored"
    left = session.output.rfind(LEAVE_PRIVATE)
    record = b"Password   typed, word 3 repaired by its check word"
    assert record in session.output[left:], "check word: no record"
    assert b"chokehold" not in session.output[left:], "check word: a word reached the main screen"
    print("check word: a word typed as ? restored on Enter, recorded without the words")

    session = Session()
    try:
        session.at_password_prompt()
        wrong = CHECK_WORD_PASSWORD.replace(b"ninth", b"zoom")
        session.answer(wrong + b"\r", CHECK_WORD_ASKED, b"Word 6: ninth instead of zoom",
                       LIST_SHOWN)
        session.answer(b"2", b"Container password: ")
        session.answer(CHECK_WORD_PASSWORD + b"\r", ACCEPTED)
    finally:
        code, settings = session.close()
    assert settings == session.original, "check word: the terminal settings were not restored"
    left = session.output.rfind(LEAVE_PRIVATE)
    record = b"Password   typed, its check word fits"
    assert record in session.output[left:], "check word: a fit was not recorded"
    assert b"ninth" not in session.output[left:], "check word: a word reached the main screen"
    print("check word: a wrong word asked about, typed again, then the fit recorded")

    session = Session()
    try:
        session.at_password_prompt()
        # The stray space of a password typed in a hurry: the repair also removes it.
        typed = b" " + CHECK_WORD_PASSWORD.replace(b"chokehold", b"?")
        session.answer(typed + b"\r", CHECK_WORD_ASKED, b"Word 3: chokehold",
                       b"extra spaces removed", LIST_SHOWN)
        session.answer(ENTER, ACCEPTED)
    finally:
        code, settings = session.close()
    assert settings == session.original, "check word: the terminal settings were not restored"
    left = session.output.rfind(LEAVE_PRIVATE)
    record = b"Password   typed, word 3 repaired by its check word; extra spaces removed"
    assert record in session.output[left:], "check word: the corrected repair was not recorded"
    print("check word: a leading space removed together with the repair")


# The hints below a line of words or a password (typed_line.rs in the tool): how many words begin
# with one letter, the words that begin with two, and a word that no list has.
COUNT_HINT = b"136 BIP39 words begin with this letter"
WORDS_HINT = b"abandon   ability   able"
NO_WORD_HINT = b"No BIP39 word begins like this."
CLEAR_BELOW = b"\x1b[J"


def check_word_hints():
    """Below the container phrase, the words of the BIP39 list are hinted as they are typed: one
    letter gives how many begin with it, two the words. Tab completes a word, Ctrl+W deletes the
    last one, and a word no list has is said. The container typed with four letters of each word
    and Tab is the container. At the password, words of the EFF list are hinted, and Tab stays a
    character of the password. No hint is left on the main screen."""
    session = Session()
    session.wait_for(b"original seed phrase: ")
    session.answer(b"a", COUNT_HINT)
    session.answer(b"b", WORDS_HINT)
    session.answer(b"ou\t", b"about ")
    session.answer(b"xq", NO_WORD_HINT)
    session.answer(b"\x17\x17", CLEAR_BELOW)
    start = len(session.output)
    # Four letters of each longer word, then Tab: the whole word and a space. A shorter word may
    # begin a longer one, as "rib" begins "ribbon", so it is typed whole with its space.
    shortened = b"".join(word[:4] + b"\t" if len(word) >= 4 else word + b" "
                         for word in CONTAINER.encode().split())
    session.answer(shortened + b"\r", b"Container password: ")
    assert CONTAINER.encode() + b" " in typed_echo(session.output[start:]), (
        "hints: Tab did not complete the container")
    session.answer(b"jov", b"jovial")
    session.answer(b"\t", CLEAR_BELOW)
    code, settings = session.close()
    assert settings == session.original, "hints: the terminal settings were not restored"
    summary = session.output[session.output.rfind(LEAVE_PRIVATE):]
    for hint in (COUNT_HINT, b"jovial", NO_WORD_HINT):
        assert hint not in summary, f"hints: {hint!r} reached the main screen"
    print("hints: a count after one letter, the words after two, a word no list has said")
    print("hints: Tab completes the container from four letters a word; Ctrl+W deletes a word")
    print("hints: EFF words below the password, where Tab stays part of the password")


def user_namespaces_allowed():
    """Whether a process of this user may create a user namespace with an empty network, which
    some systems refuse; tried in a child, so that this process stays as it is."""
    if not hasattr(os, "unshare"):
        return False
    child = os.fork()
    if child == 0:
        try:
            os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNET)
        except OSError:
            os._exit(1)
        os._exit(0)
    _, status = os.waitpid(child, 0)
    return os.waitstatus_to_exitcode(status) == 0


def check_empty_network():
    """A command started directly runs in an empty network where the system allows it, and says
    so in its summary; elsewhere it runs on with the seccomp filter alone."""
    if sys.platform != "linux":
        return
    session = Session()
    try:
        session.at_password_prompt()
    finally:
        session.close()
    shown = re.sub(CONTROL_SEQUENCE, b"", session.output)
    allowed = user_namespaces_allowed()
    expected = (
        b"isolated network, no new sockets or file writes"
        if allowed
        else b"Isolation  no new sockets or file writes"
    )
    assert expected in shown, f"empty network: {expected!r} not in the summary"
    state = "an empty network" if allowed else "seccomp alone, as this system allows no namespace"
    print(f"isolation: a command started directly runs with {state}")


# The question of `mhfe encrypt`, `mhfe new` and `mhfe rekey` before a new password
# (made_password.rs in the tool), and what a password made asks and records.
PASSWORD_KIND_ASKED = b"The container password: type your own, or let MHFE make one?"
MADE_SHOWN = re.compile(rb"\r\n  ([a-z-]+(?: [a-z-]+){4})\r\n")
TYPED_BACK_ASKED = b"Password as you wrote it down: "
NOT_AS_SHOWN = b"That is not the password shown: correct your copy from the screen."
MADE_RECORDED = b"Password   made by MHFE: 5 words from the EFF list, about 64.6 bits."


def check_made_password():
    """`mhfe encrypt` offers a password made by MHFE: five dice words are shown once on a private
    screen, then typed back from the copy; a wrong copy shows the password again, the right one
    goes on. The summary records the kind and strength, never the words. On Linux the capped run
    then stops at the memory reservation, before Argon2; elsewhere Ctrl+C ends it at the
    reservation's place."""
    capped = sys.platform == "linux"
    session = Session(("encrypt", "--pim", "0"), capped=capped)
    session.wait_for(b"seed phrase: ")
    session.answer(PHRASE.encode() + b"\r", b"How long should", LIST_SHOWN)
    session.answer(ENTER, REPAIR_ASKED, LIST_SHOWN)
    session.answer(b"5", PASSWORD_KIND_ASKED, LIST_SHOWN)
    start = len(session.output)
    session.answer(b"2", b"Write it down now")
    shown = MADE_SHOWN.search(session.output[start:])
    assert shown, f"made password: none shown in {session.output[start:]!r}"
    made = shown.group(1)
    session.answer(ENTER, TYPED_BACK_ASKED)
    session.answer(made + b"x\r", NOT_AS_SHOWN, b"Write it down now")
    session.answer(ENTER, TYPED_BACK_ASKED)
    if capped:
        session.answer(made + b"\r", MEMORY_REFUSED)
        assert session.drain_until_exit(10), "made password: the refusal did not end the tool"
    else:
        session.answer(made + b"\r", b"Encrypting")
        session.answer(CTRL_C, CANCELLED_SHOWN)
        assert session.drain_until_exit(10), "made password: Ctrl+C did not end the tool"
    code, settings = session.close()
    assert code == (NOT_ENOUGH_RESOURCES if capped else CANCELLED), f"made password: code {code}"
    assert settings == session.original, "made password: the terminal settings changed"
    summary = session.output[session.output.rfind(LEAVE_PRIVATE):]
    assert MADE_RECORDED in summary, "made password: no record of it"
    assert made not in summary, "made password: the words reached the main screen"
    print("made password: shown once, typed back, a wrong copy shows it again; recorded by kind")
