# TOOL-01: public fixtures and cases of the Python PTY test runtime.
"""The questions of `mhfe rekey` and `mhfe check` after the container.

`mhfe rekey` warns about other wallets on the old container and asks
nothing about them, and asks once, with no default, whether the wallet
has a BIP39 passphrase, as soon as the kind of confirmation is known;
with numbered answers at a terminal that cannot redraw a list. `mhfe
check` refuses an empty passphrase for the phrase + passphrase check.
Detecting the length leads to the passphrase question in check and to
the confirmation in rekey. On Linux the runs that go on stop at the
memory reservation, before Argon2.
"""

import os
import re
import sys

from .constants import (
    ADDRESS_ASKED,
    ANY_PASSPHRASE_ASKED,
    CANCELLED,
    CANCELLED_SHOWN,
    CLEAR,
    COIN_ASKED,
    COMPARE_ASKED,
    CONFIRMATION_ASKED,
    CONTAINER,
    CONTAINER_ASKED,
    CONTROL_SEQUENCE,
    CTRL_C,
    DOWN,
    ENTER,
    ESCAPE,
    FINGERPRINT_ASKED,
    HIGHLIGHT,
    KNOWN_PASSPHRASE_ASKED,
    LEAVE_PRIVATE,
    LIST_SHOWN,
    MARKED_HINT,
    MEMORY_REFUSED,
    NOT_ENOUGH_RESOURCES,
    NO_PASSPHRASE_RECORDED,
    NUMBERED_ANSWERS,
    NUMBERED_PROMPT,
    NUMBERED_REFUSED,
    PASSPHRASE_ANSWERS,
    PASSPHRASE_ASKED,
    PASSPHRASE_RECORDED,
    PASSPHRASE_REFUSED,
    PUBLIC_ADDRESS,
    PUBLIC_FINGERPRINT,
    PUBLIC_PASSPHRASE,
    REKEY_TITLE,
    SECRET,
    UNMARKED_HINT,
    UP,
    WALLET_CHECK_ENTRY,
    WALLET_CHECK_REFUSED,
)
from .session import Session, run_with_output, shown_privately, without_hints

# The warning of `mhfe rekey` about other wallets on the old container
# (src/bin/mhfe/rekey.rs).
OTHER_WALLETS_WARNING = (b"Wallets that other passwords open on the old container do not move to "
                         b"the new one: keep the old container and its passwords until you have "
                         b"moved their funds.",)


def rekey_warns_that_other_wallets_remain_in_the_old_container():
    # A PIM that is not the default is named among what to keep; the
    # default settings are not.
    for pim, warning in (("0", OTHER_WALLETS_WARNING),
                         ("2", (b"keep the old container, its passwords and PIM 2 until you have "
                                b"moved their funds.",))):
        label = f"rekey --pim {pim}"
        session = Session(("rekey", "--pim", pim, "--mem", "0", "--words", "24"))
        session.wait_for(CONTAINER_ASKED)
        code, settings = session.close()
        assert code == CANCELLED, f"{label}: exit code {code}"
        assert settings == session.original, f"{label}: terminal settings changed"
        before = re.sub(CONTROL_SEQUENCE, b"",
                        session.output[: session.output.find(CONTAINER_ASKED)])
        # Each wrapped line of a warning starts with its "!": compare
        # the words.
        words = re.sub(rb"\s+", b" ", re.sub(rb"(?m)^! ", b"", before.replace(b"\r", b"")))
        for line in warning:
            assert line in words, f"{label}: {line!r} is not shown above the container prompt"
        assert b"backed up another way?" not in session.output, (
            f"{label}: the old question was asked")
        assert b"Password" not in before, f"{label}: a password was asked first"
        print(f"{label}: the warning about other wallets heads the container prompt, "
              "nothing is asked")


# Why a rekey asks about the passphrase, the lines under the question
# (ASKS_WHY in
# src/bin/mhfe/rekey.rs).
PASSPHRASE_WHY = (b"Asked so that the list of what to keep at the end is complete:",
                  b"MHFE stores no passphrase. It asks for one only to compare an address",
                  b"or a fingerprint, or for the fingerprint to rehearse the new container.")
# The record of any answer about the passphrase, at the start of its
# line of the summary.
ANY_PASSPHRASE_RECORDED = rb"(?m)^  Passphrase "


def passphrase_question():
    """
    The question about the wallet's passphrase as a terminal shows it:
    the reason it is asked, indented, then after a blank line the link
    to the README section of `mhfe rekey`.
    """
    why = b"".join(b"\r\n  " + line for line in PASSPHRASE_WHY)
    return PASSPHRASE_ASKED + why + b"\r\n\r\n  More: https://github.com/hobby-eng/mhfe#mhfe-rekey"


def check_no_default(label, session):
    """The question about the passphrase, just shown as a list, has no
    answer marked and a hint that says so, and Enter alone leaves it as
    it is: nothing is redrawn, erased or recorded.
    """
    question = session.output.rfind(PASSPHRASE_ASKED)
    # The whole list first, up to the line break after its key hint, the
    # last thing it writes: the
    # hint of a list shown before may have passed for it.
    session.wait_for(LIST_SHOWN + b"\r\n", since=question)
    shown = session.output[question:]
    assert HIGHLIGHT not in shown, f"{label}: an answer to the passphrase question was marked"
    assert b"\r\n" + UNMARKED_HINT + b"\r\n" in shown, (
        f"{label}: the hint is not {UNMARKED_HINT!r}"
    )
    written = session.idle(ENTER)
    assert written == b"", f"{label}: Enter alone answered the passphrase question: {written!r}"


def rekey_at_old_password(words, capped):
    """
    Starts `mhfe rekey` for a phrase of `words` words, with the address
    space capped when `capped`, and answers up to the old container
    password.
    """
    session = Session(("rekey", "--pim", "0", "--words", words), capped=capped)
    session.wait_for(CONTAINER_ASKED)
    session.answer(CONTAINER.encode() + b"\r", b"container password: ")
    return session


def asked_next(label, session, since, typed=b""):
    """
    The question about the passphrase is the next screen after the keys
    typed at `since`: only `typed`, what the prompt before showed of
    them, the cleared screen and the title of the step come in between.
    No reference of the wallet, passphrase or memory for the long work
    was asked for before it.
    """
    question = session.output.find(PASSPHRASE_ASKED, since)
    between = re.sub(CONTROL_SEQUENCE, b"", without_hints(session.output[since:question]))
    between = between.replace(typed, b"").replace(REKEY_TITLE, b"")
    assert between.strip() == b"", f"rekey, {label}: {between!r} before the passphrase question"
    for prompt in (COIN_ASKED, ADDRESS_ASKED, FINGERPRINT_ASKED, ANY_PASSPHRASE_ASKED,
                   MEMORY_REFUSED):
        assert prompt not in session.output[:question], (
            f"rekey, {label}: {prompt!r} came before the passphrase question")


def give_the_reference(session, kind, select, then):
    """
    Answers the question about the passphrase with the keys `select` and
    types the reference of the wallet that the confirmation `kind`
    needs, if any; `then` is what the tool shows after the last of these
    keys.
    """
    if kind == "an address":
        # Bitcoin, the first coin, is marked at the start: Enter takes
        # it.
        steps = ((select, (COIN_ASKED, LIST_SHOWN)), (ENTER, (ADDRESS_ASKED,)),
                 (PUBLIC_ADDRESS + b"\r", then))
    elif kind == "the fingerprint":
        steps = ((select, (FINGERPRINT_ASKED,)), (PUBLIC_FINGERPRINT + b"\r", then))
    else:
        steps = ((select, then),)
    for keys, expected in steps:
        session.answer(keys, *expected)


def ended_before_argon2(label, session):
    """The capped rekey went on to the long work and was refused its
    memory, before Argon2; returns the summary on the main screen.
    """
    # The refusal is written once, at the end; it may have been read
    # with the last answer already.
    session.wait_for(MEMORY_REFUSED, since=0)
    assert session.drain_until_exit(10), f"rekey, {label}: the refusal did not end the tool"
    code, settings = session.close()
    assert code == NOT_ENOUGH_RESOURCES, f"rekey, {label}: exit code {code}"
    assert settings == session.original, f"rekey, {label}: terminal settings changed"
    return session.output[session.output.rfind(LEAVE_PRIVATE):]


def stopped_at_the_question(label, session):
    """
    Escape at the question about the passphrase, where a system without
    the address space cap stops a rekey before the long work.
    """
    session.answer(ESCAPE, CANCELLED_SHOWN)
    code, settings = session.close()
    assert code == CANCELLED, f"rekey, {label}: Escape gave exit code {code}"
    assert settings == session.original, f"rekey, {label}: terminal settings changed"
    print(f"rekey, {label}: asked, none marked; Escape stops, exit code 130")


def rekey_asks_about_the_wallet_passphrase_before_recovery():
    """
    The question about the wallet's passphrase comes once, right after
    the kind of confirmation is known, for every kind and before any
    reference or passphrase is read (multi-chain-wallet-tools
    AUD-022-API004). Only a wallet with a passphrase is then asked for
    it, and only with an address or the fingerprint; it may not be empty
    there.
    """
    capped = sys.platform == "linux"
    # On a screen of its own, as every step.
    asked = (CLEAR, passphrase_question(), *PASSPHRASE_ANSWERS, LIST_SHOWN)
    for kind, words, confirmation, mark, select, has_one in (
        # A 12-word phrase has a built-in check: nothing is chosen after
        # the password. ↓ marks the
        # first answer, which Enter then takes.
        ("the built-in check", "12", None, DOWN, ENTER, False),
        # A digit chooses at once.
        ("showing the phrase", "24", b"3", None, b"2", True),
        ("an address", "24", b"1", None, b"1", False),
        # ↑ marks the last answer.
        ("an address", "24", b"1", UP, ENTER, True),
        ("the fingerprint", "24", b"2", DOWN, ENTER, False),
        ("the fingerprint", "24", b"2", None, b"2", True),
    ):
        label = f"{kind}, {'with' if has_one else 'without'} a passphrase"
        answer = PASSPHRASE_ANSWERS[1 if has_one else 0]
        record = PASSPHRASE_RECORDED if has_one else NO_PASSPHRASE_RECORDED
        # Only a reference of the wallet is compared with a passphrase.
        asks_for_it = has_one and kind in ("an address", "the fingerprint")
        session = rekey_at_old_password(words, capped)
        if confirmation is None:
            start = len(session.output)
            session.answer(SECRET + b"\r", *asked)
            asked_next(label, session, start, typed=SECRET)
        else:
            session.answer(SECRET + b"\r", CONFIRMATION_ASKED, LIST_SHOWN)
            start = len(session.output)
            session.answer(confirmation, *asked)
            asked_next(label, session, start)
        check_no_default(f"rekey, {label}", session)
        if mark is not None:
            session.answer(mark, HIGHLIGHT + b" " + answer, MARKED_HINT)
        if not capped:
            stopped_at_the_question(label, session)
            continue
        give_the_reference(session, kind, select,
                           (KNOWN_PASSPHRASE_ASKED,) if asks_for_it else (MEMORY_REFUSED,))
        if asks_for_it:
            session.answer(b"\r", PASSPHRASE_REFUSED, KNOWN_PASSPHRASE_ASKED)
            session.answer(PUBLIC_PASSPHRASE + b"\r", MEMORY_REFUSED)
        summary = ended_before_argon2(label, session)
        if asks_for_it:
            assert b"if it has none" not in session.output, f"rekey, {label}: Enter for none"
            shown_privately(f"rekey, {label}", session.output, PUBLIC_PASSPHRASE)
        else:
            assert ANY_PASSPHRASE_ASKED not in session.output, (
                f"rekey, {label}: asked for a passphrase")
        assert record in summary, f"rekey, {label}: the summary lacks {record!r}"
        records = re.findall(ANY_PASSPHRASE_RECORDED, summary)
        assert len(records) == 1, f"rekey, {label}: {len(records)} Passphrase records, not one"
        assert PASSPHRASE_ASKED not in summary, f"rekey, {label}: the question reached the summary"
        # Recorded where it was asked: after the choice of the
        # confirmation, before the reference.
        if confirmation is not None:
            assert 0 <= summary.find(b"  Confirm ") < summary.find(record), (
                f"rekey, {label}: the answer is not recorded after the confirmation")
        first_of_reference = {"an address": b"  Coin ", "the fingerprint": b"  Master key "}
        if kind in first_of_reference:
            assert summary.find(record) < summary.find(first_of_reference[kind]), (
                f"rekey, {label}: the answer is not recorded before the reference")
        after = "an empty passphrase refused" if asks_for_it else "no passphrase prompt after it"
        print(f"rekey, {label}: asked first, none marked; {after}")
    if capped:
        print("rekey: one Passphrase record each, in the order asked; each stopped before Argon2")


def a_dumb_terminal_asks_rekey_choices_without_a_default():
    """A terminal that cannot redraw a list gets the question about the
    passphrase of `mhfe rekey` with numbered answers and a prompt
    without a default; an empty line, or a number out of range, is
    refused and the prompt asked again. A 12-word phrase has a built-in
    check, so the question follows the hidden old password. On Linux the
    capped run takes 2 and stops at the memory reservation, before
    Argon2; elsewhere Ctrl+C at the prompt ends it.
    """
    capped = sys.platform == "linux"
    session, reader = run_with_output(("rekey", "--pim", "0", "--words", "12"),
                                     redirected=True, term="dumb", capped=capped)
    session.wait_for(CONTAINER_ASKED)
    session.answer(CONTAINER.encode() + b"\r", b"Old container password (hidden): ")
    session.answer(SECRET + b"\r", PASSPHRASE_ASKED, *NUMBERED_ANSWERS, NUMBERED_PROMPT)
    shown = session.output[session.output.rfind(PASSPHRASE_ASKED):]
    assert b"[1]" not in shown, "rekey, TERM=dumb: the prompt offers a default"
    for typed in (b"", b"3"):
        session.answer(typed + b"\r", NUMBERED_REFUSED, NUMBERED_PROMPT)
    if capped:
        session.answer(b"2\r", MEMORY_REFUSED)
        expected, ending = NOT_ENOUGH_RESOURCES, "2 taken, stopped at the memory reservation"
    else:
        session.answer(CTRL_C, CANCELLED_SHOWN)
        expected, ending = CANCELLED, "Ctrl+C at the prompt ends it"
    assert session.drain_until_exit(10), "rekey, TERM=dumb: the tool did not end"
    code, settings = session.close()
    assert code == expected, f"rekey, TERM=dumb: exit code {code}"
    assert settings == session.original, "rekey, TERM=dumb: the terminal settings changed"
    assert SECRET not in session.output, "rekey, TERM=dumb: the password was shown"
    os.close(reader)
    print(
        "rekey, TERM=dumb: numbered answers, \"Choice: \" without a default, "
        "the password hidden"
    )
    print(f"rekey, TERM=dumb: an empty line and a number out of range refused; {ending}")


def a_wallet_check_requires_a_nonempty_passphrase():
    """`mhfe check` takes the phrase + passphrase check only with a
    passphrase (AUD-010).
    """
    capped = sys.platform == "linux"
    session = Session(("check", "--pim", "0"), capped=capped)
    session.wait_for(b"original seed phrase: ")
    session.answer(CONTAINER.encode() + b"\r", b"Container password: ")
    session.answer(SECRET + b"\r", COMPARE_ASKED, LIST_SHOWN)
    session.answer(WALLET_CHECK_ENTRY, KNOWN_PASSPHRASE_ASKED)
    session.answer(b"\r", WALLET_CHECK_REFUSED, KNOWN_PASSPHRASE_ASKED)
    assert b"if it has none" not in session.output, "check: Enter offered for no passphrase"
    if not capped:
        code, settings = session.close()
        assert code == CANCELLED, f"check, wallet check: Ctrl+C gave exit code {code}"
        assert settings == session.original, "check, wallet check: terminal settings changed"
        print("check: the phrase + passphrase check refuses an empty passphrase and asks again")
        return
    session.answer(PUBLIC_PASSPHRASE + b"\r", MEMORY_REFUSED)
    session.wait_for(MEMORY_REFUSED, since=0)
    assert session.drain_until_exit(10), "check, wallet check: the refusal did not end the tool"
    code, settings = session.close()
    assert code == NOT_ENOUGH_RESOURCES, f"check, wallet check: exit code {code}"
    assert settings == session.original, "check, wallet check: terminal settings changed"
    shown_privately("check, wallet check", session.output, PUBLIC_PASSPHRASE)
    summary = session.output[session.output.rfind(LEAVE_PRIVATE):]
    assert b"Passphrase typed" in summary, "check, wallet check: the passphrase was not recorded"
    print("check: the phrase + passphrase check refuses an empty passphrase, then takes one")


# The length of the original seed phrase detected (src/detection.rs in
# the library): the last
# answer of the question about the length, in check and rekey.
LENGTH_ASKED = b"How many words does your original seed phrase have?"
DETECT_OFFERED = b"Detect automatically"
ORIGINAL_PASSPHRASE_ASKED = b"Is a BIP39 passphrase used with the original seed phrase?"


def length_detection_requests_a_reference_when_checks_do_not_identify_it():
    """
    The question about the length offers detection last. In check, under
    the built-in check, it asks next whether a BIP39 passphrase is used
    with the original seed phrase, before the work; in rekey it asks how
    a 24-word phrase is confirmed, as for 24 words. On Linux the capped
    check stops at the memory reservation, before Argon2; Ctrl+C ends
    the rest.
    """
    capped = sys.platform == "linux"
    session = Session(("check", "--pim", "0"), capped=capped)
    session.wait_for(CONTAINER_ASKED)
    session.answer(CONTAINER.encode() + b"\r", b"Container password: ")
    session.answer(SECRET + b"\r", b"The container's built-in check", LIST_SHOWN)
    session.answer(b"3", LENGTH_ASKED, DETECT_OFFERED, LIST_SHOWN)
    session.answer(b"5", ORIGINAL_PASSPHRASE_ASKED, LIST_SHOWN)
    if capped:
        session.answer(b"1", MEMORY_REFUSED)
        assert session.drain_until_exit(10), "check, detected: it did not end"
    else:
        session.answer(CTRL_C, CANCELLED_SHOWN)
    session.close()
    print("check: the built-in check offers detection, then asks about the passphrase")

    session = Session(("rekey", "--pim", "0", "--mem", "0"))
    session.wait_for(CONTAINER_ASKED)
    session.answer(CONTAINER.encode() + b"\r", LENGTH_ASKED, DETECT_OFFERED, LIST_SHOWN)
    session.answer(b"6", b"Old container password")
    session.answer(SECRET + b"\r", CONFIRMATION_ASKED, LIST_SHOWN)
    session.answer(CTRL_C, CANCELLED_SHOWN)
    assert session.drain_until_exit(10), "rekey, detected: Ctrl+C did not end the tool"
    code, _ = session.close()
    assert code == CANCELLED, f"rekey, detected: exit code {code}"
    print("rekey: detection asks how a 24-word phrase is confirmed")
