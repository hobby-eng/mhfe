"""The repair of a container phrase, by its repair words or by a search for missing words.

Words typed as ? ask for the card, and the repaired container phrase is used only on "Use it", in
every command and in `mhfe repair`; a script gives the card with --repair. Without the card a
search uses an address or fingerprint of the container's own wallet: its reference records nothing
until it is read, a wrong passphrase finds nothing, two missing words are found by an address, and
a long search asks first.
"""

import sys

from .constants import (CANCELLED, CANCELLED_SHOWN, COIN_ASKED, CONTAINER, CONTAINER_ASKED, CTRL_C,
                        INVALID_INPUT, LEAVE_PRIVATE, LIST_SHOWN, MEMORY_REFUSED,
                        NOT_ENOUGH_RESOURCES, PHRASE, PUBLIC_PASSPHRASE, SECRET)
from .session import Session, run_plainly

# The repair of a container phrase where it is read (container_repair::review in the tool): the
# card asked for, the repaired container phrase shown, and the question before it is used. The
# card is the published four-word card of zero-12's container phrase (vectors/profiles).
CARD_HINT = b"Type the repair words as written on the card; ? for a word you cannot read."
CARD_ASKED = b"Repair words: "
ZERO_12_CARD = b"shaft pupil patient jewel"
REPAIRED_HEADING = b"Repaired container phrase, 24 words"
REPAIRED_SHOWN = b"Repaired words 3 and 17 of the container phrase."
USE_ASKED = b"Use the repaired container phrase?"
REPAIR_OFFERED = b"Type the container phrase again, or repair it?"
REPAIRED_RECORDED = b"Repaired   words 3 and 17 of the container phrase, with its repair words"


def container_with(changes):
    """Zero-12's container phrase with the words at the positions given, from 1, replaced."""
    words = CONTAINER.split(" ")
    for position, word in changes.items():
        words[position - 1] = word
    return " ".join(words).encode()


def check_repair_details(stderr, context):
    """The public repair example must name both positions, erasures and restored words."""
    for position, restored in ((3, b"tower"), (17, b"cycle")):
        line = next(line for line in stderr.splitlines()
                    if f"word {position:>2}".encode() in line)
        assert b"unreadable" in line and "→".encode() in line and restored in line, (
            f"{context}: missing erasure and replacement for word {position}: {line!r}")


def check_container_repair():
    """A container phrase with words typed as ? asks for its repair words at once; the repaired
    container phrase and every repaired word are shown on the private screen, and only "Use it"
    goes on, to the password, with "Repaired" in the summary and none of the words. Words that
    are not a container ask whether to type them again or repair them; Enter alone at the repair
    words goes back to the container phrase. A script gives the card on the line after the
    container phrase with --repair and is told on standard error what was repaired. All stop
    before Argon2: at the password, or at a fingerprint that is not one."""
    session = Session(("check", "--fingerprint", "--pim", "0"))
    session.wait_for(CONTAINER_ASKED)
    session.answer(container_with({3: "?", 17: "?"}) + b"\r", CARD_HINT, CARD_ASKED)
    session.answer(ZERO_12_CARD + b"\r", REPAIRED_HEADING, REPAIRED_SHOWN, USE_ASKED, LIST_SHOWN)
    session.answer(b"1", b"Container password: ")
    session.answer(CTRL_C, CANCELLED_SHOWN)
    assert session.drain_until_exit(10), "repair: Ctrl+C did not end the tool"
    code, settings = session.close()
    assert code == CANCELLED, f"repair: Ctrl+C gave exit code {code}"
    assert settings == session.original, "repair: the terminal settings changed"
    summary = session.output[session.output.rfind(LEAVE_PRIVATE):]
    assert b"Container  24 words, valid" in summary, "repair: no Container record"
    assert REPAIRED_RECORDED in summary, "repair: no Repaired record"
    for words in (ZERO_12_CARD, CONTAINER.split(" ")[2].encode(), USE_ASKED):
        assert words not in summary, f"repair: {words!r} reached the main screen"
    print("repair: ? asks for the card, shows the repaired words, uses them on \"Use it\"")

    session = Session(("check", "--fingerprint", "--pim", "0"))
    session.wait_for(CONTAINER_ASKED)
    session.answer(container_with({9: "towr"}) + b"\r", b"word 9 is not in the", REPAIR_OFFERED,
                   LIST_SHOWN)
    session.answer(b"1", CONTAINER_ASKED)
    session.answer(container_with({9: "towr"}) + b"\r", REPAIR_OFFERED, LIST_SHOWN)
    session.answer(b"2", CARD_ASKED)
    start = len(session.output)
    session.answer(b"\r", CONTAINER_ASKED)
    assert REPAIRED_HEADING not in session.output[start:], "repair: Enter alone repaired"
    session.answer(CONTAINER.encode() + b"\r", b"Container password: ")
    session.answer(CTRL_C, CANCELLED_SHOWN)
    assert session.drain_until_exit(10), "repair, typo: Ctrl+C did not end the tool"
    code, settings = session.close()
    assert code == CANCELLED, f"repair, typo: Ctrl+C gave exit code {code}"
    assert settings == session.original, "repair, typo: the terminal settings changed"
    summary = session.output[session.output.rfind(LEAVE_PRIVATE):]
    assert b"Repaired" not in summary, "repair, typo: a repair was recorded"
    print("repair: a typo offers \"Type it again\" or the card; Enter alone at the card goes back")

    lines = b"\n".join((container_with({3: "?", 17: "?"}), ZERO_12_CARD, SECRET, b"zz",
                        b"")) + b"\n"
    result = run_plainly(("check", "--stdin", "--repair", "--fingerprint"), lines,
                         capped=sys.platform == "linux")
    assert result.returncode == INVALID_INPUT, f"repair, script: exit code {result.returncode}"
    assert REPAIRED_SHOWN in result.stderr, f"repair, script: {result.stderr!r}"
    check_repair_details(result.stderr, "repair, script")
    assert result.stdout == b"", "repair, script: wrote to standard output"
    print("repair, script: --repair reads the card after the container phrase, "
          "says what it repaired")


# `mhfe repair` reads and repairs a container phrase as every command does (container_repair and
# container_search in the tool), then shows the repaired container phrase on a private screen.
REPAIR_RESULT = b"Repaired container, 24 words"
WRITE_IT_DOWN = b"Write it down now: Enter or Escape clears this screen."


def check_repair_command():
    """`mhfe repair` repairs a container phrase with its card and shows it after "Use it"; Enter
    alone at the card searches for a word typed as ?, here by the decoy fingerprint without a
    password, and the found container phrase is shown the same way. A script gives the container
    phrase and the card, one per line, and gets the repaired container phrase on standard output."""
    session = Session(("repair",))
    session.wait_for(CONTAINER_ASKED)
    session.answer(container_with({3: "?", 17: "?"}) + b"\r", CARD_HINT, CARD_ASKED)
    session.answer(ZERO_12_CARD + b"\r", REPAIRED_HEADING, REPAIRED_SHOWN, USE_ASKED, LIST_SHOWN)
    session.answer(b"1", REPAIR_RESULT, WRITE_IT_DOWN)
    session.answer(b"\r", b"Next")
    assert session.drain_until_exit(10), "repair command: it did not end"
    code, settings = session.close()
    assert code == 0, f"repair command: exit code {code}"
    assert settings == session.original, "repair command: the terminal settings changed"
    summary = session.output[session.output.rfind(LEAVE_PRIVATE):]
    assert REPAIRED_RECORDED in summary, "repair command: no Repaired record"
    print("repair command: the card repairs the container phrase, shown after \"Use it\"")

    session = Session(("repair",))
    session.wait_for(CONTAINER_ASKED)
    session.answer(container_with({24: "?"}) + b"\r", CARD_ASKED)
    session.answer(b"\r", SEARCH_ASKED, b"1 to 5 at once")
    session.answer(b"1", REFERENCE_ASKED)
    session.answer(ZERO_12_DECOY_FINGERPRINT + b"\r", CONTAINER_PASSPHRASE_ASKED, LIST_SHOWN)
    session.answer(b"1", FOUND_SHOWN, FOUND_USE_ASKED, LIST_SHOWN)
    session.answer(b"1", REPAIR_RESULT, WRITE_IT_DOWN)
    session.answer(b"\r", b"Next")
    assert session.drain_until_exit(10), "repair command, search: it did not end"
    code, _ = session.close()
    assert code == 0, f"repair command, search: exit code {code}"
    summary = session.output[session.output.rfind(LEAVE_PRIVATE):]
    assert FOUND_RECORDED in summary, "repair command, search: no record of the search"
    assert b"peace" not in summary, "repair command, search: the found word reached the summary"
    print("repair command: without the card, the decoy fingerprint finds the missing word")

    lines = b"\n".join((container_with({3: "?", 17: "?"}), ZERO_12_CARD)) + b"\n"
    result = run_plainly(("repair", "--stdin"), lines)
    assert result.returncode == 0, f"repair command, script: exit code {result.returncode}"
    assert result.stdout.strip() == CONTAINER.encode(), f"repair, script: {result.stdout!r}"
    assert REPAIRED_SHOWN in result.stderr, f"repair command, script: {result.stderr!r}"
    check_repair_details(result.stderr, "repair command, script")
    print("repair command, script: the repaired container phrase on standard output")


# The search for missing words without the repair words (container_search.rs in the tool). The
# decoy fingerprint of zero-12's container phrase, computed by an independent Python
# implementation (src/search/known_answers.rs), finds its last word in seconds.
SEARCH_ASKED = b"No repair words: what do you know?"
REFERENCE_ASKED = b"Address or master key fingerprint: "
CONTAINER_PASSPHRASE_ASKED = b"Is a BIP39 passphrase used with the container phrase?"
CONTAINER_PASSPHRASE_TYPED = b"BIP39 passphrase of the container phrase: "
NOT_IN_CONTAINER_WALLET = b"The container's own wallet does not match"
ZERO_12_DECOY_FINGERPRINT = b"487a156e"
FOUND_SHOWN = b"Found word 24: peace, with the container's own wallet."
FOUND_USE_ASKED = b"Use the found container phrase?"
FOUND_RECORDED = b"Repaired   word 24 of the container phrase, found by a search"
LONG_SEARCH_WARNED = b"8 candidates, each a full recovery: about 8 to 16 minutes at these"
TWO_EXPLAINED = b"Two words are missing: only a fingerprint or an address of the"
# A nested SegWit address of zero-12's container phrase as a wallet, at m/49'/0'/0'/0/9, derived
# by an independent Python implementation of BIP32 and P2SH-P2WPKH.
ZERO_12_DECOY_ADDRESS = b"3FWJwUxDaXoGrxZQHT4EHBDZCZw7iHUaRn"
GAP_ASKED = b"How far does the wallet go?"
TWO_FOUND = b"Found word 5: iron, word 16: nerve, with the container's own wallet."


def check_search_reference_is_recorded_once_read():
    """The one field of a search's reference records nothing on the main screen before the text is
    read as a fingerprint or an address of the coin asked: a seed phrase typed there is refused as
    several words, and a word with control characters that is no address is never recorded
    (AUD-015-SEC001)."""
    session = Session(("check", "--fingerprint", "--pim", "0"))
    session.wait_for(CONTAINER_ASKED)
    session.answer(container_with({24: "?"}) + b"\r", CARD_ASKED)
    session.answer(b"\r", SEARCH_ASKED)
    session.answer(b"1", REFERENCE_ASKED)
    session.answer(PHRASE.encode() + b"\r", b"without spaces", REFERENCE_ASKED)
    marked = b"bc1\x1b]0;AUD015\x07zz"
    session.answer(marked + b"\r", COIN_ASKED, LIST_SHOWN)
    session.answer(CTRL_C, CANCELLED_SHOWN)
    assert session.drain_until_exit(10), "search reference: Ctrl+C did not end the tool"
    code, settings = session.close()
    assert code == CANCELLED, f"search reference: Ctrl+C gave exit code {code}"
    assert settings == session.original, "search reference: the terminal settings changed"
    summary = session.output[session.output.rfind(LEAVE_PRIVATE):]
    assert PHRASE.encode() not in summary, "search reference: the phrase reached the main screen"
    assert b"AUD015" not in summary, "search reference: the typed text reached the main screen"
    assert b"Reference" not in summary, "search reference: recorded before it was read"
    print("search: the reference field records nothing until it is read; a phrase is refused")


def check_container_search():
    """Enter alone at the repair words of a container phrase with a word typed as ? asks what is
    known: an address or fingerprint of the container's own wallet, read in one field, its BIP39
    passphrase only after "Is a BIP39 passphrase used with the container phrase?". zero-12's decoy
    fingerprint finds its last word without a password, shown with the found container phrase,
    used only after "Use it"; the password follows, and the summary records the search, never the
    word. A passphrase the container phrase does not have finds nothing, and the question comes
    again. Two missing words offer only the container's own wallet: its address, at the gap
    chosen, finds both; a gap of one's own is typed. "Not now" before a long search asks again;
    on Linux the capped run then takes the password and stops at the memory reservation."""
    session = Session(("check", "--fingerprint", "--pim", "0"))
    session.wait_for(CONTAINER_ASKED)
    session.answer(container_with({24: "?"}) + b"\r", CARD_ASKED)
    session.answer(b"\r", SEARCH_ASKED, b"1 to 5 at once")
    # A passphrase the container phrase is not used with: nothing matches, the question comes
    # again.
    session.answer(b"1", REFERENCE_ASKED)
    session.answer(ZERO_12_DECOY_FINGERPRINT + b"\r", CONTAINER_PASSPHRASE_ASKED, LIST_SHOWN)
    session.answer(b"2", CONTAINER_PASSPHRASE_TYPED)
    session.answer(PUBLIC_PASSPHRASE + b"\r", NOT_IN_CONTAINER_WALLET, SEARCH_ASKED)
    session.answer(b"1", REFERENCE_ASKED)
    session.answer(ZERO_12_DECOY_FINGERPRINT + b"\r", CONTAINER_PASSPHRASE_ASKED, LIST_SHOWN)
    session.answer(b"1", b"Found container phrase, 24 words", FOUND_SHOWN, FOUND_USE_ASKED,
                   LIST_SHOWN)
    session.answer(b"1", b"Container password: ")
    session.answer(CTRL_C, CANCELLED_SHOWN)
    assert session.drain_until_exit(10), "search: Ctrl+C did not end the tool"
    code, settings = session.close()
    assert code == CANCELLED, f"search: Ctrl+C gave exit code {code}"
    assert settings == session.original, "search: the terminal settings changed"
    summary = session.output[session.output.rfind(LEAVE_PRIVATE):]
    assert FOUND_RECORDED in summary, "search: no record of the search"
    assert b"peace" not in summary, "search: the found word reached the main screen"
    print("search: the decoy fingerprint finds the missing word; a wrong passphrase asks again")

    # Two missing words: only the container's own wallet; its address among the first 20.
    session = Session(("check", "--fingerprint", "--pim", "0"))
    session.wait_for(CONTAINER_ASKED)
    session.answer(container_with({5: "?", 16: "?"}) + b"\r", CARD_ASKED)
    # Two missing words make about 4 million combinations to list first: seconds in a release
    # build, longer in a debug one.
    session.answer(b"\r", SEARCH_ASKED, TWO_EXPLAINED, b"1 or 2 at once", limit=120)
    session.answer(b"1", REFERENCE_ASKED)
    session.answer(ZERO_12_DECOY_ADDRESS + b"\r", COIN_ASKED, LIST_SHOWN)
    session.answer(b"\r", GAP_ASKED, LIST_SHOWN)
    session.answer(b"1", b"0-1/0-19, 40 addresses", CONTAINER_PASSPHRASE_ASKED, LIST_SHOWN)
    session.answer(b"1", TWO_FOUND, FOUND_USE_ASKED, limit=600)
    session.close()
    print("search: two words found by an address of the container's own wallet")

    # A gap of the person's own: a number that is not one is asked again, and the scope stated
    # follows the number taken.
    session = Session(("check", "--fingerprint", "--pim", "0"))
    session.wait_for(CONTAINER_ASKED)
    session.answer(container_with({5: "?", 16: "?"}) + b"\r", CARD_ASKED)
    session.answer(b"\r", SEARCH_ASKED, TWO_EXPLAINED, limit=120)
    session.answer(b"1", REFERENCE_ASKED)
    session.answer(ZERO_12_DECOY_ADDRESS + b"\r", COIN_ASKED, LIST_SHOWN)
    session.answer(b"\r", GAP_ASKED, LIST_SHOWN)
    session.answer(b"4", b"Addresses of each chain: ")
    session.answer(b"0\r", b"Type a whole number of addresses", b"Addresses of each chain: ")
    session.answer(b"30\r", b"0-1/0-29, 60 addresses", CONTAINER_PASSPHRASE_ASKED)
    session.close()
    print("search: a gap of one's own is typed, refused when it is not a number of addresses")

    capped = sys.platform == "linux"
    session = Session(("check", "--fingerprint", "--pim", "0"), capped=capped)
    session.wait_for(CONTAINER_ASKED)
    session.answer(container_with({24: "?"}) + b"\r", CARD_ASKED)
    session.answer(b"\r", SEARCH_ASKED, b"1 to 5 at once")
    # "Not now" goes back to the question, not to the container phrase.
    session.answer(b"4", LONG_SEARCH_WARNED, b"Start the search?", LIST_SHOWN)
    session.answer(b"2", SEARCH_ASKED, b"1 to 5 at once")
    session.answer(b"4", LONG_SEARCH_WARNED, b"Start the search?", LIST_SHOWN)
    if not capped:
        code, settings = session.close()
        assert settings == session.original, "search, nothing known: terminal settings changed"
        print("search: nothing known says how long it takes; \"Not now\" asks again")
        return
    session.answer(b"1", b"Container password: ")
    session.answer(SECRET + b"\r", MEMORY_REFUSED)
    assert session.drain_until_exit(10), "search, nothing known: the refusal did not end the tool"
    code, settings = session.close()
    assert code == NOT_ENOUGH_RESOURCES, f"search, nothing known: exit code {code}"
    assert settings == session.original, "search, nothing known: terminal settings changed"
    print("search: nothing known says how long it takes; \"Not now\" asks again")
