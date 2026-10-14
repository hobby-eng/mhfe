"""The menu of `mhfe`, and the lists and private screens of `mhfe encrypt` and `mhfe new`.

The menu's keys choose, do nothing or quit, and its password entry makes passwords on private
screens. `mhfe encrypt` asks its lists on cleared screens and nothing about a BIP39 passphrase,
also at a terminal that cannot redraw a list, where a password made by MHFE is refused. `mhfe new`
and `mhfe wallets` show a phrase only on a private screen; `mhfe new` asks about a wallet check
with no answer marked, takes a chosen word privately, and its quit keys leave the private screen. A
dumb terminal gets no hints, and keys typed ahead clear no screen.
"""

import os
import re
import signal
import time

from .constants import (AMPLE, BACKSPACE, BACK_TO_MENU, BAD_CHECKSUM, CANCELLED, CANCELLED_SHOWN,
                        CHECK_ANSWERS, CHECK_ASKED, CHECK_EXPLAINED, CHECK_MARKED_HINT,
                        CHECK_RECORDED, CHECK_UNMARKED_HINT, CHOSEN_ASKED, CHOSEN_RECORDED,
                        CHOSEN_WORD_ASKED, CLEAR, CONTAINER, CONTAINER_ASKED, CTRL_C, CTRL_UP,
                        DOWN, ENTER, ENTER_PRIVATE, ESCAPE, EXPLAINED, HELP_FROM_PASSWORD,
                        HIGHLIGHT, IGNORED_KEY, INVALID_INPUT, LEAVE_PRIVATE, LENGTH_RECORDED,
                        LIST_SHOWN, MENU_SHOWN, NEVER_USE_ASKED, NUMBERED_PROMPT, OWN_SETTINGS,
                        PASSPHRASE_ASKED, PASSWORD_AGAIN, PASSWORD_ENTRY, PASSWORD_KIND,
                        PASSWORD_MADE, PHRASE, PHRASE_RECORDED, PLACE_ASKED, PLACE_REFUSED,
                        RECOGNISABLE, REPAIR_ASKED, REPAIR_RECORDED, SECRET, SETTINGS_ASKED, UP)
from .passwords import PASSWORD_KIND_ASKED
from .recovery import ANY_PASSPHRASE_RECORDED
from .repair import CARD_ASKED, container_with
from .session import Session, shown_privately


def check_menu():
    session = Session(arguments=())
    session.wait_for(MENU_SHOWN)
    moves = DOWN * PASSWORD_ENTRY + UP
    # The password and the prompt arrive together; the count of passwords is checked at the end.
    session.answer(IGNORED_KEY + CTRL_UP + moves + ENTER, PASSWORD_KIND)
    session.answer(ENTER, PASSWORD_AGAIN)
    for _ in range(2):
        session.answer(ENTER, PASSWORD_AGAIN)
    session.answer(ESCAPE, MENU_SHOWN)
    # The second time, random characters.
    session.answer(str(PASSWORD_ENTRY).encode(), PASSWORD_KIND)
    session.answer(b"3", b"random characters", PASSWORD_AGAIN)
    session.answer(b"q", MENU_SHOWN)
    # The menu keeps the password entry highlighted after it.
    session.answer(DOWN * HELP_FROM_PASSWORD + ENTER, BACK_TO_MENU)
    session.answer(ENTER, MENU_SHOWN)
    session.press(b"q")
    # The tool needs a moment to end; close() would send Ctrl+C to a tool that is still running.
    assert session.drain_until_exit(10), "menu: q did not end the tool"
    code, settings = session.close()
    assert code == 0, f"menu: q gave exit code {code}"
    assert settings == session.original, "menu: the terminal settings were not restored"
    assert session.output.count(PASSWORD_MADE) == 4, "menu: passwords were not regenerated"
    # One private screen each time the entry is chosen; it is cleared on entering and on leaving,
    # and once more before each password made again.
    assert session.output.count(ENTER_PRIVATE) == 2, "menu: passwords did not use private screens"
    assert session.output.count(LEAVE_PRIVATE) == 2, "menu: password screens were not left"
    assert session.output.count(CLEAR) == 6, "menu: a password was not replaced by the next"
    # A password of random characters may hold the key's letter; nothing else may.
    shown = re.sub(rb"(?m)^  [2-9A-HJ-NP-Za-km-z]{16}\r?$", b"", session.output)
    assert IGNORED_KEY not in shown, "menu: a key was shown"
    print("menu: password regeneration, Escape/q return, private screens cleared, "
          "terminal restored")
    print("menu: the password entry asks for words or characters and makes both")

    # Escape alone: the tool waits a moment for the rest of an arrow key's sequence, then quits.
    session = Session(arguments=())
    session.wait_for(MENU_SHOWN)
    session.press(ESCAPE)
    assert session.drain_until_exit(10), "menu: Escape did not end the tool"
    code, settings = session.close()
    assert code == 0, f"menu: Escape gave exit code {code}"
    assert settings == session.original, "menu: Escape did not restore the terminal settings"
    print("menu: a lone Escape quits, exit code 0, terminal restored")

    session = Session(arguments=())
    session.wait_for(MENU_SHOWN)
    session.type(CTRL_C)
    session.wait_for(CANCELLED_SHOWN)
    code, settings = session.close()
    assert code == CANCELLED, f"menu: Ctrl+C gave exit code {code}"
    assert settings == session.original, "menu: Ctrl+C did not restore the terminal settings"
    print("menu: Ctrl+C, exit code 130, terminal restored")


def check_encrypt_lists():
    session = Session(arguments=("encrypt",))
    # Nothing typed yet: this waits for the whole first question, its link and its list.
    session.answer(b"", SETTINGS_ASKED, LIST_SHOWN)
    session.answer(b"2", b"PIM: ")
    session.answer(b"x\r", b"whole number", b"PIM: ")
    session.answer(b"1\r", b"Memory level: ")
    session.answer(b"0\r", b"seed phrase: ")
    # Twelve times the first word fails the checksum; the phrase is asked again.
    session.answer(BAD_CHECKSUM + b"\r", b"Please type it again", b"seed phrase: ")
    # A valid phrase is taken at once, without a question; the next step clears the screen.
    session.answer(PHRASE.encode() + b"\r", CLEAR, b"How long should", LIST_SHOWN)
    session.answer(b"?", EXPLAINED, LIST_SHOWN)
    # Nothing is asked about a passphrase: the length is followed by the repair words.
    session.answer(IGNORED_KEY + DOWN + UP + ENTER, CLEAR, REPAIR_ASKED, LIST_SHOWN)
    # No repair words: they would appear only after the encryption, which this test never reaches.
    session.answer(b"5", PASSWORD_KIND_ASKED, LIST_SHOWN)
    # The person's own password, the first answer.
    session.answer(b"1", b"Container password: ")
    session.answer(SECRET + b"\r", b"Repeat the container password: ")
    session.answer(SECRET + CTRL_C, CANCELLED_SHOWN)
    assert session.drain_until_exit(10), "encrypt: Ctrl+C did not end the tool"
    code, settings = session.close()
    assert code == CANCELLED, f"encrypt: Ctrl+C gave exit code {code}"
    assert settings == session.original, "encrypt: the terminal settings were not restored"
    shown_privately("encrypt", session.output, SECRET)
    assert IGNORED_KEY not in session.output, "encrypt: a key was shown"
    # The steps stayed on the alternate screen; the main screen got the summary when it ended.
    summary = session.output[session.output.rfind(LEAVE_PRIVATE):]
    records = (OWN_SETTINGS, PHRASE_RECORDED, LENGTH_RECORDED, REPAIR_RECORDED)
    for record in records:
        assert record in summary, f"encrypt: the summary lacks {record!r}"
    places = [summary.find(record) for record in records]
    assert places == sorted(places), "encrypt: the summary is not in the order of the questions"
    for step in (b"How long should", b"seed phrase: ", EXPLAINED):
        assert step not in summary, f"encrypt: {step!r} reached the main screen"
    assert PASSPHRASE_ASKED not in session.output, "encrypt: asked about the passphrase"
    assert not re.search(ANY_PASSPHRASE_RECORDED, summary), "encrypt: a Passphrase record"
    print("encrypt: own settings; phrase refused once, then taken at once; ? and the arrows")
    print("encrypt: nothing asked about a passphrase; the summary has no Passphrase record")
    print("encrypt: password shown only on the alternate screen; Ctrl+C leaves it, exit code 130")
    print("encrypt: every step on a cleared screen; only the summary on the main screen")

    session = Session(arguments=("encrypt",))
    session.answer(b"", SETTINGS_ASKED, LIST_SHOWN)
    session.answer(ESCAPE, CANCELLED_SHOWN)
    assert session.drain_until_exit(10), "encrypt: Escape did not end the tool"
    code, settings = session.close()
    assert code == CANCELLED, f"encrypt: Escape gave exit code {code}"
    assert settings == session.original, "encrypt: Escape did not restore the terminal settings"
    print("encrypt: Escape at a list cancels, exit code 130, terminal restored")


def check_encrypt_numbered():
    """A terminal that cannot redraw a list gets no question between the hidden phrase and the
    hidden password: nothing is asked about the passphrase. The settings are given, so the hidden
    phrase is the first answer; the container keeps 24 words and no repair words are asked, as
    neither can be a list there."""
    session = Session(("encrypt", "--pim", "0"), term="dumb")
    session.wait_for(b"Original seed phrase (hidden): ")
    start = len(session.output)
    session.answer(PHRASE.encode() + b"\r", b"Container password (hidden): ")
    between = session.output[start:]
    for asked in (PASSPHRASE_ASKED, NUMBERED_PROMPT):
        assert asked not in between, f"encrypt, TERM=dumb: {asked!r} before the password"
    session.answer(CTRL_C, CANCELLED_SHOWN)
    assert session.drain_until_exit(10), "encrypt, TERM=dumb: Ctrl+C did not end the tool"
    code, settings = session.close()
    assert code == CANCELLED, f"encrypt, TERM=dumb: Ctrl+C gave exit code {code}"
    assert settings == session.original, "encrypt, TERM=dumb: the terminal settings changed"
    assert PHRASE.encode() not in session.output, "encrypt, TERM=dumb: the phrase was shown"
    print("encrypt, TERM=dumb: the hidden password right after the hidden phrase, "
          "the phrase hidden")
    # A password made by MHFE needs a private screen, which TERM=dumb has none of: refused before
    # anything is asked (AUD-015-SEC003).
    for command in (("encrypt", "--pim", "0"), ("rekey", "--pim", "0")):
        session = Session((*command, "--new-password", "words"), term="dumb")
        session.wait_for(b"shown only on a private screen")
        assert session.drain_until_exit(10), f"{command[0]}, TERM=dumb: the refusal did not end"
        code, settings = session.close()
        assert code == INVALID_INPUT, f"{command[0]} --new-password words, TERM=dumb: exit {code}"
        assert settings == session.original, f"{command[0]}, TERM=dumb: terminal settings changed"
        assert b"Original seed phrase" not in session.output, f"{command[0]}: asked first"
    print("encrypt and rekey, TERM=dumb: a made password is refused before anything is asked")


def run_with_output(arguments, redirected=False, term=None):
    """Starts the tool with standard output in a pipe when `redirected`; returns the session and
    the read end of the pipe, or None."""
    if not redirected:
        return Session(arguments, term=term), None
    reader, writer = os.pipe()
    session = Session(arguments, stdout=writer, term=term)
    # The tool holds its own copy; the pipe ends once the tool has ended.
    os.close(writer)
    return session, reader


def piped_output(reader):
    """Everything the tool wrote to standard output, read once it has ended."""
    data = b""
    while chunk := os.read(reader, 65536):
        data += chunk
    os.close(reader)
    return data


def other_terminal_output(leader):
    """Everything the tool wrote to a second terminal, read once it has ended. A pseudo-terminal
    whose other end is closed reports an error instead of the end of the data."""
    os.set_blocking(leader, False)
    data = b""
    try:
        while chunk := os.read(leader, 65536):
            data += chunk
    except OSError:
        pass
    os.close(leader)
    return data


def check_private_reveals():
    refused = b"only on a private screen"
    for command in ("new", "wallets"):
        for label, redirected, term in (("standard output in a pipe", True, None),
                                        ("TERM=dumb", False, "dumb")):
            session, reader = run_with_output((command, "--pim", "0"), redirected, term)
            session.wait_for(refused)
            # The refusal ends the tool by itself. The needle stands mid-line, so the tool may
            # still be writing; a Ctrl+C typed now would race its exit code with the handler's
            # 130 (AUD-023-BLD004).
            assert session.drain_until_exit(10), f"{command}, {label}: the refusal did not end"
            code, settings = session.close()
            assert code == INVALID_INPUT, f"{command}, {label}: exit code {code}"
            assert CANCELLED_SHOWN not in session.output, f"{command}, {label}: cancelled"
            assert settings == session.original, f"{command}, {label}: terminal settings changed"
            for asked in (b"assphrase", b"Password", b"Esc cancels"):
                assert asked not in session.output, f"{command}, {label}: asked {asked!r} first"
            if reader is not None:
                assert piped_output(reader) == b"", f"{command}, {label}: wrote to the pipe"
            print(f"{command}: refused with {label}, before any question, exit code 2")
        # Standard output on a second terminal: the private screen would be switched and cleared
        # on the first one only (AUD-008-SEC004).
        leader, follower = os.openpty()
        session = Session((command, "--pim", "0"), stdout=follower)
        os.close(follower)
        session.wait_for(refused)
        label = "standard output on another terminal"
        assert session.drain_until_exit(10), f"{command}, {label}: the refusal did not end"
        code, settings = session.close()
        assert code == INVALID_INPUT, f"{command}, {label}: exit code {code}"
        assert CANCELLED_SHOWN not in session.output, f"{command}, {label}: cancelled"
        assert settings == session.original, f"{command}, {label}: terminal settings changed"
        for asked in (b"assphrase", b"Password", b"Esc cancels"):
            assert asked not in session.output, f"{command}, {label}: asked {asked!r} first"
        assert other_terminal_output(leader) == b"", f"{command}, {label}: wrote to it"
        print(f"{command}: refused with {label}, before any question, exit code 2")

    session = Session(("new", "--pim", "0"))
    session.wait_for(b"passphrase of the new wallet")
    code, _ = session.close()
    assert code == CANCELLED, f"new at a terminal: exit code {code}"
    print("new: at a terminal it goes on to the passphrase")

    for redirected in (False, True):
        session, reader = run_with_output(("rekey", "--pim", "0", "--words", "24"), redirected)
        session.wait_for(CONTAINER_ASKED)
        session.answer(CONTAINER.encode() + b"\r", b"container password: ")
        session.answer(SECRET + b"\r", b"confirmed?", LIST_SHOWN)
        offered = b"show me the phrase" in session.output
        code, _ = session.close()
        assert code == CANCELLED, f"rekey: exit code {code}"
        label = "with standard output in a pipe" if redirected else "at a terminal"
        assert offered != redirected, f"rekey, {label}: showing the phrase offered: {offered}"
        if reader is not None:
            assert piped_output(reader) == b"", f"rekey, {label}: wrote to the pipe"
        state = "not offered" if redirected else "offered"
        print(f"rekey: showing the phrase for comparison {state} {label}")


def check_new_check_question():
    """`mhfe new` asks about the wallet check with no answer marked (AUD-010): Enter, also typed
    ahead with the repeated passphrase, does nothing, ? explains both answers, ↓ marks the first,
    and Escape cancels before anything is drawn or recorded."""
    session = Session(("new", "--pim", "0"))
    session.wait_for(b"passphrase of the new wallet")
    session.answer(SECRET + b"\r", b"Repeat the passphrase")
    # The Enter after the repeated passphrase arrives before the list is drawn.
    session.answer(SECRET + b"\r" + ENTER, CHECK_ASKED, *CHECK_ANSWERS, LIST_SHOWN)
    question = session.output.rfind(CHECK_ASKED)
    # The whole list, up to the line break after the last line of its hint.
    session.wait_for(LIST_SHOWN + b"\r\n", since=question)
    shown = session.output[question:]
    assert HIGHLIGHT not in shown, "new: an answer to the check question was marked"
    assert b"\r\n" + CHECK_UNMARKED_HINT + b"\r\n" in shown, (
        f"new: the hint is not {CHECK_UNMARKED_HINT!r}")
    written = session.idle(ENTER)
    assert written == b"", f"new: Enter alone answered the check question: {written!r}"
    session.answer(b"?", CHECK_EXPLAINED, LIST_SHOWN)
    explained = session.output[session.output.rfind(CHECK_EXPLAINED):]
    assert HIGHLIGHT not in explained, "new: ? marked an answer"
    session.answer(DOWN, HIGHLIGHT + b" " + CHECK_ANSWERS[0], CHECK_MARKED_HINT)
    session.answer(ESCAPE, CANCELLED_SHOWN)
    assert session.drain_until_exit(10), "new: Escape did not end the tool"
    code, settings = session.close()
    assert code == CANCELLED, f"new: Escape gave exit code {code}"
    assert settings == session.original, "new: the terminal settings were not restored"
    assert REPAIR_ASKED not in session.output, "new: went on past the check question"
    shown_privately("new", session.output, SECRET)
    summary = session.output[session.output.rfind(LEAVE_PRIVATE):]
    assert CHECK_RECORDED not in summary, "new: an answer to the check question was recorded"
    print("new: the check question has no default; Enter, also typed ahead, does nothing")
    print("new: ? explains both answers, ↓ marks the first; Escape cancels, exit code 130")


def check_new_chosen_words():
    """`mhfe new` asks for one chosen word on a private screen: a position the library refuses is
    named without the word and asked again from the question; a word at the last position and a
    word never to use keep about 244 random bits, said before the draw with the warning that the
    word gives the wallet away. Escape at the next question cancels before anything is drawn. The
    summary records how many words were chosen and the bits kept, never the word."""
    session = Session(("new", "--pim", "0"))
    session.wait_for(b"passphrase of the new wallet")
    # No passphrase: no wallet check, so the question about a word comes next.
    session.answer(b"\r", CHOSEN_ASKED, LIST_SHOWN)
    session.answer(b"2", CHOSEN_WORD_ASKED)
    session.answer(b"zoo\r", PLACE_ASKED)
    # One word only: the words never to use come next.
    session.answer(b"25\r", NEVER_USE_ASKED)
    start = len(session.output)
    session.answer(b"\r", PLACE_REFUSED, CHOSEN_ASKED, LIST_SHOWN)
    assert b"zoo" not in session.output[start:], "new: the refusal named the word"
    session.answer(b"2", CHOSEN_WORD_ASKED)
    # The chosen word is hinted from the BIP39 list as it is typed.
    session.answer(b"zo", b"zone  zoo")
    session.answer(b"o\r", PLACE_ASKED)
    session.answer(b"24\r", NEVER_USE_ASKED)
    session.answer(b"abandon\r", RECOGNISABLE, AMPLE, REPAIR_ASKED, LIST_SHOWN)
    session.answer(ESCAPE, CANCELLED_SHOWN)
    assert session.drain_until_exit(10), "new, chosen word: Escape did not end the tool"
    code, settings = session.close()
    assert code == CANCELLED, f"new, chosen word: Escape gave exit code {code}"
    assert settings == session.original, "new, chosen word: terminal settings changed"
    shown_privately("new, chosen word", session.output, b"zoo")
    summary = session.output[session.output.rfind(LEAVE_PRIVATE):]
    assert CHOSEN_RECORDED in summary, "new, chosen word: the wishes were not recorded"
    assert b"zoo" not in summary, "new, chosen word: the word reached the summary"
    print("new: one chosen word is typed privately; a wrong position is refused and asked again")
    print("new: the bits kept and the warning are said before the draw; no word in the summary")


def check_quit_keys_leave_the_private_screen():
    """Ctrl+\\ and Ctrl+Z at a visible prompt on a private screen, and SIGTERM, end `mhfe new` as
    Ctrl+C does: the private screen with the chosen word on it is left, the terminal restored and
    the exit code 130 (AUD-015-SEC004)."""
    for name, stop in (("Ctrl+\\", b"\x1c"), ("Ctrl+Z", b"\x1a"), ("SIGTERM", None)):
        session = Session(("new", "--pim", "0"))
        session.wait_for(b"passphrase of the new wallet")
        session.answer(b"\r", CHOSEN_ASKED, LIST_SHOWN)
        session.answer(b"2", CHOSEN_WORD_ASKED)
        session.answer(b"zoo\r", PLACE_ASKED)
        if stop is None:
            session.process.send_signal(signal.SIGTERM)
        else:
            session.type(stop)
        assert session.drain_until_exit(10), f"new, {name}: the tool did not end"
        code, settings = session.close()
        assert code == CANCELLED, f"new, {name}: exit code {code}"
        assert settings == session.original, f"new, {name}: terminal settings changed"
        shown_privately(f"new, {name}", session.output, b"zoo")
        assert session.output.rfind(LEAVE_PRIVATE) > session.output.rfind(b"zoo"), name
    print("new: Ctrl+\\, Ctrl+Z and SIGTERM leave the private screen and end as Ctrl+C does")


def check_dumb_terminal_has_no_hints():
    """At TERM=dumb the container prompt and the repair-word prompt write no control sequence and
    no word hint while a word is typed and corrected, while at a terminal that redraws they hint
    the words (AUD-023-UI004)."""
    def typed_at(term, arguments, prompt, before=b""):
        session = Session(arguments, term=term)
        session.wait_for(CONTAINER_ASKED)
        if before:
            session.answer(before, prompt)
        written = session.idle(b"ab" + BACKSPACE)
        session.type(CTRL_C)
        assert session.drain_until_exit(10), f"{term}: it did not end"
        session.close()
        return written

    prompts = (
        ("container", ("decrypt", "--pim", "0"), CONTAINER_ASKED, b""),
        ("repair-word", ("repair",), CARD_ASKED, container_with({3: "?"}) + b"\r"),
    )
    for name, arguments, prompt, before in prompts:
        dumb = typed_at("dumb", arguments, prompt, before)
        assert b"\x1b" not in dumb, f"TERM=dumb, {name} prompt: {dumb!r}"
        assert b"BIP39 word" not in dumb, f"TERM=dumb, {name} prompt: a hint: {dumb!r}"
        redrawn = typed_at("xterm-256color", arguments, prompt, before)
        assert b"BIP39 word" in redrawn, f"xterm, {name} prompt: no hint: {redrawn!r}"
    print("TERM=dumb: the container and repair-word prompts write no control sequence or hint")


def check_typed_ahead_keys_answer_nothing():
    """A key typed before a screen that waits to be left appeared, during the start or with the
    line before it, does not clear it, Enter, q and Escape alike: a made password and a repair
    card stay until a key is pressed after they appeared (AUD-023-UI003)."""
    cases = (
        ("password", ("password", "--words", "6"), None, b"\r"),
        ("password", ("password", "--words", "6"), None, b"q"),
        ("password", ("password", "--words", "6"), None, ESCAPE),
        ("repair card", ("repair-words", "--count", "4"), CONTAINER_ASKED,
         CONTAINER.encode() + b"\r\r"),
        ("repair card", ("repair-words", "--count", "4"), CONTAINER_ASKED,
         CONTAINER.encode() + b"\rq"),
    )
    for name, arguments, prompt, typed in cases:
        session = Session(arguments)
        if prompt is not None:
            session.wait_for(prompt)
        session.type(typed)
        session.wait_for(b"Write it down now")
        time.sleep(1)
        key = repr(typed[-1:])
        assert session.process.poll() is None, f"{name}: the {key} typed ahead cleared it"
        session.answer(ENTER, b"")
        assert session.drain_until_exit(10), f"{name}: Enter after it appeared did not leave"
        code, _ = session.close()
        assert code == 0, f"{name}: exit code {code}"
    print("typed ahead: an Enter, q or Escape typed before a made password or a repair card "
          "appeared clears neither")
