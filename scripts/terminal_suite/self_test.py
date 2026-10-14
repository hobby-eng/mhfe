"""`mhfe self-test`, the checks at start, and copies of the program that fail them.

The report lists every part with its mark in mhfe's style, at a terminal, with NO_COLOR, in a pipe
and from the menu; the checks at start show nothing when they pass; and a copy with one bit flipped
in a known answer stops before anything is asked, with the part named.
"""

from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

from .constants import (ALL_PASSED, ANSWER_DELAY, A_FEW_SECONDS, BACK_TO_MENU, BOLD, CANCELLED,
                        CANCELLED_SHOWN, COLOUR_CODE, CONTROL_SEQUENCE, ENCRYPT_TITLE, ENTER,
                        ENTER_PRIVATE, ERROR_MARK, ESCAPE, FACT_LABEL_WIDTH, GREY, INTERNAL_ERROR,
                        LIST_SHOWN, MENU_SHOWN, MENU_TITLE, NAME, NOT_AVAILABLE, PASS,
                        PRESS_ENTER_TO_QUIT, PROGRAM, RESET, SELF_TEST_ALARM, SELF_TEST_ANSWERS,
                        SELF_TEST_ENTRY, SELF_TEST_LINK, SELF_TEST_PARTS, SELF_TEST_PARTS_PIPED,
                        SELF_TEST_SECONDS, SETTINGS_QUESTION, TEXT_WIDTH, VECTORS_COST, WHICH_TEST)
from .passwords import CHECK_WORD_PASSWORD
from .session import Session, tool_environment, wrapped


def screen_lines(output):
    """The lines a terminal shows for `output`, which holds no control sequences: a carriage return
    alone goes back to the start of its line, and what follows is written over what stood there."""
    lines = []
    for line in output.decode().split("\r\n"):
        shown = []
        for part in line.split("\r"):
            shown[:len(part)] = part
        lines.append("".join(shown).rstrip())
    return lines


def plain(_, text):
    """`text` as the tool writes it without colour."""
    return text


def painted(colour, text):
    """`text` in `colour`, as the tool writes it at a terminal (paint in src/bin/mhfe/style.rs)."""
    return f"{colour}{text}{RESET}"


def fact_line(paint, label, value):
    """A fact of a summary: its grey label padded to the facts' column, then its value."""
    return f"  {paint(GREY, label.ljust(FACT_LABEL_WIDTH))} {value}"


def self_test_report(marks, paint=plain):
    """The lines of `mhfe self-test` before its verdict when its parts give `marks`: the title; a
    row per part, with its grey label in a column as wide as the widest and its mark painted as a
    pass and wrapped under its own column (report_row in src/bin/mhfe/style.rs); the time it took,
    as took_a_few_seconds reads it; and the published vectors, which it did not run."""
    width = max(len(label) for label, _ in marks)
    # Two columns of indent before the label and two after it.
    column = 2 + width + 2
    lines = ["", f"{paint(NAME, 'MHFE')} {paint(GREY, '·')} {paint(BOLD, 'Test this program')}"]
    for label, mark in marks:
        # A protection this system does not offer is said in grey, not as a pass (verdicts in
        # src/bin/mhfe/self_test.rs).
        style = GREY if mark.startswith(NOT_AVAILABLE) else PASS
        first, *rest = wrapped(mark, TEXT_WIDTH - column)
        lines.append(f"  {paint(GREY, label.ljust(width))}  {paint(style, first)}")
        lines.extend(" " * column + paint(style, line) for line in rest)
    vectors = paint(GREY, f"not run · mhfe self-test --vectors, {VECTORS_COST}")
    return [*lines, "", fact_line(paint, "Time", "a few seconds"),
            fact_line(paint, "Vectors", vectors), ""]


def passed(paint=plain):
    """The verdict of a self-test whose every part passed, and the line break after it."""
    return [f"{paint(PASS, '✓')} {ALL_PASSED}", ""]


def took_a_few_seconds(lines, paint=plain):
    """`lines` with the value of their Time fact read as "a few seconds" where it says so."""
    took = fact_line(paint, "Time", "")
    return [took + "a few seconds"
            if line.startswith(took) and re.fullmatch(A_FEW_SECONDS, line[len(took):]) else line
            for line in lines]


def check_self_test():
    """`mhfe self-test` tests every part in seconds and reports each with its mark in mhfe's style:
    in colour at a terminal, without colour codes with NO_COLOR and in a pipe, and from the menu,
    whose entry asks which of the two tests to run."""
    session = Session(("self-test",), colour=True)
    assert session.drain_until_exit(SELF_TEST_SECONDS), "self-test: it did not end"
    code, settings = session.close()
    assert code == 0, f"self-test: exit code {code}"
    assert settings == session.original, "self-test: the terminal settings were not restored"
    # The line that names the part being tested is written over by the report's first row.
    shown = [line.split("\r")[-1] for line in session.output.decode().split("\r\n")]
    expected = self_test_report(SELF_TEST_PARTS, painted) + passed(painted)
    assert took_a_few_seconds(shown, painted) == expected, f"self-test: the report is {shown!r}"
    print("self-test: every part with its pass mark, in mhfe's colours; ✓ and exit code 0")

    session = Session(("self-test",))
    assert session.drain_until_exit(SELF_TEST_SECONDS), "self-test, NO_COLOR: it did not end"
    code, settings = session.close()
    assert code == 0, f"self-test, NO_COLOR: exit code {code}"
    assert settings == session.original, "self-test, NO_COLOR: terminal settings changed"
    assert re.search(COLOUR_CODE, session.output) is None, "self-test, NO_COLOR: colour codes"
    # At a terminal a line names each part while it is tested, in the order of the report.
    testing = re.findall(r"\r  Testing ([^\r]*)… *(?=\r)", session.output.decode())
    assert testing == [label for label, _ in SELF_TEST_PARTS], f"self-test: {testing!r} named"
    # Erased before the report: the screen shows the report alone.
    shown = took_a_few_seconds(screen_lines(session.output))
    expected = self_test_report(SELF_TEST_PARTS) + passed()
    assert shown == expected, f"self-test, NO_COLOR: the screen shows {shown!r}"
    print("self-test, NO_COLOR: no colour codes; each part named while tested, then erased")

    # Neither NO_COLOR nor a dumb terminal: only the pipe turns colour off.
    result = subprocess.run([PROGRAM, "self-test"], stdin=subprocess.DEVNULL, capture_output=True,
                            env=tool_environment(colour=True), timeout=SELF_TEST_SECONDS)
    assert result.returncode == 0, f"self-test in a pipe: exit code {result.returncode}"
    assert result.stdout == b"", "self-test in a pipe: wrote to standard output"
    assert b"\x1b" not in result.stderr, "self-test in a pipe: control sequences in the report"
    shown = took_a_few_seconds(result.stderr.decode().split("\n"))
    expected = self_test_report(SELF_TEST_PARTS_PIPED) + passed()
    assert shown == expected, f"self-test in a pipe: the report is {shown!r}"
    print("self-test in a pipe: the same report, without colour codes or the part being tested")

    session = Session(arguments=())
    session.wait_for(MENU_SHOWN)
    answers = (b"\r\n" + answer.encode() + b"\r\n" for answer in SELF_TEST_ANSWERS)
    session.answer(str(SELF_TEST_ENTRY).encode(), WHICH_TEST, *answers, LIST_SHOWN)
    session.answer(ESCAPE, MENU_SHOWN)
    session.answer(str(SELF_TEST_ENTRY).encode(), WHICH_TEST, LIST_SHOWN)
    start = len(session.output)
    session.answer(b"1", BACK_TO_MENU, limit=SELF_TEST_SECONDS)
    title = session.output.find(b"\r\n" + "MHFE · Test this program".encode(), start)
    report = session.output[title:session.output.rfind(BACK_TO_MENU)]
    shown = took_a_few_seconds(screen_lines(report))
    # The menu leaves a blank line before its wait.
    expected = self_test_report(SELF_TEST_PARTS) + passed() + [""]
    assert shown == expected, f"menu, every part: the screen shows {shown!r}"
    session.press(ESCAPE)
    assert session.drain_until_exit(10), "menu: Escape after the self-test did not end the tool"
    code, settings = session.close()
    assert code == 0, f"menu: Escape after the self-test gave exit code {code}"
    assert settings == session.original, "menu: the self-test changed the terminal settings"
    print("menu: the self-test entry asks which test, offering both; Escape returns to the menu")
    print("menu: every part tested from the menu, with the same report")


def check_quiet_start():
    """The checks at start show nothing when they pass: `mhfe encrypt`, which handles a secret,
    writes its first step first, and the menu its title."""
    session = Session(("encrypt",))
    session.answer(b"", SETTINGS_QUESTION, LIST_SHOWN)
    before = session.output[:session.output.find(SETTINGS_QUESTION)]
    assert before.startswith(ENTER_PRIVATE), f"encrypt: {before!r} before its first step"
    shown = re.sub(CONTROL_SEQUENCE, b"", before).strip()
    assert shown == ENCRYPT_TITLE, f"encrypt: {shown!r} before its first question"
    session.answer(ESCAPE, CANCELLED_SHOWN)
    assert session.drain_until_exit(10), "encrypt: Escape did not end the tool"
    code, _ = session.close()
    assert code == CANCELLED, f"encrypt: Escape gave exit code {code}"
    print("encrypt: the checks at start pass unseen; its first step comes first")

    session = Session(arguments=())
    session.wait_for(MENU_SHOWN)
    before = session.output[:session.output.find(MENU_TITLE)]
    assert before == b"\r\n", f"menu: {before!r} before its title"
    session.press(b"q")
    assert session.drain_until_exit(10), "menu: q did not end the tool"
    code, _ = session.close()
    assert code == 0, f"menu: q gave exit code {code}"
    print("menu: the checks at start pass unseen; its title comes first")


# Known answers that the checks at start compare, each held once in the program, with the part that
# compares it and what that part reports once a bit of the text is flipped, at start and in the full
# self-test: the six repair words of the container phrase of the suite 3 vector zero-12
# (MHFE-REPAIR-1), and the third vector of MHFE-PASSWORD-CHECK-1, both public vectors of the
# specification (vectors/profiles/README.md). At start only zero-12's container phrase gets its
# cards; the full self-test makes the cards of four container phrases.
DAMAGED_VECTORS = (
    (b"credit buzz orbit tired sail coffee", "Repair words (MHFE-REPAIR-1)",
     "card 1 of 1 gives other words", "card 1 of 4 gives other words"),
    (CHECK_WORD_PASSWORD, "Password check word (MHFE-PASSWORD-CHECK-1)",
     "vector 3 of 4 gives other words", "vector 3 of 4 gives other words"),
)


def damaged_copy(folder, text):
    """A copy of the program in `folder` with the lowest bit of the last letter of `text`, which
    the program holds once, flipped, as a damaged download or a faulty memory might; its path."""
    data = bytearray(Path(PROGRAM).read_bytes())
    assert data.count(text) == 1, f"damaged copy: {text!r} is not held once in the program"
    data[data.find(text) + len(text) - 1] ^= 1
    copy = folder / Path(PROGRAM).name
    copy.write_bytes(data)
    copy.chmod(0o700)
    if sys.platform == "darwin":
        # macOS on Apple silicon runs only signed code, and the flipped bit breaks the signature
        # the linker gave the program: the copy is signed again in the same way, ad hoc.
        subprocess.run(["codesign", "--force", "--sign", "-", str(copy)], check=True,
                       capture_output=True)
    return str(copy)


def stopped_at_start(part, detail):
    """What a command shows when `part` fails its known answers at start, and nothing else: one
    error wrapped to the text width under its first line, then the link to the README section of
    the self-test (failure_text in src/bin/mhfe/startup.rs)."""
    text = f"Self-test at start failed: {part}: {detail}. Do not use this program on this computer."
    first, *rest = wrapped(text, TEXT_WIDTH - len(ERROR_MARK))
    return [ERROR_MARK + first, *(" " * len(ERROR_MARK) + line for line in rest), SELF_TEST_LINK]


def check_damaged_copies():
    """A copy of the program with one bit flipped in a known answer stops a command that handles a
    secret before it asks for anything, and the menu before it is shown, with exit code 1 and the
    part named; the full self-test names the part too. The copies are made in a temporary folder
    (TMPDIR), never in the repository, and deleted afterwards."""
    with tempfile.TemporaryDirectory(prefix="mhfe-damaged-") as temporary:
        for index, (text, part, at_start, in_full) in enumerate(DAMAGED_VECTORS):
            # A folder of its own for each copy: macOS keeps the signature of a program it has
            # run, and stops another written over the same file.
            folder = Path(temporary) / str(index)
            folder.mkdir()
            program = damaged_copy(folder, text)
            stopped = stopped_at_start(part, at_start)

            session = Session(("encrypt",), program=program)
            assert session.drain_until_exit(10), f"damaged {part}: encrypt did not stop"
            code, settings = session.close()
            assert code == INTERNAL_ERROR, f"damaged {part}: encrypt gave exit code {code}"
            assert settings == session.original, f"damaged {part}: terminal settings changed"
            shown = session.output.decode().split("\r\n")
            assert shown == [*stopped, ""], f"damaged {part}: encrypt showed {shown!r}"
            print(f"damaged {part}: encrypt stops before it asks anything, exit code 1")

            # The window that a double-click opened stays until the message has been read.
            session = Session(arguments=(), program=program)
            session.wait_for(PRESS_ENTER_TO_QUIT.encode())
            # Pressed after the message was read, as a person does.
            time.sleep(ANSWER_DELAY)
            session.type(ENTER)
            assert session.drain_until_exit(10), f"damaged {part}: Enter did not end the menu"
            code, settings = session.close()
            assert code == INTERNAL_ERROR, f"damaged {part}: the menu gave exit code {code}"
            assert settings == session.original, f"damaged {part}: terminal settings changed"
            shown = session.output.decode().split("\r\n")
            expected = [*stopped, "", PRESS_ENTER_TO_QUIT, ""]
            assert shown == expected, f"damaged {part}: the menu showed {shown!r}"
            print(f"damaged {part}: no menu; the message stays until Enter, exit code 1")

            result = subprocess.run([program, "self-test"], stdin=subprocess.DEVNULL,
                                    capture_output=True, env=tool_environment(),
                                    timeout=SELF_TEST_SECONDS)
            assert result.returncode == INTERNAL_ERROR, (
                f"damaged {part}: self-test gave exit code {result.returncode}")
            marks = [(label, f"NOT as published: {in_full}" if label == part else mark)
                     for label, mark in SELF_TEST_PARTS_PIPED]
            shown = took_a_few_seconds(result.stderr.decode().split("\n"))
            expected = self_test_report(marks) + [*SELF_TEST_ALARM, ""]
            assert shown == expected, f"damaged {part}: the self-test reported {shown!r}"
            print(f"damaged {part}: the self-test names it and raises the alarm, exit code 1")
