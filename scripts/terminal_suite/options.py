# TOOL-01: public fixtures and cases of the Python PTY test runtime.
"""
Options, scripts and refusals: what the tool says without a terminal or
before a question.

`mhfe encrypt --stdin` asks nothing about a passphrase; a --never-use
word, new settings out of range and a --confirm that does not fit are
refused at start; given options bypass their mapped questions; a
result that cannot be written fails with exit code 1; password sizes out
of range are refused in the library's words; usage errors and help
follow the tool's style; and the messages of a script wrap at 78 columns
and name only what a command has.
"""

import os
import subprocess
import sys

from .constants import (
    BAD_CHECKSUM,
    CANCELLED,
    CHECK_ASKED,
    CHOSEN_ASKED,
    COIN_ASSUMED,
    COMMANDS,
    CONTAINER,
    CONTAINER_ASKED,
    CTRL_C,
    ERROR_MARK,
    ERROR_RED,
    HELP_WIDTH,
    INVALID_INPUT,
    MEMORY_REFUSED,
    NAMES_COIN,
    NOT_ENOUGH_RESOURCES,
    NO_TERMINAL,
    NUMBERED_PROMPT,
    PASSPHRASE_ASKED,
    PHRASE,
    PROGRAM,
    PUBLIC_ADDRESS,
    PUBLIC_ETHEREUM_ADDRESS,
    REPAIR_ASKED,
    SECRET,
    TEXT_WIDTH,
)
from .recovery import ORIGINAL_PASSPHRASE_ASKED
from .repair import ZERO_12_CARD, container_with
from .session import Session, run_plainly, tool_environment, wrapped


def script_encryption_asks_no_passphrase_and_refuses_different_passwords():
    """
    A script gives the phrase and the password twice, one per line, and
    is not asked about the wallet's passphrase, as no one is: the two
    lines after the phrase are taken as the passwords. They differ,
    which ends the tool before Argon2. A question would show its text
    and take the first password line as its answer instead. The help
    lists no passphrase among what encrypt asks for.
    """
    lines = b"\n".join((PHRASE.encode(), SECRET, SECRET + b"x")) + b"\n"
    result = subprocess.run([PROGRAM, "encrypt", "--stdin"], input=lines, capture_output=True,
                            env=dict(os.environ, NO_COLOR="1"), timeout=30)
    assert result.returncode == INVALID_INPUT, f"encrypt --stdin: exit code {result.returncode}"
    assert b"The password and its repetition differ" in result.stderr, (
        f"encrypt --stdin: {result.stderr!r}"
    )
    assert PASSPHRASE_ASKED not in result.stderr, "encrypt --stdin: asked about the passphrase"
    assert NUMBERED_PROMPT not in result.stderr, "encrypt --stdin: asked to choose"
    assert result.stdout == b"", "encrypt --stdin: wrote to standard output"
    print(
        "encrypt --stdin: not asked about the passphrase; "
        "two different passwords end it, code 2"
    )
    text = run_plainly(("encrypt", "--help")).stdout
    asks = text[text.index(b"What it asks for:"):text.index(b"Examples:")]
    assert b"Original seed phrase" in asks and b"Password" in asks, f"encrypt --help: {asks!r}"
    assert b"passphrase" not in asks.lower(), f"encrypt --help: asks for a passphrase: {asks!r}"
    print("encrypt --help: no passphrase among what it asks for")


def an_invalid_never_use_word_is_refused_before_any_question():
    """A --never-use word the library refuses whatever word is chosen is
    refused before the first question, with exit code 2, instead of the
    chosen-word question coming back again and again (AUD-015-UI002).
    """
    for word in ("notaword", "abandon,zoo"):
        result = run_plainly(("new", "--never-use", word))
        assert result.returncode == INVALID_INPUT, f"new --never-use {word}: {result.returncode}"
        error = result.stderr.decode()
        assert "wishes for the new phrase cannot be used" in error, error
        assert word.split(",")[0] not in error, f"new --never-use: the refusal named {word}"
        assert b"Do you want to choose" not in result.stderr, "new --never-use: a question came"
    print("new: a --never-use word the library refuses ends the tool before any question")


def rekey_refuses_invalid_new_settings_before_any_question():
    """
    New settings out of range, or more memory than the computer gives,
    and a --confirm the length given cannot use, end `mhfe rekey` with
    exit code 2 or 4 before the container is asked, not after the old
    container's recovery (AUD-023-UI002).
    """
    for arguments, code, refusal in (
        (("--new-pim", "5000"), INVALID_INPUT, b"The new PIM must be a whole number"),
        (("--new-mem", "99"), INVALID_INPUT, b"The new memory level must be a whole number"),
        (("--words", "24", "--confirm", "check"), INVALID_INPUT, b"The built-in check alone"),
        # 3 TiB: more free memory than any computer that runs this suite
        # reports.
        (("--new-mem", "21"), NOT_ENOUGH_RESOURCES, b"memory"),
    ):
        session = Session(("rekey", "--pim", "0", *arguments))
        assert session.drain_until_exit(10), f"rekey {' '.join(arguments)}: it did not end"
        exit_code, _ = session.close()
        label = f"rekey {' '.join(arguments)}"
        assert exit_code == code, f"{label}: exit code {exit_code}"
        assert refusal in session.output, f"{label}: {session.output!r}"
        assert CONTAINER_ASKED not in session.output, f"{label}: the container was asked"
    print("rekey: given new settings and a --confirm the length cannot use are refused at start")


def given_options_skip_their_corresponding_questions():
    """
    new, encrypt and check skip the questions answered by their flags.

    This case covers --wallet-check, --choose-word, --repair-words,
    --same-length and --passphrase-used. option_paths covers the other
    explicit option families; cli-questions.json inventories questions
    and interactive follow-ups without claiming they all need flags.
    """
    session = Session(("new", "--pim", "0", "--wallet-check", "no", "--choose-word", "no",
                       "--repair-words", "0"))
    session.wait_for(b"passphrase of the new wallet")
    session.answer(SECRET + b"\r", b"Repeat the passphrase")
    session.answer(SECRET + b"\r", b"Write it down now")
    session.type(CTRL_C)
    assert session.drain_until_exit(10), "new with its answers: it did not end"
    session.close()
    for question in (CHECK_ASKED, CHOSEN_ASKED, REPAIR_ASKED):
        assert question not in session.output, f"new with its answers: asked {question!r}"

    session = Session(("encrypt", "--pim", "0", "--same-length", "no"))
    session.wait_for(b"seed phrase: ")
    session.answer(PHRASE.encode() + b"\r", REPAIR_ASKED)
    session.type(CTRL_C)
    assert session.drain_until_exit(10), "encrypt --same-length no: it did not end"
    session.close()
    assert b"How long should" not in session.output, "encrypt --same-length no: asked the length"

    # The capped address space stops the check at its memory
    # reservation, after the questions.
    session = Session(("check", "--pim", "0", "--words", "auto", "--passphrase-used", "no"),
                      capped=sys.platform == "linux")
    session.wait_for(CONTAINER_ASKED)
    session.answer(CONTAINER.encode() + b"\r", b"ontainer password: ")
    capped = sys.platform == "linux"
    # Without Linux's effective cap, cancel before any reservation.
    session.type(SECRET + b"\r" if capped else CTRL_C)
    assert session.drain_until_exit(10), "check with its answers: it did not end"
    code, _ = session.close()
    assert code == (NOT_ENOUGH_RESOURCES if capped else CANCELLED), (
        f"check with its answers: code {code}")
    if capped:
        assert MEMORY_REFUSED in session.output, "check with its answers: no memory refusal"
    else:
        assert b"Recovering" not in session.output, "check with its answers: recovery started"
    assert ORIGINAL_PASSPHRASE_ASKED not in session.output, (
        "check --passphrase-used no: asked about the passphrase")

    # --wallet-check yes asks again for a passphrase given empty: the
    # check needs one.
    session = Session(("new", "--pim", "0", "--wallet-check", "yes", "--choose-word", "no",
                       "--repair-words", "0"))
    session.wait_for(b"passphrase of the new wallet")
    start = len(session.output)
    session.answer(b"\r", b"needs a BIP39 passphrase", b"passphrase of the new wallet")
    assert session.process.poll() is None, "new --wallet-check yes: an empty passphrase ended it"
    session.type(CTRL_C)
    assert session.drain_until_exit(10), "new --wallet-check yes: it did not end"
    session.close()
    assert CHECK_ASKED not in session.output[start:], "new --wallet-check yes: asked the check"

    # --passphrase-used answers only the question of --words auto at a
    # terminal.
    for arguments, refusal in (
            (("check", "--fingerprint", "--passphrase-used", "no"),
             b"--passphrase-used belongs only to --words auto"),
            (("check", "--words", "auto", "--passphrase-used", "no", "--stdin"),
             b"--passphrase-used belongs only to a terminal")):
        result = run_plainly(arguments)
        assert result.returncode == INVALID_INPUT, f"{arguments}: exit code {result.returncode}"
        assert refusal in b" ".join(result.stderr.split()), f"{arguments}: {result.stderr!r}"

    for arguments in (("new", "--wallet-check", "maybe"), ("new", "--choose-word", "maybe"),
                      ("encrypt", "--same-length", "maybe"),
                      ("check", "--words", "auto", "--passphrase-used", "maybe")):
        result = run_plainly(arguments)
        assert result.returncode == INVALID_INPUT, f"{arguments}: exit code {result.returncode}"
        # The refusal is wrapped to the width of the error column, at
        # any word.
        refusal = b" ".join(result.stderr.split())
        assert b"give yes or no" in refusal, f"{arguments}: {result.stderr!r}"
    print("new, encrypt and check: answers given as options are not asked; maybe is refused")
    print("new --wallet-check yes: an empty passphrase is asked again")
    print("check: --passphrase-used is refused without --words auto and with --stdin")


# What a result that cannot be written gives (style::out in
# src/bin/mhfe/style.rs): one error
# line and exit code 1, never a panic or a success (AUD-023-FUN001).
OUTPUT_FAILED = b"Error: Input or output failed: "
# The device on which every write fails with "no space left". Linux has
# it; macOS, where CI runs
# this script too, does not.
FULL_DEVICE = "/dev/full"


def unwritable_output(target):
    """
    A descriptor every write to which fails: the writing end of a pipe
    whose reader is closed, or the full device.
    """
    if target == FULL_DEVICE:
        return os.open(FULL_DEVICE, os.O_WRONLY)
    reader, writer = os.pipe()
    os.close(reader)
    return writer


def unwritable_standard_output_refuses_a_successful_result():
    """A result written to a pipe whose reader has gone, or to a full
    device where the system has one, fails with one error line and exit
    code 1, for each command whose result needs no Argon2 work:
    password, repair-words and repair. encrypt, decrypt and check write
    theirs through the same function.
    """
    container = container_with({3: "?", 17: "?"})
    commands = (
        (("password", "--words", "6"), b""),
        (("repair-words", "--count", "4", "--stdin"), CONTAINER.encode() + b"\n"),
        (("repair", "--stdin"), container + b"\n" + ZERO_12_CARD + b"\n"),
    )
    targets = ("closed pipe", FULL_DEVICE) if os.path.exists(FULL_DEVICE) else ("closed pipe",)
    for arguments, data in commands:
        for target in targets:
            output = unwritable_output(target)
            try:
                result = subprocess.run([PROGRAM, *arguments], input=data, stdout=output,
                                        stderr=subprocess.PIPE, env=tool_environment(),
                                        timeout=30)
            finally:
                os.close(output)
            label = f"{' '.join(arguments[:1])} to a {target}"
            assert result.returncode == 1, f"{label}: exit code {result.returncode}"
            assert result.stderr.count(OUTPUT_FAILED) == 1, f"{label}: {result.stderr!r}"
            assert b"panicked" not in result.stderr, f"{label}: {result.stderr!r}"
        print(f"{arguments[0]}: a result that cannot be written to a {' or a '.join(targets)} "
              "fails with exit code 1")


def unwritable_standard_error_refuses_a_successful_result():
    """Messages that cannot be written to standard error, a full device,
    fail a command that otherwise succeeded with exit code 1, and leave
    the documented code of one that failed, with no panic and no abort
    (AUD-024-FUN009). Linux only, which has the device.
    """
    if not os.path.exists(FULL_DEVICE):
        print("standard error on a full device: not checked, as this system has none")
        return
    for arguments, expected in ((("password", "--words", "6"), 1),
                                (("password", "--words", "33"), INVALID_INPUT)):
        errors = os.open(FULL_DEVICE, os.O_WRONLY)
        try:
            result = subprocess.run([PROGRAM, *arguments], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=errors,
                                    env=tool_environment(), timeout=30)
        finally:
            os.close(errors)
        label = " ".join(arguments)
        assert result.returncode == expected, f"{label}: exit code {result.returncode}"
    print("standard error on a full device: exit code 1 after a success, the documented code "
          "after a failure, and no abort")


def password_sizes_outside_the_library_limits_are_refused():
    """
    A password size out of range is refused before anything is made, in
    the library's words (AUD-011-ARC001), with exit code 2; the sizes at
    the limits are made.
    """
    for arguments, message in (
        (("password", "--words", "33"), "Choose between 1 and 32 words"),
        (("password", "--words", "0"), "Choose between 1 and 32 words"),
        (("password", "--chars", "65"), "Choose between 1 and 64 characters"),
    ):
        label = " ".join(arguments)
        result = run_plainly(arguments)
        assert result.returncode == INVALID_INPUT, f"{label}: exit code {result.returncode}"
        assert result.stdout == b"", f"{label}: a password was made"
        assert (ERROR_MARK + message).encode() in result.stderr, f"{label}: {result.stderr!r}"
    for arguments in (("password", "--words", "1"), ("password", "--words", "32"),
                      ("password", "--chars", "64")):
        result = run_plainly(arguments)
        assert result.returncode == 0 and result.stdout.strip(), " ".join(arguments)
    print("password sizes: out of range refused in the library's words, the limits made")


def usage_errors_hide_secrets_and_help_keeps_terminal_colours():
    """Usage errors read as errors of the tool, and every help fits its
    width with examples.
    """
    for arguments, message in (
        (("encrypt", "--no-such-option"), "Unexpected argument '--no-such-option' found"),
        (("serve",), "The following required arguments were not provided: <FILE>"),
        (("check", "--address", "--fingerprint"),
         "The argument '--address' cannot be used with '--fingerprint'"),
    ):
        label = " ".join(arguments)
        result = run_plainly(arguments)
        assert result.returncode == INVALID_INPUT, f"{label}: exit code {result.returncode}"
        assert result.stdout == b"", f"{label}: wrote to standard output"
        shown = result.stderr.decode().split("\n")
        assert shown[:2] == ["", ERROR_MARK + message], f"{label}: {shown!r}"
        assert "error:" not in result.stderr.decode(), f"{label}: clap's own error line"
        assert "Usage: mhfe" in result.stderr.decode(), f"{label}: no usage"
        assert all(len(line) <= TEXT_WIDTH for line in shown), f"{label}: a line is too long"
    result = run_plainly(("encrypt", "--no-such-option"), colour=True)
    assert (ERROR_RED + ERROR_MARK.strip()).encode() in result.stderr, (
        f"usage error: not in mhfe's red: {result.stderr!r}")
    print("usage errors: one red ✗ Error: line, then the usage in grey; exit code 2")
    for flag in ("--help", "--version"):
        result = run_plainly((flag,))
        assert result.returncode == 0, f"mhfe {flag}: exit code {result.returncode}"
        assert result.stdout and result.stderr == b"", f"mhfe {flag}: not on standard output"
    for command in ((), *((name,) for name in COMMANDS)):
        for flag in ("-h", "--help"):
            label = " ".join(("mhfe", *command, flag))
            result = run_plainly((*command, flag))
            assert result.returncode == 0, f"{label}: exit code {result.returncode}"
            text = result.stdout.decode()
            assert "\nExamples:\n" in text, f"{label}: no examples"
            wide = [line for line in text.split("\n") if len(line) > HELP_WIDTH]
            assert not wide, f"{label}: lines wider than {HELP_WIDTH} columns: {wide!r}"
    print(f"help: --help and --version unchanged; every -h and --help fits {HELP_WIDTH} columns, "
          "with examples")


def script_messages_wrap_with_their_commands_input_names():
    """
    Errors wrap at the text width, the advice without a terminal names
    only what a command has, and a script that compares with an address
    without --coin is told that Bitcoin is assumed (AUD-010).
    """
    lines = b"\n".join((BAD_CHECKSUM, SECRET, SECRET)) + b"\n"
    result = run_plainly(("encrypt", "--stdin", "--pim", "0"), lines)
    assert result.returncode == INVALID_INPUT, f"encrypt --stdin: exit code {result.returncode}"
    shown = result.stderr.decode().rstrip("\n").split("\n")
    error = shown[next(index for index, line in enumerate(shown) if line.startswith(ERROR_MARK)):]
    text = ("The seed phrase is not a valid English BIP39 phrase: its checksum does not match, so "
            "a word is wrong or words are out of order")
    first, *rest = wrapped(text, TEXT_WIDTH - len(ERROR_MARK))
    assert error == [ERROR_MARK + first, *(" " * len(ERROR_MARK) + line for line in rest)], (
        f"encrypt --stdin: the error is shown as {error!r}")
    print("errors: a long one wraps to 78 columns under its mark")

    container = CONTAINER.encode()
    # A command that reads a secret refuses a standard input that is no
    # terminal at once, without
    # --stdin, before any question could take its lines as answers
    # (AUD-023-UI006).
    lines = b"1\n" + container + b"\n" + SECRET + b"\n"
    for arguments, data, names_stdin in (
        (("password", "--dice"), b"", False),
        (("rekey", "--pim", "0", "--words", "24"), lines, False),
        (("rekey",), lines, False),
        (("encrypt", "--pim", "0"), b"", True),
        (("encrypt",), lines, True),
        (("decrypt",), b"", True),
        (("decrypt",), lines, True),
        (("decrypt", "--pim", "0", "--mem", "0"), container[:20] + b"\n" + SECRET + b"\n", True),
        (("check", "--address", "--coin", "ethereum"), b"", True),
        (("check", "--fingerprint"), lines, True),
    ):
        label = " ".join(arguments)
        result = run_plainly(arguments, data)
        said = " ".join(result.stderr.decode().split())
        assert result.returncode == INVALID_INPUT, f"{label}: exit code {result.returncode}"
        assert NO_TERMINAL in said, f"{label}: {said!r}"
        assert ("--stdin" in said) == names_stdin, f"{label}: {said!r}"
        assert b"Choice" not in result.stderr and b"?" not in result.stderr, (
            f"{label}: a question was asked: {said!r}")
    # A command that needs no answer still runs.
    result = run_plainly(("password",))
    assert result.returncode == 0, f"password without a terminal: exit code {result.returncode}"
    print("without a terminal: refused at start, --stdin named only by a command that has it")

    def answers(address):
        return b"\n".join((container, SECRET, address, b"")) + b"\n"

    without_coin = ("check", "--stdin", "--address", "--pim", "0")
    result = run_plainly(without_coin, answers(PUBLIC_ETHEREUM_ADDRESS))
    shown = result.stderr.decode()
    error = " ".join(shown[shown.index(ERROR_MARK):].split())
    assert result.returncode == INVALID_INPUT, f"check --stdin --address: {result.returncode}"
    assert COIN_ASSUMED in shown.split("\n"), f"check --stdin --address: {shown!r}"
    assert error.startswith(ERROR_MARK + NAMES_COIN[0]) and error.endswith(NAMES_COIN[1]), (
        f"check --stdin --address: {error!r}")
    assert result.stdout == b"", "check --stdin --address: wrote to standard output"
    if sys.platform == "linux":
        result = run_plainly(without_coin, answers(PUBLIC_ADDRESS), capped=True)
        assert result.returncode == NOT_ENOUGH_RESOURCES, (
            f"check --stdin --address, a Bitcoin address: exit code {result.returncode}")
        assert COIN_ASSUMED in result.stderr.decode().split("\n"), (
            "check --stdin --address, a Bitcoin address: the coin assumed is not recorded")
        assert MEMORY_REFUSED in result.stderr, "check --stdin --address: not at the reservation"
        result = run_plainly(("check", "--stdin", "--address", "--coin", "ethereum", "--pim", "0"),
                             answers(PUBLIC_ETHEREUM_ADDRESS), capped=True)
        assert result.returncode == NOT_ENOUGH_RESOURCES, (
            f"check --stdin --address --coin ethereum: exit code {result.returncode}")
        assert "--coin was given" not in result.stderr.decode(), (
            "check --coin ethereum: records a coin assumed")
        assert MEMORY_REFUSED in result.stderr, "check --coin ethereum: not at the reservation"
    print("check --stdin --address: Bitcoin without --coin, recorded, and another coin's address "
          "refused with a pointer to --coin; the coin given takes its address")
