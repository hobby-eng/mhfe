# TOOL-01: public fixtures and cases of the Python PTY test runtime.
"""Exercise explicit CLI options before full-size Argon2 work."""
import re
import sys
import tempfile
from pathlib import Path

from .constants import (
    ADDRESS_ASKED,
    FINGERPRINT_ASKED,
    CANCELLED,
    CANCELLED_SHOWN,
    CONTAINER,
    CONTAINER_ASKED,
    COIN_ASKED,
    CTRL_C,
    ENTER,
    INVALID_INPUT,
    ROOT,
    SECRET,
    SETTINGS_QUESTION,
)
from .repair import (
    CARD_ASKED,
    GAP_ASKED,
    REFERENCE_ASKED,
    SEARCH_ASKED,
    TWO_EXPLAINED,
    ZERO_12_DECOY_ADDRESS,
    CONTAINER_PASSPHRASE_ASKED,
    container_with,
)
from .session import Session, run_plainly
from .passwords import CHECK_WORD_PASSWORD


def cancel_before_work(session, label):
    """End a preflight session and check terminal restoration."""
    session.type(CTRL_C)
    assert session.drain_until_exit(10), f"{label}: did not end"
    code, settings = session.close()
    assert code == CANCELLED, f"{label}: exit {code}"
    assert settings == session.original, f"{label}: terminal settings changed"


def scan_gap_options_refuse_invalid_values_and_skip_the_gap_question():
    """
    All five commands validate gaps; a supplied gap reaches search.
    """
    # Read the library's limit instead of typing a second upper bound.
    source = (ROOT / "src/wallet.rs").read_text()
    assert re.search(r"pub const MOST: u32 = HARDENED;", source)
    bits = re.search(r"pub const HARDENED: u32 = (\d+) << (\d+);", source)
    maximum = int(bits[1]) << int(bits[2])
    for command in ("decrypt", "check", "rekey", "wallets", "repair"):
        for gap in (0, maximum + 1):
            result = run_plainly((command, "--scan-gap", str(gap)))
            assert result.returncode == INVALID_INPUT, (command, gap, result.stderr)
            assert b"scan-gap" in result.stderr and result.stdout == b""
    session = Session(("check", "--fingerprint", "--pim", "0", "--scan-gap", "30"),
        capped=sys.platform == "linux")
    session.wait_for(CONTAINER_ASKED)
    session.answer(container_with({5: "?", 16: "?"}) + ENTER, CARD_ASKED)
    session.answer(ENTER, SEARCH_ASKED, TWO_EXPLAINED, limit=120)
    session.answer(b"1", REFERENCE_ASKED)
    session.answer(ZERO_12_DECOY_ADDRESS + ENTER, COIN_ASKED)
    session.answer(ENTER, b"0-1/0-29, 60 addresses", CONTAINER_PASSPHRASE_ASKED)
    assert GAP_ASKED not in session.output, "--scan-gap 30 asked its question"
    cancel_before_work(session, "explicit scan gap")
    print("scan-gap: all five commands refuse bad gaps; 30 skips its question and bounds search")


def explicit_check_paths_are_used_and_misplaced_paths_are_refused():
    """
    The exact address path is shown; malformed/misplaced paths fail.
    """
    path = "m/84'/0'/0'/0/7"
    for arguments in (
        ("check", "--address", "--path", "m/84'/0'/0'/0/x"),
        ("check", "--fingerprint", "--path", path),
    ):
        result = run_plainly(arguments)
        assert result.returncode == INVALID_INPUT and b"path" in result.stderr
    session = Session(("check", "--address", "--pim", "0", "--coin", "bitcoin",
                       "--path", path), capped=sys.platform == "linux")
    session.wait_for(CONTAINER_ASKED)
    session.answer(CONTAINER.encode() + ENTER, b"ontainer password")
    session.answer(SECRET + ENTER, ADDRESS_ASKED)
    session.answer(ZERO_12_DECOY_ADDRESS + ENTER, path.encode())
    assert b"only " + path.encode() in session.output, session.output
    cancel_before_work(session, "check --path")
    print("check --path: the address uses its exact path; bad and fingerprint paths are refused")


def a_check_word_password_has_the_librarys_check_word():
    """
    --check-word makes a checked password, not the ordinary default.
    """
    result = run_plainly(("password", "--check-word"))
    assert result.returncode == 0, result.stderr
    words = result.stdout.split()
    assert len(words) == len(CHECK_WORD_PASSWORD.split()), result.stdout
    # The existing independent known-answer/round-trip check validates
    # the
    # rule. Here the CLI consumes the generated value and must not
    # repair it.
    session = Session(("check", "--fingerprint", "--pim", "0"))
    session.wait_for(CONTAINER_ASKED)
    session.answer(CONTAINER.encode() + ENTER, b"ontainer password")
    session.answer(b" ".join(words) + ENTER, FINGERPRINT_ASKED)
    assert b"Use this password?" not in session.output, session.output
    cancel_before_work(session, "password --check-word")
    print("password --check-word: six generated words pass the password check without repair")


def explicit_repair_options_ask_for_the_card_before_the_password():
    """Decrypt, rekey and wallets all honor --repair."""
    for command in ("decrypt", "rekey", "wallets"):
        session = Session((command, "--pim", "0", "--mem", "0", "--repair"))
        session.wait_for(CONTAINER_ASKED)
        session.answer(CONTAINER.encode() + ENTER, CARD_ASKED)
        assert b"ontainer password:" not in session.output, session.output
        cancel_before_work(session, f"{command} --repair")
    print("--repair: decrypt, rekey and wallets ask for the card immediately after the container")


def passphrase_repair_password_and_memory_options_reach_their_preflights():
    """Explicit answers bypass their questions without full recovery."""
    for command in ("decrypt", "rekey"):
        result = run_plainly((command, "--passphrase-used", "maybe"))
        assert result.returncode == INVALID_INPUT and b"passphrase-used" in result.stderr
    refused = Session(("rekey", "--repair-words", "3"))
    assert refused.drain_until_exit(10), "bad repair count did not end"
    code, settings = refused.close()
    assert code == INVALID_INPUT and settings == refused.original
    assert b"repair words, not 3" in b" ".join(refused.output.split()), refused.output
    assert CONTAINER_ASKED not in refused.output
    session = Session(("rekey", "--pim", "0", "--new-pim", "0", "--new-mem", "0",
                       "--words", "24", "--confirm", "fingerprint",
                       "--passphrase-used", "no", "--repair-words", "0"))
    session.wait_for(CONTAINER_ASKED)
    session.answer(CONTAINER.encode() + ENTER, b"Old container password")
    session.answer(SECRET + ENTER, FINGERPRINT_ASKED)
    assert b"Does the wallet" not in session.output
    cancel_before_work(session, "rekey --passphrase-used no")
    # Decrypt's passphrase question is after recovery. A Rust unit test
    # exercises that pure decision through parsed Options, without
    # Argon2.
    session = Session(("decrypt", "--pim", "0", "--passphrase-used", "no"))
    session.wait_for(CONTAINER_ASKED)
    cancel_before_work(session, "decrypt --passphrase-used no")
    session = Session(("new", "--pim", "0", "--mem", "0", "--wallet-check", "no",
                       "--choose-word", "no", "--repair-words", "0",
                       "--new-password", "words"))
    session.wait_for(b"passphrase of the new wallet")
    session.answer(ENTER, b"Write it down now")
    session.answer(ENTER, b"Shown only once and not stored")
    assert SETTINGS_QUESTION not in session.output
    assert b"let MHFE make one?" not in session.output
    cancel_before_work(session, "new --new-password words --mem 0")
    session = Session(("wallets", "--pim", "0", "--mem", "0"))
    session.wait_for(CONTAINER_ASKED)
    assert b"Which settings" not in session.output
    cancel_before_work(session, "wallets --mem 0")
    print("given answers: rekey and new skip their questions; decrypt and wallets accept theirs")


def test_tool_options_refuse_bad_selections_before_any_argon2_work():
    """
    Vector selection/output and benchmark settings have cheap cases.
    """
    scratch = (ROOT.parent / "tmp/aud024" if (ROOT.parent / "AGENTS.md").exists()
               else ROOT / "target")
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=scratch) as folder:
        output = Path(folder) / "not-created"
        for suite in ((), ("--same-length",)):
            result = run_plainly(("test-vectors", *suite, "--output", str(output),
                                  "--only", "no-such-public-vector"))
            assert result.returncode == INVALID_INPUT and b"selects none" in result.stderr
            assert not output.exists(), "refused selection wrote its output folder"
        output.write_text("public fixture")
        result = run_plainly(("test-vectors", "--output", str(output), "--only", "zero-12"))
        assert result.returncode == 1 and output.read_text() == "public fixture"
        assert b"round" not in result.stdout, result.stdout
    for option in ("--pim", "--mem"):
        result = run_plainly(("test-benchmark", option, "4294967295"))
        assert result.returncode == INVALID_INPUT, result.stderr
    if sys.platform == "linux":
        result = run_plainly(("test-benchmark", "--pim", "0", "--mem", "0"), capped=True)
        assert result.returncode == 4 and b"memory" in result.stderr.lower(), result.stderr
    print("test tools: selections, output failures and explicit settings stop before Argon2")
