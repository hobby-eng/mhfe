# TOOL-01: public fixtures and cases of the Python PTY test runtime.
"""
The program under check, the public test data and the values the cases
look for.

The program and --full come from the command line of
scripts/verify-hidden-input.py, read when this module is first imported.
The exit codes, keys, prompts, records, colours and parts of the
self-test that the cases look for are each named once here; the values
of one group of cases stand next to it in its module.
"""

import argparse
import json
from pathlib import Path
import sys

# The repository, above scripts/ and this package.
ROOT = Path(__file__).resolve().parents[2]


def parse_arguments():
    """
    The program to check, and whether to run the cases that need Argon2
    at full size.
    """
    parser = argparse.ArgumentParser(
        description="Checks the terminal input of the mhfe tool in a pseudo-terminal."
    )
    parser.add_argument("program", nargs="?", default=str(ROOT / "target/debug/mhfe"),
                        help="the mhfe program to check (default: target/debug/mhfe)")
    parser.add_argument("--full", action="store_true",
                        help="also run the cases that need Argon2 at 2 GiB, which take minutes")
    return parser.parse_args()


ARGUMENTS = parse_arguments()
PROGRAM, FULL = ARGUMENTS.program, ARGUMENTS.full
ZERO_12 = json.loads((ROOT / "tests/fixtures/suite3-vectors/zero-12.json").read_text())
CONTAINER, PHRASE = ZERO_12["container"], ZERO_12["inputs"]["phrase"]
# The spelling screen's confirmation, shared by the Unix and Windows
# drivers before either waits for the next input prompt.
READ_BACK_PROMPT = b"Check the written-out words; Enter continues."
ZERO_24 = json.loads((ROOT / "tests/fixtures/suite3-vectors/zero-24.json").read_text())
# Exit codes of the tool when the person cancels, when an answer or the
# setup is refused, when
# the memory for Argon2 cannot be reserved and when a part of the
# program fails its known answers
# (src/bin/mhfe/exit.rs).
CANCELLED, INVALID_INPUT, NOT_ENOUGH_RESOURCES, INTERNAL_ERROR = 130, 2, 4, 1
# The exit codes of a check's three outcomes.
MATCHES, NO_MATCH, NOT_VERIFIED = 0, 3, 5
# What the tool prints next after each kind of answer. An accepted one
# leads to the fingerprint.
# A refused password is asked again ("Please type it again").
REFUSED = b"again"
ACCEPTED = b"ingerprint"
# The private screen: the terminal's alternate screen, cleared before
# the tool leaves it
# (src/bin/mhfe/terminal.rs).
ENTER_PRIVATE, LEAVE_PRIVATE = b"\x1b[?1049h", b"\x1b[2J\x1b[H\x1b[?1049l"
CLEAR = b"\x1b[2J\x1b[H"
BACKSPACE, CTRL_U, CTRL_C = b"\x7f", b"\x15", b"\x03"
# The keys of the menu, as a terminal sends them. Ctrl+Up carries a 5,
# which must not choose
# entry 5.
UP, DOWN, ENTER, CTRL_UP, ESCAPE = b"\x1b[A", b"\x1b[B", b"\r", b"\x1b[1;5A", b"\x1b"
# The menu entry of `mhfe password` when no browser tool lies next to
# the program, and the entry
# of `mhfe self-test` right below it.
PASSWORD_ENTRY = 8
SELF_TEST_ENTRY = PASSWORD_ENTRY + 1
# The entry that shows the help, two below the password entry with mhfe
# self-test between: it is
# the tenth, past the number keys, so it is reached with the arrows from
# the password entry.
HELP_FROM_PASSWORD = 2
# The prompts are matched whole: the "Esc quits" at the end of the first
# must not pass for the menu.
# A password made ends its summary with "bits."; the answers of its kind
# name bits without the stop.
MENU_SHOWN, PASSWORD_MADE = b"Esc quits", b"bits."
BACK_TO_MENU = b"Press Enter to return to the menu (Esc quits)."
PASSWORD_AGAIN = b"Press Enter for another password (Esc returns to the menu)."
# The question of the password entry: five dice words, five words and a
# check word, or sixteen
# random characters.
PASSWORD_KIND = b"What kind of password?"
# What the lists of `mhfe encrypt` show: a list's hint line, the
# explanation behind ?, and the line
# that records the chosen container length.
LIST_SHOWN, EXPLAINED = b"Esc cancels", b"8-character code"
LENGTH_RECORDED = b"Container  24 words (recommended)"
# The question about repair words for the container, and the record of
# "No repair words".
REPAIR_ASKED = b"Repair words for the container phrase?"
# What the tool prints when it is cancelled, by Ctrl+C or Escape.
CANCELLED_SHOWN = b"Cancelled"
REPAIR_RECORDED = b"Repair     No repair words"
PHRASE_RECORDED = b"Phrase     12 words, valid"
# Valid words whose checksum fails: the phrase is refused and asked
# again.
BAD_CHECKSUM = b" ".join([b"abandon"] * 12)
SETTINGS_ASKED, OWN_SETTINGS = b"#settings-pim-and-memory-level", b"PIM 1 \xc2\xb7 memory level 0"
# The question of `mhfe rekey` about the wallet's BIP39 passphrase, for
# the keep list at the end,
# which `mhfe encrypt` does not ask; its two answers, neither of them a
# default; and the record of
# each.
PASSPHRASE_ASKED = b"Does the wallet of this phrase have a BIP39 passphrase?"
PASSPHRASE_ANSWERS = (b"1  No BIP39 passphrase", b"2  It has a BIP39 passphrase")
NO_PASSPHRASE_RECORDED = b"Passphrase No BIP39 passphrase"
PASSPHRASE_RECORDED = b"Passphrase It has a BIP39 passphrase"
# The marker before the marked answer of a list, as "› 1  Label"
# (src/bin/mhfe/choice.rs).
HIGHLIGHT = "›".encode()
# The key hint of that question's list while no answer is marked, and
# once an arrow has marked one
# (hint in src/bin/mhfe/choice.rs).
UNMARKED_HINT = ("↑ ↓ choose · Enter selects once one is marked · 1 or 2 at once · "
                 "Esc cancels").encode()
MARKED_HINT = "↑ ↓ choose · Enter selects · 1 or 2 at once · Esc cancels".encode()
# How long the tool is watched after a key that must do nothing; it
# answers a key at once.
QUIET_SECONDS = 1
# How long a person takes at least to answer what appeared: longer than
# the window in which the
# tool drops keys typed before a list or a screen waited for them
# (TYPED_AHEAD in
# src/bin/mhfe/hidden_input.rs, 200 ms), so that an answer is not taken
# for one typed ahead.
ANSWER_DELAY = 0.25
# The same question at a terminal that cannot redraw a list: numbered
# answers, a prompt without a
# default, and what an empty line or a number out of range gets
# (Input::choose_numbered in
# src/bin/mhfe/terminal.rs).
NUMBERED_ANSWERS = (b"1. No BIP39 passphrase", b"2. It has a BIP39 passphrase")
NUMBERED_PROMPT, NUMBERED_REFUSED = b"Choice: ", b"Type a number from 1 to 2."
# The prompt of the BIP39 passphrase of a wallet that the person said
# has one, which offers no
# Enter for none; what an empty answer gets there; and a passphrase for
# it: the one of BIP39's
# published test vectors (read_passphrase_named in
# src/bin/mhfe/check/passphrase.rs).
KNOWN_PASSPHRASE_ASKED = b"BIP39 passphrase of the wallet: "
PASSPHRASE_REFUSED = b"Type the passphrase: you said the wallet has one."
PUBLIC_PASSPHRASE = b"TREZOR"
# The beginning of every passphrase prompt, also that of `mhfe check`,
# "BIP39 passphrase of the
# wallet, or Enter if it has none: ".
ANY_PASSPHRASE_ASKED = b"BIP39 passphrase of"
# The question of `mhfe rekey` after a recovery without a built-in
# check.
CONFIRMATION_ASKED = b"How should the recovered seed phrase be confirmed?"
# The prompts of a reference of the wallet: the coin of an address, the
# address, the fingerprint.
COIN_ASKED, ADDRESS_ASKED = b"Which coin is the address for?", b"Receiving address ("
FINGERPRINT_ASKED = b"Master key fingerprint, eight hex digits: "
# The title at the top of every step of `mhfe rekey`, and a terminal's
# control sequences.
REKEY_TITLE = "MHFE · Change the password".encode()
CONTROL_SEQUENCE = rb"\x1b\[[0-9;?]*[A-Za-z]"
# A reference of the wallet for that confirmation: the first receiving
# address of BIP84's test
# vectors, a public one, and the master key fingerprint of the public
# zero-12 phrase. Argon2
# never runs here, so neither is ever compared with a recovered phrase.
PUBLIC_ADDRESS, PUBLIC_FINGERPRINT = b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", b"73c5da0a"
# An address space of 1 GiB, too small for the 2 GiB that memory level 0
# reserves for Argon2: a
# rekey that goes on to the long work is refused there, before Argon2
# runs. Only Linux enforces
# this limit (RLIMIT_AS).
ADDRESS_SPACE_CAP = 1 << 30
MEMORY_REFUSED = b"could not reserve 2 GiB of memory for Argon2"
# A key the menu ignores; it appears nowhere in what the menu or `mhfe
# password` print.
IGNORED_KEY = b"Z"
# The control characters a terminal in its usual mode acts on instead of
# passing them on.
TERMINAL_KEYS = {
    "Ctrl+S": b"\x13",
    "Ctrl+Q": b"\x11",
    "Ctrl+V": b"\x16",
    "Ctrl+W": b"\x17",
    "Ctrl+R": b"\x12",
    "Ctrl+O": b"\x0f",
    "Ctrl+\\": b"\x1c",
    "Ctrl+Z": b"\x1a",
}
OTHER_CONTROLS = {
    "TAB": b"\t",
    "NUL": b"\x00",
    "U+0085": "\u0085".encode(),
    "Ctrl+D inside the line": b"\x04",
}
# The longest valid password: 4096 bytes typed, 1024 bytes after NFKD. A
# terminal in line mode
# would cut it after 4095 bytes on Linux.
LONGEST = "\U0001D400".encode() * 1024
SECRET = b"synthetic"
# The variables that turn colour on or off (src/bin/mhfe/style.rs); a
# run that is about colour sets
# the one it checks and passes none of the others on.
COLOUR_VARIABLES = ("NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE")
# mhfe's colours as its terminal output writes them
# (src/bin/mhfe/style.rs): bold cyan for the
# tool's name, grey (bright black) for labels and secondary text, bold
# for what matters and bold
# green for a pass, each ended by a reset.
NAME, GREY, BOLD = "\x1b[1m\x1b[36m", "\x1b[90m", "\x1b[1m"
PASS, RESET = "\x1b[1m\x1b[32m", "\x1b[0m"
COLOUR_CODE = rb"\x1b\[[0-9;]*m"
# Running text is wrapped to 78 columns; a fact's label is padded to 10
# (src/bin/mhfe/style.rs).
TEXT_WIDTH, FACT_LABEL_WIDTH = 78, 10
# The parts `mhfe self-test` tests, in the order of its report, and the
# mark each gets when it
# gives its known answers or its protection holds (verdicts in
# src/bin/mhfe/self_test.rs). Only
# Linux lets a program isolate itself; elsewhere the report says why
# there is nothing to read
# back (IsolationCheck in src/bin/mhfe/protect.rs). Hidden input is
# tested only at a terminal.
# How the self-test words a part that this system cannot test
# (ComponentOutcome::NotAvailable).
NOT_AVAILABLE = "not available here: "
ISOLATED = ("enforced" if sys.platform == "linux"
            else NOT_AVAILABLE + "this system offers none to a program")
SELF_TEST_PARTS = (
    ("Cipher hashes", "as published"),
    ("Argon2id", "as published"),
    ("Cipher rounds", "as published"),
    ("Formats", "as published"),
    ("Container facts", "as published"),
    ("Keep advice", "as published"),
    ("Passwords (Unicode 17)", "as published"),
    ("BIP39 words", "as published"),
    ("Repair words (MHFE-REPAIR-1)", "as published"),
    ("Search for missing words", "as published"),
    ("Password check word (MHFE-PASSWORD-CHECK-1)", "as published"),
    ("Wallet hashes", "as published"),
    ("BIP39 seeds", "as published"),
    ("BIP32 keys", "as published"),
    ("Address encodings", "as published"),
    ("Wallet check (MHFE-WALLET-CHECK-SEED-1)", "as published"),
    ("Hidden wallets", "as published"),
    ("Rekey", "as published"),
    ("Rehearsal", "as published"),
    ("Argon2id at 64 and 256 MiB", "as published"),
    ("Password generator", "as published"),
    ("Password strength estimate", "as published"),
    ("Word hints", "as published"),
    ("Random source", "healthy"),
    ("Address search", "as published"),
    ("Chosen word of a new phrase", "as published"),
    ("Locked memory", "works"),
    ("Core dumps", "off"),
    ("Isolation", ISOLATED),
    ("Hidden input", "echo off"),
)
# The same parts without a terminal on standard input.
SELF_TEST_PARTS_PIPED = (*SELF_TEST_PARTS[:-1], ("Hidden input", NOT_AVAILABLE + "no terminal"))
# What the published vectors cost by the estimate of the default
# settings, which the report and
# the menu state (vectors_cost in src/bin/mhfe/self_test.rs).
VECTORS_COST = "about 2 to 4 minutes, 2 GiB"
ALL_PASSED = "Every part of this program gives its known answers."
SELF_TEST_LINK = "  More: https://github.com/hobby-eng/mhfe#mhfe-self-test"
# The verdict of a self-test that a part failed (alarm in
# src/bin/mhfe/self_test.rs).
SELF_TEST_ALARM = ["✗ A part of this program does NOT give its known answers.",
                   "! Do NOT use it for a real phrase; try another computer or build.",
                   SELF_TEST_LINK]
# The time the self-test took, the one value of its report that differs
# from run to run: below ten
# seconds with a decimal, whole seconds above (seconds() in
# src/bin/mhfe/self_test.rs). A release
# build takes about a second and a debug build about ten; a minute or
# more fails the check.
A_FEW_SECONDS = r"\d\.\d s|[1-5]\d s"
# How long a self-test is waited for, beyond which it counts as hung.
SELF_TEST_SECONDS = 120
# The menu's question for its self-test entry, its two answers with what
# each costs, the first
# marked, and the text the menu leads with.
WHICH_TEST = b"Which test?\r\n" + SELF_TEST_LINK.encode()
SELF_TEST_ANSWERS = ("› 1  Every part                            a few seconds",
                     f"  2  Every part and the published vectors  {VECTORS_COST}")
MENU_TITLE = "MHFE · Memory-Hard Feistel Encryption for BIP39 Mnemonics".encode()
# The first question of `mhfe encrypt`, which the title of its step
# precedes.
ENCRYPT_TITLE = "MHFE · Encrypt a seed phrase".encode()
SETTINGS_QUESTION = b"Which settings should protect the phrase?"
# How an error begins (src/bin/mhfe/style.rs), and what the menu asks
# after a failure at start.
ERROR_MARK = "✗ Error: "
PRESS_ENTER_TO_QUIT = "Press Enter to quit."
# The red of an error as the tool writes it at a terminal: bold, then
# red (BAD in style.rs).
ERROR_RED = "\x1b[1m\x1b[31m"
# The question of `mhfe new` about a wallet check, its answers, neither
# marked at the start
# (AUD-010), the line ? adds below what each answer gives, and the
# record of the answer.
CHECK_ASKED = b"Do you want a check that confirms the password at recovery?"
CHECK_ANSWERS = (b"1  No check", b"2  A phrase + passphrase check")
CHECK_EXPLAINED = b"A draft, for new wallets only."
CHECK_RECORDED = b"  Check "
# The hint of that list while no answer is marked, on two lines, with
# Enter and Esc together on
# the second, and once an arrow has marked one; it offers the
# explanation behind ? too (hint in
# src/bin/mhfe/choice.rs).
CHECK_UNMARKED_HINT = ("↑ ↓ choose · 1 or 2 at once · ? explains both\r\n"
                       "Enter selects once one is marked · Esc cancels").encode()
CHECK_MARKED_HINT = ("↑ ↓ choose · Enter selects · 1 or 2 at once · ? explains both · "
                     "Esc cancels").encode()
# The question of `mhfe new` about a chosen word (chosen_words.rs in the
# tool), what it asks on its
# private screen, the refusal of a position the library does not take,
# the warnings before the draw
# and the record of the wishes, which names no word.
CHOSEN_ASKED = b"Do you want to choose a word of the new phrase?"
CHOSEN_WORD_ASKED = b"Chosen word, or Enter for none"
PLACE_ASKED = b"or Enter for anywhere: "
NEVER_USE_ASKED = b"Word never to use, or Enter for none: "
PLACE_REFUSED = b"the chosen word needs a"
RECOGNISABLE = b"If someone learns or guesses your chosen word, it lets them rule out almost"
AMPLE = b"The phrase keeps about 244 of its 256 random bits: still far more than"
CHOSEN_RECORDED = b"Chosen     1 word, 1 never to use; about 244 random bits"
# The question of `mhfe check` about the reference, the place of "The
# phrase + passphrase check"
# for a 24-word container whose original may be shorter, and what an
# empty passphrase gets there.
COMPARE_ASKED = b"What should the recovered seed phrase be compared with?"
WALLET_CHECK_ENTRY = b"4"
WALLET_CHECK_REFUSED = b"Type the passphrase: the phrase + passphrase check needs one."
# The width of the help texts (HELP_WIDTH in src/bin/mhfe/style.rs), and
# every command of the
# tool, each of whose help must end with examples.
HELP_WIDTH = 80
COMMANDS = ("new", "encrypt", "decrypt", "check", "rekey", "wallets", "repair", "repair-words",
            "password", "self-test", "serve", "test-vectors", "test-benchmark")
# The first Ethereum address of the public zero-12 phrase without a
# passphrase (BIP44, m/44'/60'/
# 0'/0/0), as every Ethereum wallet shows it for that phrase.
PUBLIC_ETHEREUM_ADDRESS = b"0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
# What a command without a terminal says. What a script that compares
# with an address without
# --coin records, and what the refusal of another coin's address then
# adds (SCRIPT_DEFAULT_COIN
# in src/bin/mhfe/check/wallet_reference.rs).
NO_TERMINAL = "There is no terminal to type secrets into."
COIN_ASSUMED = "  Coin       Bitcoin, as no --coin was given"
NAMES_COIN = ("The address cannot be used for the check: without --coin a script compares with a "
              "Bitcoin address, and ", "; name the address's coin with --coin, such as --coin "
              "ethereum")
# How the prompt for the container phrase ends.
CONTAINER_ASKED = b"original seed phrase: "
