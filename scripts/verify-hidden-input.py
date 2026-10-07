"""Checks the terminal input of the mhfe tool in a pseudo-terminal (Linux and macOS).

    python3 scripts/verify-hidden-input.py [path/to/mhfe]

The default is target/debug/mhfe. At a terminal every step of a command has a screen of its own on
the terminal's alternate screen, and the main screen gets only the summary, when the command ends.
It drives `mhfe check --fingerprint --pim 0`, which reads the container on a step of its own, taken
at once, and then the container password on another, and stops the tool before a fingerprint is
given, so no memory is reserved and Argon2 never runs; the PIM given skips the question of the
settings. Only the public zero-12 test container is used.

It checks that
- every control character in a password reaches the password check and is refused, including
  the ones a terminal would otherwise act on (Ctrl+S, Ctrl+Q, Ctrl+V, Ctrl+W, Ctrl+R, Ctrl+O,
  Ctrl+\\, Ctrl+Z and Ctrl+D inside the line), and that a Unicode password is accepted, also the
  longest one: 1024 characters U+1D400, 4096 bytes that NFKD turns into 1024;
- Backspace and Ctrl+U edit the line: a TAB typed and then deleted leaves an accepted password;
- the password is shown as it is typed only on the alternate screen, which is cleared and left
  before the summary, and none of its control characters is ever written back;
- Ctrl+C at the password ends the tool with exit code 130 and leaves the alternate screen;
- the terminal settings are exactly the original ones afterwards, after a normal answer and after
  Ctrl+C.

A password with a check word (MHFE-PASSWORD-CHECK-1) is repaired only on the person's choice and
before Argon2: a word typed as ? is restored as the third public vector says, "chokehold", with the
repair as the first answer, also after a stray leading space, which the repair removes; a wrong word
gets the question with the password as typed first, and "Type the password again" asks for it
again. The summary records how the check word came out and none of the words.

A command started directly runs in a network namespace with only inactive loopback where the
system allows user namespaces. Its summary says "isolated network, no new sockets or file writes";
elsewhere it says "no new sockets or file writes" for seccomp and Landlock alone. Previously opened
descriptors are not revoked by these restrictions.

It also drives the menu that `mhfe` shows when it starts without arguments: the arrow keys and Enter
choose an entry, its number chooses it at once, other escape sequences (Ctrl+Up) and keys do
nothing and are not shown, q and a lone Escape quit with exit code 0 and Ctrl+C with 130, and the
terminal settings are restored either way. The `mhfe password` entry shows each password on one
private screen, which it clears for the next one on Enter and when Escape or q returns to the menu;
the help entry returns on Enter. Neither needs secret input.

It answers the first question of `mhfe rekey`, which every user gets: whether the funds of other
wallets on the container are moved or backed up another way (AUD-007-FUN002). Yes goes on to the
container, No stops with exit code 130 before anything is typed, and so does Escape; the question
never asks for another wallet or its password.

A rekey asks whether the wallet has a BIP39 passphrase (multi-chain-wallet-tools AUD-022-API004)
once, as soon as the kind of confirmation is known, for every kind: the next screen after the
password when a 12-word phrase is confirmed by its built-in check, and after the choice of an
address, the fingerprint or showing the phrase otherwise. It shows both answers and the link to the
README section of the command, and no reference or passphrase is asked before it. The question has
no default: no answer is marked and the hint says "Enter selects once one is marked", Enter alone
leaves the list as it is and records nothing, an arrow marks an answer and the hint then says
"Enter selects", and a digit chooses at once. After "No BIP39 passphrase" an address or the
fingerprint is read without a passphrase prompt. After "It has a BIP39 passphrase" it is followed by
"BIP39 passphrase of the wallet", without the "Enter if it has none" of `mhfe check`: an empty one
is refused with "Type the passphrase: you said the wallet has one." and asked again, and a typed one
is taken and never reaches the main screen. The built-in check and showing the phrase ask for no
passphrase either way. On Linux these runs get an address space too small for the 2 GiB of memory
level 0: whatever they ask comes before the memory is reserved, and the reservation is refused
before Argon2 runs, with exit code 4. The summary then holds exactly one "Passphrase" record, the
answer, after the choice of the confirmation and before the reference. Other systems do not enforce
that limit, so there every run stops with Escape at the question, after the arrow.

Last, it answers the questions of `mhfe encrypt` up to the password, so again without Argon2: its
own settings, PIM 1 after a mistyped one; the phrase, refused once for its checksum and then taken
without a question; the length question on a cleared screen, where ? explains both lengths and the
arrows and Enter keep 24 words; whether the wallet has a BIP39 passphrase, on a cleared screen with
both answers, none marked, and the link to the README section of the command, where Enter alone
does nothing and ↑ marks the last answer for Enter, as the hint then says; no repair words; Ctrl+C
at the repeated password ends the tool. The summary then records the settings, the phrase's length,
the container's, the passphrase and the repair choice, in the order they were asked, and holds none
of the questions.
Escape at a list cancels with exit code 130. The phrase is the public zero-12 test phrase and the
password a synthetic one, which never reaches the main screen. A script, `mhfe encrypt --stdin`, is
not asked about the passphrase: it gives the phrase and two passwords that differ, which end the
tool with exit code 2 before Argon2. A terminal that cannot redraw a list (TERM=dumb) gets the
question of `mhfe encrypt --pim 0` with numbered answers after the hidden phrase, prompted as
"Choice: " without a default: an empty line, or a number out of range, gets "Type a number from 1
to 2." and the prompt again, and 2 goes on to the hidden password, where Ctrl+C ends the tool. The
phrase is never shown there.

Finally it checks that a phrase the person did not ask to export is shown only on a private screen
(AUD-007-SEC001): `mhfe new` and `mhfe wallets` refuse to start, before anything is asked and with
nothing on standard output, when standard output goes to a pipe or to a second terminal
(AUD-008-SEC004) or TERM is dumb, while `mhfe new` at a terminal goes on to its first question;
and `mhfe rekey` offers to show the phrase for the owner's comparison only when standard output is
the terminal. Neither gets as far as Argon2.

`mhfe new` asks whether the new phrase gets a wallet check with nothing marked either (AUD-010):
after the passphrase typed twice, an Enter typed ahead with the repeated passphrase and an Enter at
the list do nothing and record nothing, the hint offers "? explains both" on its first line and
says "Enter selects once one is marked · Esc cancels" on its second, ? shows what each answer gives
and costs and leaves none marked, ↓ marks "No check" and the hint then fits one line, and Escape
cancels with exit code 130 before the question about repair words. The passphrase, a synthetic
one, never reaches the main screen.

`mhfe check` offers "The phrase + passphrase check" only with a BIP39 passphrase, as the library
and the browser package do (AUD-010): after the public zero-12 container, a password and the
choice, it asks "BIP39 passphrase of the wallet" without "Enter if it has none", refuses an empty
one with "Type the passphrase: the phrase + passphrase check needs one." and asks again, and takes
BIP39's public test passphrase; on Linux the capped run then stops at the memory reservation, with
exit code 4 and "Passphrase typed" in the summary.

What a person reads without a terminal and in a script follows the tool's style (AUD-010). A usage
error, such as an unknown option, a missing argument or two that cannot go together, is one
"✗ Error:" line, bold red in colour, followed by clap's tip, the usage and its pointer to --help,
with exit code 2, nothing on standard output and no clap "error:"; --help and --version still
print to standard output with exit code 0. The help of the tool and of every command, -h and
--help, fits 80 columns and has an "Examples:" section. A long error, the one for a phrase whose
checksum fails in `mhfe encrypt --stdin`, is wrapped to 78 columns under its mark. Without a
terminal, `mhfe password --dice` and a piped `mhfe rekey` say to run the command in a terminal and
name no --stdin, which they do not have, while `mhfe encrypt` names it. `mhfe check --stdin
--address` without --coin compares with a Bitcoin address, as in v0.5.0, and says so: its summary
records "Coin       Bitcoin, as no --coin was given", and the public Ethereum address of the
zero-12 phrase is refused with exit code 2 by an error that names Bitcoin and --coin. On Linux the
capped run with the phrase's public Bitcoin address, and the one with --coin ethereum and its
Ethereum address, which records no such line, stop at the memory reservation with exit code 4.

Every command that handles a secret, and the menu, first compares every part of the program with
its known answers; when they pass, nothing shows: `mhfe encrypt` writes its first step first and
the menu its title. `mhfe self-test` runs these checks and the slower ones, up to Argon2 at 256 MiB,
never the 2 GiB of the published vectors. At a terminal its report lists every part with its mark
of a pass, in mhfe's colours, names each part while it is tested and erases that line, and ends
with ✓ and exit code 0. With NO_COLOR, and with its output in a pipe, the report holds no colour
codes. The menu's self-test entry asks "Which test?" and offers both tests; Escape returns to the
menu, and the first runs the same report. Copies of the program with one bit flipped in a known
answer of the checks at start, a repair card and a check-word vector, stop `mhfe encrypt` before
it asks anything, and the menu before it is shown, with "✗ Error: Self-test at start failed", the
part and what differed, and exit code 1; their self-test names the part too. The copies are made
in a temporary folder (TMPDIR), signed again on macOS, and deleted afterwards.
"""

import fcntl
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import subprocess
import sys
import tempfile
import termios
import textwrap
import time

ROOT = Path(__file__).resolve().parent.parent
PROGRAM = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "target/debug/mhfe")
ZERO_12 = json.loads((ROOT / "tests/fixtures/suite3-vectors/zero-12.json").read_text())
CONTAINER, PHRASE = ZERO_12["container"], ZERO_12["inputs"]["phrase"]
# Exit codes of the tool when the person cancels, when an answer or the setup is refused, when
# the memory for Argon2 cannot be reserved and when a part of the program fails its known answers
# (src/bin/mhfe/exit.rs).
CANCELLED, INVALID_INPUT, NOT_ENOUGH_RESOURCES, INTERNAL_ERROR = 130, 2, 4, 1
# What the tool prints next after each kind of answer. An accepted one leads to the fingerprint.
# A refused password is asked again ("Please type it again").
REFUSED = b"again"
ACCEPTED = b"ingerprint"
# The private screen: the terminal's alternate screen, cleared before the tool leaves it
# (src/bin/mhfe/terminal.rs).
ENTER_PRIVATE, LEAVE_PRIVATE = b"\x1b[?1049h", b"\x1b[2J\x1b[H\x1b[?1049l"
CLEAR = b"\x1b[2J\x1b[H"
BACKSPACE, CTRL_U, CTRL_C = b"\x7f", b"\x15", b"\x03"
# The keys of the menu, as a terminal sends them. Ctrl+Up carries a 5, which must not choose entry 5.
UP, DOWN, ENTER, CTRL_UP, ESCAPE = b"\x1b[A", b"\x1b[B", b"\r", b"\x1b[1;5A", b"\x1b"
# The menu entry of `mhfe password` when no browser tool lies next to the program, and the entry
# of `mhfe self-test` right below it.
PASSWORD_ENTRY = 8
SELF_TEST_ENTRY = PASSWORD_ENTRY + 1
# The entry that shows the help, two below the password entry with mhfe self-test between: it is
# the tenth, past the number keys, so it is reached with the arrows from the password entry.
HELP_FROM_PASSWORD = 2
# The prompts are matched whole: the "Esc quits" at the end of the first must not pass for the menu.
MENU_SHOWN, PASSWORD_MADE = b"Esc quits", b"bits"
BACK_TO_MENU = b"Press Enter to return to the menu (Esc quits)."
PASSWORD_AGAIN = b"Press Enter for another password (Esc returns to the menu)."
# The question of the password entry: five dice words, five words and a check word, or sixteen
# random characters.
PASSWORD_KIND = b"What kind of password?"
# What the lists of `mhfe encrypt` show: a list's hint line, the explanation behind ?, and the line
# that records the chosen container length.
LIST_SHOWN, EXPLAINED = b"Esc cancels", b"8-character code"
LENGTH_RECORDED = b"Container  24 words (recommended)"
# The question about repair words for the plate, and the record of "No repair words".
REPAIR_ASKED, REPAIR_RECORDED = b"Repair words for the plate?", b"Repair     No repair words"
PHRASE_RECORDED = b"Phrase     12 words, valid"
# Valid words whose checksum fails: the phrase is refused and asked again.
BAD_CHECKSUM = b" ".join([b"abandon"] * 12)
SETTINGS_ASKED, OWN_SETTINGS = b"#settings-pim-and-memory-level", b"PIM 1 \xc2\xb7 memory level 0"
# The question of `mhfe encrypt` and `mhfe rekey` about the wallet's BIP39 passphrase, for the keep
# list at the end; its two answers, neither of them a default; and the record of each.
PASSPHRASE_ASKED = b"Does the wallet of this phrase have a BIP39 passphrase?"
PASSPHRASE_ANSWERS = (b"1  No BIP39 passphrase", b"2  It has a BIP39 passphrase")
NO_PASSPHRASE_RECORDED = b"Passphrase No BIP39 passphrase"
PASSPHRASE_RECORDED = b"Passphrase It has a BIP39 passphrase"
# The marker before the marked answer of a list, as "› 1  Label" (src/bin/mhfe/choice.rs).
HIGHLIGHT = "›".encode()
# The key hint of that question's list while no answer is marked, and once an arrow has marked one
# (hint in src/bin/mhfe/choice.rs).
UNMARKED_HINT = ("↑ ↓ choose · Enter selects once one is marked · 1 or 2 at once · "
                 "Esc cancels").encode()
MARKED_HINT = "↑ ↓ choose · Enter selects · 1 or 2 at once · Esc cancels".encode()
# How long the tool is watched after a key that must do nothing; it answers a key at once.
QUIET_SECONDS = 1
# The same question at a terminal that cannot redraw a list: numbered answers, a prompt without a
# default, and what an empty line or a number out of range gets (Input::choose_numbered in
# src/bin/mhfe/terminal.rs).
NUMBERED_ANSWERS = (b"1. No BIP39 passphrase", b"2. It has a BIP39 passphrase")
NUMBERED_PROMPT, NUMBERED_REFUSED = b"Choice: ", b"Type a number from 1 to 2."
# The prompt of the BIP39 passphrase of a wallet that the person said has one, which offers no
# Enter for none; what an empty answer gets there; and a passphrase for it: the one of BIP39's
# published test vectors (read_known_passphrase in src/bin/mhfe/check.rs).
KNOWN_PASSPHRASE_ASKED = b"BIP39 passphrase of the wallet: "
PASSPHRASE_REFUSED = b"Type the passphrase: you said the wallet has one."
PUBLIC_PASSPHRASE = b"TREZOR"
# The beginning of every passphrase prompt, also that of `mhfe check`, "BIP39 passphrase of the
# wallet, or Enter if it has none: ".
ANY_PASSPHRASE_ASKED = b"BIP39 passphrase of"
# The question of `mhfe rekey` after a recovery without a built-in check.
CONFIRMATION_ASKED = b"How should the recovered seed phrase be confirmed?"
# The prompts of a reference of the wallet: the coin of an address, the address, the fingerprint.
COIN_ASKED, ADDRESS_ASKED = b"Which coin is the address for?", b"Receiving address ("
FINGERPRINT_ASKED = b"Master key fingerprint, eight hex digits: "
# The title at the top of every step of `mhfe rekey`, and a terminal's control sequences.
REKEY_TITLE = "MHFE · Change the password".encode()
CONTROL_SEQUENCE = rb"\x1b\[[0-9;?]*[A-Za-z]"
# A reference of the wallet for that confirmation: the first receiving address of BIP84's test
# vectors, a public one, and the master key fingerprint of the public zero-12 phrase. Argon2
# never runs here, so neither is ever compared with a recovered phrase.
PUBLIC_ADDRESS, PUBLIC_FINGERPRINT = b"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", b"73c5da0a"
# An address space of 1 GiB, too small for the 2 GiB that memory level 0 reserves for Argon2: a
# rekey that goes on to the long work is refused there, before Argon2 runs. Only Linux enforces
# this limit (RLIMIT_AS).
ADDRESS_SPACE_CAP = 1 << 30
MEMORY_REFUSED = b"could not reserve 2 GiB of memory for Argon2"
# A key the menu ignores; it appears nowhere in what the menu or `mhfe password` print.
IGNORED_KEY = b"Z"
# The control characters a terminal in its usual mode acts on instead of passing them on.
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
# The longest valid password: 4096 bytes typed, 1024 bytes after NFKD. A terminal in line mode
# would cut it after 4095 bytes on Linux.
LONGEST = "\U0001D400".encode() * 1024
SECRET = b"synthetic"
# The variables that turn colour on or off (src/bin/mhfe/style.rs); a run that is about colour sets
# the one it checks and passes none of the others on.
COLOUR_VARIABLES = ("NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE")
# mhfe's colours as its terminal output writes them (src/bin/mhfe/style.rs): bold cyan for the
# tool's name, grey (bright black) for labels and secondary text, bold for what matters and bold
# green for a pass, each ended by a reset.
NAME, GREY, BOLD = "\x1b[1m\x1b[36m", "\x1b[90m", "\x1b[1m"
PASS, RESET = "\x1b[1m\x1b[32m", "\x1b[0m"
COLOUR_CODE = rb"\x1b\[[0-9;]*m"
# Running text is wrapped to 78 columns; a fact's label is padded to 10 (src/bin/mhfe/style.rs).
TEXT_WIDTH, FACT_LABEL_WIDTH = 78, 10
# The parts `mhfe self-test` tests, in the order of its report, and the mark each gets when it
# gives its known answers or its protection holds (verdicts in src/bin/mhfe/self_test.rs). Only
# Linux lets a program isolate itself; elsewhere the report says why there is nothing to read
# back (IsolationCheck in src/bin/mhfe/protect.rs). Hidden input is tested only at a terminal.
ISOLATED = ("enforced" if sys.platform == "linux"
            else "not available here: this system offers none to a program")
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
    ("Random source", "healthy"),
    ("Address search", "as published"),
    ("Locked memory", "works"),
    ("Core dumps", "off"),
    ("Isolation", ISOLATED),
    ("Hidden input", "echo off"),
)
# The same parts without a terminal on standard input.
SELF_TEST_PARTS_PIPED = (*SELF_TEST_PARTS[:-1], ("Hidden input", "not available here: no terminal"))
# What the published vectors cost by the estimate of the default settings, which the report and
# the menu state (vectors_cost in src/bin/mhfe/self_test.rs).
VECTORS_COST = "about 2 to 4 minutes, 2 GiB"
ALL_PASSED = "Every part of this program gives its known answers."
SELF_TEST_LINK = "  More: https://github.com/hobby-eng/mhfe#mhfe-self-test"
# The verdict of a self-test that a part failed (alarm in src/bin/mhfe/self_test.rs).
SELF_TEST_ALARM = ["✗ A part of this program does NOT give its known answers.",
                   "! Do NOT use it for a real phrase; try another computer or build.",
                   SELF_TEST_LINK]
# The time the self-test took, the one value of its report that differs from run to run: below ten
# seconds with a decimal, whole seconds above (seconds() in src/bin/mhfe/self_test.rs). A release
# build takes about a second and a debug build about ten; a minute or more fails the check.
A_FEW_SECONDS = r"\d\.\d s|[1-5]\d s"
# How long a self-test is waited for, beyond which it counts as hung.
SELF_TEST_SECONDS = 120
# The menu's question for its self-test entry, its two answers with what each costs, the first
# marked, and the text the menu leads with.
WHICH_TEST = b"Which test?\r\n" + SELF_TEST_LINK.encode()
SELF_TEST_ANSWERS = ("› 1  Every part                            a few seconds",
                     f"  2  Every part and the published vectors  {VECTORS_COST}")
MENU_TITLE = "MHFE · Memory-Hard Feistel Encryption for BIP39 Mnemonics".encode()
# The first question of `mhfe encrypt`, which the title of its step precedes.
ENCRYPT_TITLE = "MHFE · Encrypt a seed phrase".encode()
SETTINGS_QUESTION = b"Which settings should protect the phrase?"
# How an error begins (src/bin/mhfe/style.rs), and what the menu asks after a failure at start.
ERROR_MARK = "✗ Error: "
PRESS_ENTER_TO_QUIT = "Press Enter to quit."
# The red of an error as the tool writes it at a terminal: bold, then red (BAD in style.rs).
ERROR_RED = "\x1b[1m\x1b[31m"
# The question of `mhfe new` about a wallet check, its answers, neither marked at the start
# (AUD-010), the line ? adds below what each answer gives, and the record of the answer.
CHECK_ASKED = b"Do you want a check that confirms the password at recovery?"
CHECK_ANSWERS = (b"1  No check", b"2  A phrase + passphrase check")
CHECK_EXPLAINED = b"A draft, for new wallets only."
CHECK_RECORDED = b"  Check "
# The hint of that list while no answer is marked, on two lines, with Enter and Esc together on
# the second, and once an arrow has marked one; it offers the explanation behind ? too (hint in
# src/bin/mhfe/choice.rs).
CHECK_UNMARKED_HINT = ("↑ ↓ choose · 1 or 2 at once · ? explains both\r\n"
                       "Enter selects once one is marked · Esc cancels").encode()
CHECK_MARKED_HINT = ("↑ ↓ choose · Enter selects · 1 or 2 at once · ? explains both · "
                     "Esc cancels").encode()
# The question of `mhfe check` about the reference, the place of "The phrase + passphrase check"
# for a 24-word container whose original may be shorter, and what an empty passphrase gets there.
COMPARE_ASKED = b"What should the recovered seed phrase be compared with?"
WALLET_CHECK_ENTRY = b"4"
WALLET_CHECK_REFUSED = b"Type the passphrase: the phrase + passphrase check needs one."
# The width of the help texts (HELP_WIDTH in src/bin/mhfe/style.rs), and every command of the
# tool, each of whose help must end with examples.
HELP_WIDTH = 80
COMMANDS = ("new", "encrypt", "decrypt", "check", "rekey", "wallets", "repair", "repair-words",
            "password", "self-test", "serve", "test-vectors", "test-benchmark")
# The first Ethereum address of the public zero-12 phrase without a passphrase (BIP44, m/44'/60'/
# 0'/0/0), as every Ethereum wallet shows it for that phrase.
PUBLIC_ETHEREUM_ADDRESS = b"0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
# What a command without a terminal says. What a script that compares with an address without
# --coin records, and what the refusal of another coin's address then adds (SCRIPT_DEFAULT_COIN
# in src/bin/mhfe/check.rs).
NO_TERMINAL = "There is no terminal to type secrets into."
COIN_ASSUMED = "  Coin       Bitcoin, as no --coin was given"
NAMES_COIN = ("The address cannot be used for the check: without --coin a script compares with a "
              "Bitcoin address, and ", "; name the address's coin with --coin, such as --coin "
              "ethereum")


def attach_terminal():
    """Makes the pseudo-terminal the controlling terminal, so that Ctrl+C sends SIGINT."""
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def attach_terminal_capped():
    """attach_terminal, and the address space limited to ADDRESS_SPACE_CAP."""
    attach_terminal()
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_CAP, ADDRESS_SPACE_CAP))


def tool_environment(colour=False, term=None):
    """The environment of the tool: NO_COLOR unless `colour`, and nothing else that turns colour on
    or off. A capable terminal unless `term` names another: the shell that runs the checks may
    itself be a dumb one, as some editors' consoles are."""
    environment = {name: value for name, value in os.environ.items()
                   if name not in COLOUR_VARIABLES}
    environment["TERM"] = term or "xterm-256color"
    if not colour:
        environment["NO_COLOR"] = "1"
    return environment


class Session:
    def __init__(self, arguments=("check", "--fingerprint", "--pim", "0"), stdout=None, term=None,
                 capped=False, colour=False, program=PROGRAM):
        """`stdout` replaces the terminal as standard output, such as a pipe; `term` sets TERM;
        `capped` limits the address space, so that the memory for Argon2 is refused; `colour`
        leaves out NO_COLOR; `program` runs another copy of the tool."""
        self.master, self.slave = os.openpty()
        os.set_blocking(self.master, False)
        # The settings are read through the master side: on macOS the slave side stops answering
        # once the tool, the leader of its session, has ended, because the system revokes the
        # terminal of an ended session. The master side reads the same terminal on every system.
        self.original = termios.tcgetattr(self.master)
        environment = tool_environment(colour, term)
        self.process = subprocess.Popen(
            [program, *arguments],
            stdin=self.slave, stdout=self.slave if stdout is None else stdout, stderr=self.slave,
            start_new_session=True,
            preexec_fn=attach_terminal_capped if capped else attach_terminal, env=environment,
        )
        self.output = b""

    def wait_for(self, *needles, limit=10, since=None):
        """Reads until one of `needles` appears after the text already seen, or after the place
        `since` in it; returns it."""
        start = len(self.output) if since is None else since
        end = time.monotonic() + limit
        while time.monotonic() < end:
            if select.select([self.master], [], [], 0.1)[0]:
                try:
                    self.output += os.read(self.master, 4096)
                except OSError:
                    break
            for needle in needles:
                if needle in self.output[start:]:
                    return needle
        raise AssertionError(f"none of {needles} in {self.output[start:]!r}")

    def answer(self, keys, *expected, limit=10):
        """Types `keys` and reads until every one of `expected` has appeared after them. A list
        and its question arrive together, so each is looked for in all that followed the keys."""
        start = len(self.output)
        self.type(keys)
        end = time.monotonic() + limit
        while not all(needle in self.output[start:] for needle in expected):
            if time.monotonic() > end:
                raise AssertionError(f"not all of {expected} in {self.output[start:]!r}")
            if select.select([self.master], [], [], 0.1)[0]:
                try:
                    self.output += os.read(self.master, 4096)
                except OSError:
                    time.sleep(0.05)

    def idle(self, keys, seconds=QUIET_SECONDS):
        """Types `keys` and returns all that the tool wrote in the `seconds` after them."""
        start = len(self.output)
        self.type(keys)
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if select.select([self.master], [], [], 0.1)[0]:
                try:
                    self.output += os.read(self.master, 4096)
                except OSError:
                    time.sleep(0.05)
        return self.output[start:]

    def type(self, data, limit=10):
        """Writes `data` as pasted text; the line only ends at the carriage return.

        A pseudo-terminal holds little input (about 1 KiB on macOS), so a long paste is written
        in parts as the tool reads them. The tool's output is read meanwhile, so that neither
        side waits for the other, and a tool that stops reading fails the check instead of
        blocking it for ever.
        """
        end = time.monotonic() + limit
        while data:
            if time.monotonic() > end:
                raise AssertionError(f"the tool stopped reading; {len(data)} bytes left to type")
            readable, writable, _ = select.select([self.master], [self.master], [], 0.1)
            if readable:
                try:
                    self.output += os.read(self.master, 4096)
                except OSError:
                    pass
            if writable:
                try:
                    data = data[os.write(self.master, data):]
                except BlockingIOError:
                    pass

    def close(self):
        """Ends the tool as a person would, with Ctrl+C, so that it can restore the terminal."""
        if self.process.poll() is None:
            self.type(CTRL_C)
            if not self.drain_until_exit(5):
                # SIGKILL leaves the terminal as it is; the settings check below then fails.
                self.process.send_signal(signal.SIGKILL)
        if not self.drain_until_exit(10):
            raise AssertionError("the tool did not end")
        code = self.process.returncode
        settings = termios.tcgetattr(self.master)
        os.close(self.master)
        os.close(self.slave)
        return code, settings

    def drain_until_exit(self, limit):
        """Waits up to `limit` seconds for the tool to end, reading its output meanwhile.

        On macOS a process that ends waits until the terminal has delivered its last output, which
        happens only when this side reads it; without reading, the tool never finishes exiting.
        """
        end = time.monotonic() + limit
        while self.process.poll() is None:
            if time.monotonic() > end:
                return False
            if select.select([self.master], [], [], 0.1)[0]:
                try:
                    self.output += os.read(self.master, 4096)
                except OSError:
                    time.sleep(0.05)
        return True

    def at_password_prompt(self):
        self.wait_for(b"original: ")
        # The container is read on its own private screen and taken at once.
        self.answer(CONTAINER.encode() + b"\r", b"Container password: ")


def shown_privately(label, output, secret):
    """The secret was shown on the private screen and nowhere after the tool left it."""
    entered = output.rfind(ENTER_PRIVATE, 0, output.find(secret))
    assert entered >= 0, f"{label}: the password was shown off the private screen"
    left = output.find(LEAVE_PRIVATE, entered)
    assert left >= 0, f"{label}: the private screen was not left"
    assert secret not in output[left:], f"{label}: the password reached the main screen"


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
    session.type(b"q")
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
    print("menu: password regeneration, Escape/q return, private screens cleared, terminal restored")
    print("menu: the password entry asks for words or characters and makes both")

    # Escape alone: the tool waits a moment for the rest of an arrow key's sequence, then quits.
    session = Session(arguments=())
    session.wait_for(MENU_SHOWN)
    session.type(ESCAPE)
    assert session.drain_until_exit(10), "menu: Escape did not end the tool"
    code, settings = session.close()
    assert code == 0, f"menu: Escape gave exit code {code}"
    assert settings == session.original, "menu: Escape did not restore the terminal settings"
    print("menu: a lone Escape quits, exit code 0, terminal restored")

    session = Session(arguments=())
    session.wait_for(MENU_SHOWN)
    session.type(CTRL_C)
    session.wait_for(b"Cancelled")
    code, settings = session.close()
    assert code == CANCELLED, f"menu: Ctrl+C gave exit code {code}"
    assert settings == session.original, "menu: Ctrl+C did not restore the terminal settings"
    print("menu: Ctrl+C, exit code 130, terminal restored")


def check_rekey_asks_about_other_wallets():
    question = b"backed up another way?"
    for label, key, expected in (("Yes", b"1", (b"original: ",)),
                                 ("No", b"2", (b"Move the funds", b"Cancelled")),
                                 ("Escape", ESCAPE, (b"Cancelled",))):
        session = Session(("rekey", "--pim", "0", "--words", "24"))
        session.wait_for(question)
        session.answer(key, *expected)
        code, settings = session.close()
        assert code == CANCELLED, f"rekey, {label}: exit code {code}"
        assert settings == session.original, f"rekey, {label}: terminal settings changed"
        asked = session.output[: session.output.find(question)]
        assert b"Password" not in asked, f"rekey, {label}: a password was asked first"
        if label != "Yes":
            assert b"original: " not in session.output, f"rekey, {label}: went on to the container"
        result = "goes on to the container" if label == "Yes" else "stops, exit code 130"
        print(f"rekey: {label} at the question about other wallets {result}")


def passphrase_question(command):
    """The question about the wallet's passphrase as a terminal shows it, with the link to the
    README section of `command` on the next line, as part of the question."""
    return PASSPHRASE_ASKED + b"\r\n  More: https://github.com/hobby-eng/mhfe#mhfe-" + command


def check_no_default(label, session):
    """The question about the passphrase, just shown as a list, has no answer marked and a hint
    that says so, and Enter alone leaves it as it is: nothing is redrawn, erased or recorded."""
    question = session.output.rfind(PASSPHRASE_ASKED)
    # The whole list first, up to the line break after its key hint, the last thing it writes: the
    # hint of a list shown before may have passed for it.
    session.wait_for(LIST_SHOWN + b"\r\n", since=question)
    shown = session.output[question:]
    assert HIGHLIGHT not in shown, f"{label}: an answer to the passphrase question was marked"
    assert b"\r\n" + UNMARKED_HINT + b"\r\n" in shown, f"{label}: the hint is not {UNMARKED_HINT!r}"
    written = session.idle(ENTER)
    assert written == b"", f"{label}: Enter alone answered the passphrase question: {written!r}"


def rekey_at_old_password(words, capped):
    """Starts `mhfe rekey` for a phrase of `words` words, with the address space capped when
    `capped`, and answers up to the old container password."""
    session = Session(("rekey", "--pim", "0", "--words", words), capped=capped)
    session.wait_for(b"backed up another way?")
    session.answer(b"1", b"original: ")
    session.answer(CONTAINER.encode() + b"\r", b"container password: ")
    return session


def asked_next(label, session, since, typed=b""):
    """The question about the passphrase is the next screen after the keys typed at `since`: only
    `typed`, what the prompt before showed of them, the cleared screen and the title of the step
    come in between. No reference of the wallet, passphrase or memory for the long work was asked
    for before it."""
    question = session.output.find(PASSPHRASE_ASKED, since)
    between = re.sub(CONTROL_SEQUENCE, b"", session.output[since:question])
    between = between.replace(typed, b"").replace(REKEY_TITLE, b"")
    assert between.strip() == b"", f"rekey, {label}: {between!r} before the passphrase question"
    for prompt in (COIN_ASKED, ADDRESS_ASKED, FINGERPRINT_ASKED, ANY_PASSPHRASE_ASKED,
                   MEMORY_REFUSED):
        assert prompt not in session.output[:question], (
            f"rekey, {label}: {prompt!r} came before the passphrase question")


def give_the_reference(session, kind, select, then):
    """Answers the question about the passphrase with the keys `select` and types the reference of
    the wallet that the confirmation `kind` needs, if any; `then` is what the tool shows after the
    last of these keys."""
    if kind == "an address":
        # Bitcoin, the first coin, is marked at the start: Enter takes it.
        steps = ((select, (COIN_ASKED, LIST_SHOWN)), (ENTER, (ADDRESS_ASKED,)),
                 (PUBLIC_ADDRESS + b"\r", then))
    elif kind == "the fingerprint":
        steps = ((select, (FINGERPRINT_ASKED,)), (PUBLIC_FINGERPRINT + b"\r", then))
    else:
        steps = ((select, then),)
    for keys, expected in steps:
        session.answer(keys, *expected)


def ended_before_argon2(label, session):
    """The capped rekey went on to the long work and was refused its memory, before Argon2; returns
    the summary on the main screen."""
    # The refusal is written once, at the end; it may have been read with the last answer already.
    session.wait_for(MEMORY_REFUSED, since=0)
    assert session.drain_until_exit(10), f"rekey, {label}: the refusal did not end the tool"
    code, settings = session.close()
    assert code == NOT_ENOUGH_RESOURCES, f"rekey, {label}: exit code {code}"
    assert settings == session.original, f"rekey, {label}: terminal settings changed"
    return session.output[session.output.rfind(LEAVE_PRIVATE):]


def stopped_at_the_question(label, session):
    """Escape at the question about the passphrase, where a system without the address space cap
    stops a rekey before the long work."""
    session.answer(ESCAPE, b"Cancelled")
    code, settings = session.close()
    assert code == CANCELLED, f"rekey, {label}: Escape gave exit code {code}"
    assert settings == session.original, f"rekey, {label}: terminal settings changed"
    print(f"rekey, {label}: asked, none marked; Escape stops, exit code 130")


def check_rekey_asks_about_the_passphrase():
    """The question about the wallet's passphrase comes once, right after the kind of confirmation
    is known, for every kind and before any reference or passphrase is read
    (multi-chain-wallet-tools AUD-022-API004). Only a wallet with a passphrase is then asked for it,
    and only with an address or the fingerprint; it may not be empty there."""
    capped = sys.platform == "linux"
    # On a screen of its own, as every step.
    asked = (CLEAR, passphrase_question(b"rekey"), *PASSPHRASE_ANSWERS, LIST_SHOWN)
    for kind, words, confirmation, mark, select, has_one in (
        # A 12-word phrase has a built-in check: nothing is chosen after the password. ↓ marks the
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
        records = re.findall(rb"(?m)^  Passphrase ", summary)
        assert len(records) == 1, f"rekey, {label}: {len(records)} Passphrase records, not one"
        assert PASSPHRASE_ASKED not in summary, f"rekey, {label}: the question reached the summary"
        # Recorded where it was asked: after the choice of the confirmation, before the reference.
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
    session.answer(IGNORED_KEY + DOWN + UP + ENTER, CLEAR, passphrase_question(b"encrypt"),
                   *PASSPHRASE_ANSWERS, LIST_SHOWN)
    check_no_default("encrypt", session)
    # ↑ with nothing marked marks the last answer, and the hint then offers Enter, which takes it.
    session.answer(UP, HIGHLIGHT + b" " + PASSPHRASE_ANSWERS[1], MARKED_HINT)
    session.answer(ENTER, CLEAR, REPAIR_ASKED, LIST_SHOWN)
    # No repair words: they would appear only after the encryption, which this test never reaches.
    session.answer(b"5", b"Container password: ")
    session.answer(SECRET + b"\r", b"Repeat the container password: ")
    session.answer(SECRET + CTRL_C, b"Cancelled")
    assert session.drain_until_exit(10), "encrypt: Ctrl+C did not end the tool"
    code, settings = session.close()
    assert code == CANCELLED, f"encrypt: Ctrl+C gave exit code {code}"
    assert settings == session.original, "encrypt: the terminal settings were not restored"
    shown_privately("encrypt", session.output, SECRET)
    assert IGNORED_KEY not in session.output, "encrypt: a key was shown"
    # The steps stayed on the alternate screen; the main screen got the summary when it ended.
    summary = session.output[session.output.rfind(LEAVE_PRIVATE):]
    records = (OWN_SETTINGS, PHRASE_RECORDED, LENGTH_RECORDED, PASSPHRASE_RECORDED,
               REPAIR_RECORDED)
    for record in records:
        assert record in summary, f"encrypt: the summary lacks {record!r}"
    # The passphrase is asked after the container's length and before the repair words.
    places = [summary.find(record) for record in records]
    assert places == sorted(places), "encrypt: the summary is not in the order of the questions"
    for step in (b"How long should", b"seed phrase: ", EXPLAINED, PASSPHRASE_ASKED):
        assert step not in summary, f"encrypt: {step!r} reached the main screen"
    print("encrypt: own settings; phrase refused once, then taken at once; ? and the arrows")
    print("encrypt: asks about the passphrase after the length, with its link; records the answer")
    print("encrypt: the passphrase question has no default; Enter alone does nothing, ↑ then Enter")
    print("encrypt: password shown only on the alternate screen; Ctrl+C leaves it, exit code 130")
    print("encrypt: every step on a cleared screen; only the summary on the main screen")

    session = Session(arguments=("encrypt",))
    session.answer(b"", SETTINGS_ASKED, LIST_SHOWN)
    session.answer(ESCAPE, b"Cancelled")
    assert session.drain_until_exit(10), "encrypt: Escape did not end the tool"
    code, settings = session.close()
    assert code == CANCELLED, f"encrypt: Escape gave exit code {code}"
    assert settings == session.original, "encrypt: Escape did not restore the terminal settings"
    print("encrypt: Escape at a list cancels, exit code 130, terminal restored")


def check_encrypt_script():
    """A script gives the phrase and the password twice, one per line, and is not asked about the
    wallet's passphrase: the two lines after the phrase are taken as the passwords. They differ,
    which ends the tool before Argon2. A question would show its text and take the first password
    line as its answer instead."""
    lines = b"\n".join((PHRASE.encode(), SECRET, SECRET + b"x")) + b"\n"
    result = subprocess.run([PROGRAM, "encrypt", "--stdin"], input=lines, capture_output=True,
                            env=dict(os.environ, NO_COLOR="1"), timeout=30)
    assert result.returncode == INVALID_INPUT, f"encrypt --stdin: exit code {result.returncode}"
    assert b"The two passwords differ" in result.stderr, f"encrypt --stdin: {result.stderr!r}"
    assert PASSPHRASE_ASKED not in result.stderr, "encrypt --stdin: asked about the passphrase"
    assert NUMBERED_PROMPT not in result.stderr, "encrypt --stdin: asked to choose"
    assert result.stdout == b"", "encrypt --stdin: wrote to standard output"
    print("encrypt --stdin: not asked about the passphrase; two different passwords end it, code 2")


def check_encrypt_numbered():
    """A terminal that cannot redraw a list gets the question about the passphrase with numbered
    answers and a prompt without a default; an empty line is refused and the prompt asked again.
    The settings are given, so the hidden phrase is the first answer; the container keeps 24 words
    and no repair words are asked, as neither can be a list there."""
    session = Session(("encrypt", "--pim", "0"), term="dumb")
    session.wait_for(b"Original seed phrase (hidden): ")
    session.answer(PHRASE.encode() + b"\r", PASSPHRASE_ASKED, *NUMBERED_ANSWERS, NUMBERED_PROMPT)
    shown = session.output[session.output.rfind(PASSPHRASE_ASKED):]
    assert b"[1]" not in shown, "encrypt, TERM=dumb: the prompt offers a default"
    for typed in (b"", b"3"):
        session.answer(typed + b"\r", NUMBERED_REFUSED, NUMBERED_PROMPT)
    session.answer(b"2\r", b"Container password (hidden): ")
    session.answer(CTRL_C, b"Cancelled")
    assert session.drain_until_exit(10), "encrypt, TERM=dumb: Ctrl+C did not end the tool"
    code, settings = session.close()
    assert code == CANCELLED, f"encrypt, TERM=dumb: Ctrl+C gave exit code {code}"
    assert settings == session.original, "encrypt, TERM=dumb: the terminal settings changed"
    assert PHRASE.encode() not in session.output, "encrypt, TERM=dumb: the phrase was shown"
    print("encrypt, TERM=dumb: numbered answers, \"Choice: \" without a default, the phrase hidden")
    print("encrypt, TERM=dumb: an empty line and a number out of range refused, then 2 taken")


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
            code, settings = session.close()
            assert code == INVALID_INPUT, f"{command}, {label}: exit code {code}"
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
        code, settings = session.close()
        label = "standard output on another terminal"
        assert code == INVALID_INPUT, f"{command}, {label}: exit code {code}"
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
        # Everyone confirms that other wallets' funds are safe (AUD-007-FUN002).
        session.wait_for(b"backed up another way?")
        session.answer(b"1", b"original: ")
        session.answer(CONTAINER.encode() + b"\r", b"container password: ")
        session.answer(SECRET + b"\r", b"confirmed?", LIST_SHOWN)
        offered = b"Show me the phrase" in session.output
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
    session.answer(ESCAPE, b"Cancelled")
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


def check_wallet_check_needs_a_passphrase():
    """`mhfe check` takes the phrase + passphrase check only with a passphrase (AUD-010)."""
    capped = sys.platform == "linux"
    session = Session(("check", "--pim", "0"), capped=capped)
    session.wait_for(b"original: ")
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


def run_plainly(arguments, data=b"", colour=False, capped=False):
    """Runs the tool with `data` on standard input and both outputs in pipes, without a terminal;
    `colour` forces colour on, and `capped` limits the address space as for a Session."""
    environment = tool_environment(colour)
    if colour:
        environment["CLICOLOR_FORCE"] = "1"
    limit = None
    if capped:
        def limit():
            resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_CAP, ADDRESS_SPACE_CAP))
    return subprocess.run([PROGRAM, *arguments], input=data, capture_output=True, env=environment,
                          timeout=30, preexec_fn=limit)


def check_usage_errors_and_help():
    """Usage errors read as errors of the tool, and every help fits its width with examples."""
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


def check_script_messages():
    """Errors wrap at the text width, the advice without a terminal names only what a command has,
    and a script that compares with an address without --coin is told that Bitcoin is assumed
    (AUD-010)."""
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
    for arguments, data, names_stdin in (
        (("password", "--dice"), b"", False),
        (("rekey", "--pim", "0", "--words", "24"), b"1\n" + container + b"\n", False),
        (("encrypt", "--pim", "0"), b"", True),
    ):
        label = " ".join(arguments)
        result = run_plainly(arguments, data)
        said = " ".join(result.stderr.decode().split())
        assert result.returncode == INVALID_INPUT, f"{label}: exit code {result.returncode}"
        assert NO_TERMINAL in said, f"{label}: {said!r}"
        assert ("--stdin" in said) == names_stdin, f"{label}: {said!r}"
    print("without a terminal: --stdin named only by a command that has it")

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


def wrapped(text, width):
    """`text` broken into lines of at most `width` characters at its spaces, as mhfe wraps running
    text (wrap in src/bin/mhfe/style.rs)."""
    return textwrap.wrap(text, width, break_long_words=False, break_on_hyphens=False)


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
        first, *rest = wrapped(mark, TEXT_WIDTH - column)
        lines.append(f"  {paint(GREY, label.ljust(width))}  {paint(PASS, first)}")
        lines.extend(" " * column + paint(PASS, line) for line in rest)
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
    session.type(ESCAPE)
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
    session.answer(ESCAPE, b"Cancelled")
    assert session.drain_until_exit(10), "encrypt: Escape did not end the tool"
    code, _ = session.close()
    assert code == CANCELLED, f"encrypt: Escape gave exit code {code}"
    print("encrypt: the checks at start pass unseen; its first step comes first")

    session = Session(arguments=())
    session.wait_for(MENU_SHOWN)
    before = session.output[:session.output.find(MENU_TITLE)]
    assert before == b"\r\n", f"menu: {before!r} before its title"
    session.type(b"q")
    assert session.drain_until_exit(10), "menu: q did not end the tool"
    code, _ = session.close()
    assert code == 0, f"menu: q gave exit code {code}"
    print("menu: the checks at start pass unseen; its title comes first")


# Known answers that the checks at start compare, each held once in the program, with the part
# that compares it and what that part reports once a bit of the text is flipped, at start and in
# the full self-test: the six repair words of the plate of the suite 3 vector zero-12
# (MHFE-REPAIR-1), and the third vector of MHFE-PASSWORD-CHECK-1, both public vectors of the
# specification (vectors/profiles/README.md). At start only zero-12's plate gets its cards; the
# full self-test makes the cards of four plates.
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


def main():
    # Each result is shown at once, so that a CI log shows how far the checks came.
    sys.stdout.reconfigure(line_buffering=True)
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
    session.wait_for(b"Cancelled")
    code, settings = session.close()
    assert code == CANCELLED, f"Ctrl+C: exit code {code}"
    assert settings == session.original, "Ctrl+C: the terminal settings were not restored"
    shown_privately("Ctrl+C", session.output, SECRET)
    print("cancelled: Ctrl+C at the password, exit code 130, private screen left, terminal restored")

    check_check_word()
    check_empty_network()
    check_menu()
    check_rekey_asks_about_other_wallets()
    check_rekey_asks_about_the_passphrase()
    check_encrypt_lists()
    check_encrypt_script()
    check_encrypt_numbered()
    check_private_reveals()
    check_new_check_question()
    check_wallet_check_needs_a_passphrase()
    check_usage_errors_and_help()
    check_script_messages()
    check_quiet_start()
    check_self_test()
    check_damaged_copies()


if __name__ == "__main__":
    main()
