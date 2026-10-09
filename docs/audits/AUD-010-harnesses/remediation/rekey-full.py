#!/usr/bin/env python3
"""AUD-010 remediation: `mhfe rekey` at full cost, from the first question to a new container that
opens with the new password (AUD-010, the CLI rekey sealed through the library's Rekey::seal).

    python3 docs/audits/AUD-010-harnesses/remediation/rekey-full.py [program] [--until-reservation]

`program` is the release build to test, target/release/mhfe by default. The run drives
`mhfe rekey --pim 0 --mem 0 --words 12 --new-pim 0 --new-mem 0` in a pseudo-terminal on the public
zero-12 container of tests/fixtures/suite3-vectors/zero-12.json, with standard output in a pipe so
that the new container comes out there once its check has passed:

1. Yes at the question about other wallets, the container, and the vector's public password.
2. The built-in check of the 12-word original confirms the recovery (no question), and the wallet
   is said to have no BIP39 passphrase ("No").
3. No repair words, then a new public test password, typed twice.
4. The program must end with exit code 0, write one new 24-word container to standard output,
   record "Recovered  12 words, passed its built-in check" and keep "the 24 words and the
   password": no passphrase.
5. `mhfe decrypt --stdin --pim 0` of the new container with the new password must give
   "12 verified <the zero-12 phrase>".

Cost: the recovery (12 Argon2 rounds), the sealing (24) and the decryption (12), each at memory
level 0, 2 GiB; about 5 to 10 minutes. Run it alone, capped, as every full-size check here:

    docs/audits/AUD-010-harnesses/run-capped.sh rekey-full \\
      python3 docs/audits/AUD-010-harnesses/remediation/rekey-full.py target/release/mhfe

--until-reservation checks only steps 1 and 2, cheaply: the address space is capped at 1 GiB, so
the program must stop at the reservation of the 2 GiB, with exit code 4, before any Argon2 round.
It needs Linux, which enforces that cap.

Exit code 0 when every step passes, 1 when one fails (its reason on standard error), 2 for an
unknown option. Public test data only.
"""

import fcntl
import json
import os
import re
import resource
import select
import signal
import subprocess
import sys
import termios
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
VECTOR = json.loads((ROOT / "tests/fixtures/suite3-vectors/zero-12.json").read_text())
CONTAINER = VECTOR["container"]
OLD_PASSWORD = VECTOR["inputs"]["password"]
PHRASE = VECTOR["inputs"]["phrase"]
# A new public test password. Four words, so that the check-word review of a six-word password
# (src/check_word.rs) asks nothing.
NEW_PASSWORD = "AUD-010 public rekey test"
ARGUMENTS = ("rekey", "--pim", "0", "--mem", "0", "--words", "12", "--new-pim", "0",
             "--new-mem", "0")

# What the program shows, in the order a rekey asks (src/bin/mhfe/rekey.rs, encrypt.rs,
# plate_repair.rs, terminal.rs).
OTHER_WALLETS = b"backed up another way?"
CONTAINER_ASKED = b"as long as the original: "
OLD_PASSWORD_ASKED = b"Old container password"
PASSPHRASE_ASKED = b"Does the wallet of this phrase have a BIP39 passphrase?"
LIST_SHOWN = b"Esc cancels"
REPAIR_ASKED = b"Repair words for the plate?"
NEW_PASSWORD_ASKED = b"New container password"
REPEAT_ASKED = b"Repeat the new container password"
MEMORY_REFUSED = b"could not reserve 2 GiB of memory for Argon2"
RECOVERED = "Recovered  12 words, passed its built-in check"
NO_PASSPHRASE = "Passphrase No BIP39 passphrase"
KEEP = "the 24 words and the password"
# The keys: the first answer, "No BIP39 passphrase" (the first of two) and "No repair words" (the
# fifth of five), each chosen by its number.
YES, NO_PASSPHRASE_KEY, NO_REPAIR_KEY = b"1", b"1", b"5"
# Exit codes (src/bin/mhfe/exit.rs).
SUCCESS, NOT_ENOUGH_RESOURCES = 0, 4
# Large enough for the checks at start, too small for the 2 GiB of memory level 0.
ADDRESS_SPACE_CAP = 1 << 30
# The questions come within seconds; the recovery and the sealing take minutes each.
QUESTION_SECONDS = 30
RECOVERY_SECONDS = 30 * 60
SEALING_SECONDS = 60 * 60
CONTROL_SEQUENCE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
FACT_LABEL_WIDTH = 10


class Failed(Exception):
    """A step that did not give what it must."""


def environment():
    """No colour, a capable terminal, and nothing else that changes the output."""
    env = {name: value for name, value in os.environ.items()
           if name not in ("NO_COLOR", "CLICOLOR", "CLICOLOR_FORCE", "TERM")}
    env.update(NO_COLOR="1", TERM="xterm-256color")
    return env


class Session:
    """The program on a pseudo-terminal that is its controlling terminal, standard output in a
    pipe."""

    def __init__(self, program, capped):
        self.master, slave = os.openpty()
        os.set_blocking(self.master, False)
        reader, writer = os.pipe()

        def start():
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            if capped:
                resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_SPACE_CAP, ADDRESS_SPACE_CAP))

        self.process = subprocess.Popen(
            [program, *ARGUMENTS], stdin=slave, stdout=writer, stderr=slave,
            start_new_session=True, preexec_fn=start, env=environment())
        os.close(slave)
        os.close(writer)
        self.stdout = reader
        self.output = b""

    def read(self):
        if select.select([self.master], [], [], 0.1)[0]:
            try:
                self.output += os.read(self.master, 65536)
            except OSError:
                time.sleep(0.05)

    def wait_for(self, needle, seconds=QUESTION_SECONDS, since=0):
        end = time.monotonic() + seconds
        while needle not in self.output[since:]:
            if time.monotonic() > end or self.process.poll() is not None:
                self.read()
                if needle in self.output[since:]:
                    break
                tail = self.screen()[-600:]
                raise Failed(f"{needle!r} did not come; the program showed last: {tail!r}")
            self.read()

    def answer(self, keys, *expected, seconds=QUESTION_SECONDS):
        start = len(self.output)
        os.write(self.master, keys)
        for needle in expected:
            self.wait_for(needle, seconds, since=start)

    def finish(self, seconds):
        """Waits for the program to end; returns its exit code and its standard output."""
        end = time.monotonic() + seconds
        while self.process.poll() is None:
            if time.monotonic() > end:
                self.process.send_signal(signal.SIGKILL)
                self.process.wait()
                raise Failed(f"the program did not end within {seconds} s")
            self.read()
        for _ in range(5):
            self.read()
        stdout = b""
        while chunk := os.read(self.stdout, 65536):
            stdout += chunk
        os.close(self.stdout)
        os.close(self.master)
        return self.process.returncode, stdout.decode()

    def screen(self):
        """What the program wrote to the terminal, without control sequences."""
        return CONTROL_SEQUENCE.sub("", self.output.decode("utf-8", "replace"))


def summary_facts(text):
    """The facts in `text`, by label: lines of two spaces, the label padded to its width, one
    space and the value (fact_line in src/bin/mhfe/style.rs). A wrapped value's further lines,
    indented to the value's column, are joined to it; a later fact of the same label wins."""
    facts = {}
    label = None
    value_column = 2 + FACT_LABEL_WIDTH + 1
    for line in text.replace("\r", "").split("\n"):
        if label and line.startswith(" " * value_column) and line.strip():
            facts[label] += " " + line.strip()
        elif (line.startswith("  ") and line[2:3].strip() and len(line) > value_column
              and line[value_column - 1] == " "):
            label = line[2:2 + FACT_LABEL_WIDTH].strip()
            facts[label] = line[value_column:].strip()
        else:
            label = None
    return facts


def up_to_the_long_work(session):
    """Steps 1 and 2: every answer before the recovery."""
    session.wait_for(OTHER_WALLETS)
    session.answer(YES, CONTAINER_ASKED)
    session.answer(CONTAINER.encode() + b"\r", OLD_PASSWORD_ASKED)
    session.answer(OLD_PASSWORD.encode() + b"\r", PASSPHRASE_ASKED, LIST_SHOWN)


def rekey(program):
    """Steps 1 to 4; returns the new container."""
    session = Session(program, capped=False)
    up_to_the_long_work(session)
    # The recovery runs after this answer: the repair question comes once it has passed.
    session.answer(NO_PASSPHRASE_KEY, REPAIR_ASKED, LIST_SHOWN, seconds=RECOVERY_SECONDS)
    session.answer(NO_REPAIR_KEY, NEW_PASSWORD_ASKED)
    session.answer(NEW_PASSWORD.encode() + b"\r", REPEAT_ASKED)
    session.answer(NEW_PASSWORD.encode() + b"\r")
    code, stdout = session.finish(SEALING_SECONDS)
    screen = session.screen()
    if code != SUCCESS:
        raise Failed(f"rekey: exit code {code}; it showed last: {screen[-600:]!r}")
    lines = stdout.split()
    if len(lines) != 24:
        raise Failed(f"rekey: standard output is not one 24-word container: {stdout!r}")
    container = " ".join(lines)
    if container == CONTAINER:
        raise Failed("rekey: the new container is the old one")
    # Each record as the step showed it or as the summary repeats it, and the facts at the end.
    facts = summary_facts(screen)
    for label, expected in (("Recovered", RECOVERED), ("Passphrase", NO_PASSPHRASE)):
        value = facts.get(label)
        if f"{label:<{FACT_LABEL_WIDTH}} {value}" != expected:
            raise Failed(f"rekey: the summary records {label} as {value!r}, not {expected!r}")
    keep = facts.get("Keep")
    if keep != KEEP or "passphrase" in (keep or "").lower():
        raise Failed(f"rekey: Keep is {keep!r}, not {KEEP!r}")
    print(f"PASS rekey: exit code 0, a new 24-word container; {RECOVERED}; Keep {keep}")
    return container


def decrypts_to_the_phrase(program, container):
    """Step 5."""
    answers = f"{container}\n{NEW_PASSWORD}\n".encode()
    result = subprocess.run([program, "decrypt", "--stdin", "--pim", "0"], input=answers,
                            capture_output=True, env=environment(), timeout=RECOVERY_SECONDS)
    expected = f"12 verified {PHRASE}"
    if result.returncode != SUCCESS or result.stdout.decode().strip() != expected:
        raise Failed(f"decrypt --stdin: exit code {result.returncode}, standard output "
                     f"{result.stdout.decode()!r}, not {expected!r}; standard error "
                     f"{result.stderr.decode()[-400:]!r}")
    print("PASS decrypt --stdin: the new container with the new password gives the zero-12 phrase,"
          " verified")


def until_reservation(program):
    """Steps 1 and 2 only, stopped at the reservation by the address space cap."""
    session = Session(program, capped=True)
    up_to_the_long_work(session)
    session.answer(NO_PASSPHRASE_KEY, MEMORY_REFUSED)
    code, stdout = session.finish(QUESTION_SECONDS)
    if code != NOT_ENOUGH_RESOURCES or stdout:
        raise Failed(f"rekey, capped: exit code {code}, standard output {stdout!r}")
    print("PASS rekey, capped: every answer taken up to the reservation, exit code 4")


def main():
    options = [argument for argument in sys.argv[1:] if argument.startswith("--")]
    programs = [argument for argument in sys.argv[1:] if not argument.startswith("--")]
    if set(options) - {"--until-reservation"} or len(programs) > 1:
        print(__doc__, file=sys.stderr)
        return 2
    program = programs[0] if programs else str(ROOT / "target/release/mhfe")
    try:
        if options:
            until_reservation(program)
        else:
            decrypts_to_the_phrase(program, rekey(program))
    except (Failed, OSError, subprocess.SubprocessError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
