"""AUD-010 cli-terminal probe: the wallet-check question of `mhfe new` (CHECK-UI-002).

    python3 docs/audits/AUD-010-harnesses/cli-terminal/new-check-default.py target/release/mhfe

README.md, `mhfe new`: "Only with a passphrase does it then ask whether you want a check that
confirms the password at recovery, with nothing preselected". src/bin/mhfe/new_wallet.rs says the
same above ask_for_check ("Nothing is preselected"). For the passphrase question of `mhfe encrypt`
and `mhfe rekey`, "no default" means: no answer marked, the hint "Enter selects once one is
marked", and Enter alone doing nothing (src/bin/mhfe/choice.rs, choose_without_default).

The probe runs `mhfe new --pim 0` in a pseudo-terminal of 80 x 24, types a synthetic passphrase
twice, and at the check question:
- N1 reads whether an answer is marked ("›") and which hint is shown;
- N2 presses Enter alone and watches whether the command goes on to its next question ("Repair
  words for the plate?") within two seconds;
then presses Escape, which cancels (exit code 130) before any phrase is drawn and before Argon2;
- N3 the summary on the main screen records the check answer, if one was taken.
Exits 1 when an answer is preselected (N1) or Enter alone chooses one (N2).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ptyrun import Pty, plain  # noqa: E402

PROGRAM = sys.argv[1] if len(sys.argv) > 1 else "target/release/mhfe"
PASSPHRASE = b"synthetic probe passphrase"
QUESTION = b"Do you want a check that confirms the password at recovery?"
NEXT_QUESTION = b"Repair words for the plate?"
LEAVE_ALTERNATE = b"\x1b[?1049l"


def main():
    session = Pty(PROGRAM, ["new", "--pim", "0"])
    steps = []
    ok = session.wait_for(b"or Enter for none: ", limit=30)
    steps.append(f"passphrase prompt shown: {ok}")
    session.type(PASSPHRASE + b"\r")
    ok = ok and session.wait_for(b"Repeat the passphrase: ", limit=10)
    session.type(PASSPHRASE + b"\r")
    at_question = session.wait_for(b"Esc cancels", limit=10, since=0) and QUESTION in session.output
    start = session.output.rfind(QUESTION)
    block = plain(session.output[start:]).decode("utf-8", "replace")
    marked = [line.strip() for line in block.split("\n") if line.strip().startswith("›")]
    hint = next((line.strip() for line in block.split("\n") if "Esc cancels" in line), "")
    preselected = bool(marked) or "once one is marked" not in hint
    print(f"{'FAIL' if preselected else 'PASS'} N1 check question: question shown {at_question}; "
          f"marked {marked or 'none'}; hint {hint!r}")
    before_enter = len(session.output)
    session.type(b"\r")
    session.idle(2.0)
    went_on = NEXT_QUESTION in session.output[before_enter:]
    print(f"{'FAIL' if went_on else 'PASS'} N2 Enter alone: the command "
          f"{'went on to' if went_on else 'stayed at the question, not'} {NEXT_QUESTION.decode()!r}")
    session.type(b"\x1b")
    code = session.finish(limit=20)
    left = session.output.rfind(LEAVE_ALTERNATE)
    summary = plain(session.output[left:]).decode("utf-8", "replace") if left >= 0 else ""
    check_record = next((line.strip() for line in summary.split("\n") if line.strip().startswith("Check")), None)
    leaked = PASSPHRASE in session.output[left:] if left >= 0 else True
    print(f"INFO N3 exit code {code}; summary check record {check_record!r}; passphrase on the main "
          f"screen {leaked}; steps: {'; '.join(steps)}")
    failed = preselected or went_on or leaked or code != 130 or not at_question
    print("new-check-default: " + ("FAILED" if failed else "passed"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
