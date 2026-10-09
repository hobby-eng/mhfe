"""AUD-010 cli-terminal probe: scripts mode (--stdin), refusals and exit codes (CHECK-UI-002).

    python3 docs/audits/AUD-010-harnesses/cli-terminal/scripts-mode.py target/release/mhfe

Expected results come from README.md ("For scripts", the exit-code table), each command's --help,
src/bin/mhfe/exit.rs and AGENTS.md ("Terminal output": running text wraps at 78 columns, a red
"✗ Error:" line). Standard input, output and error are pipes. Every run that would reach Argon2's
2 GiB gets an address space of 1 GiB, so that it stops at the reservation with exit code 4 before
any round: what it read before is then checked without Argon2 work. Only public BIP39 vectors and
synthetic passwords are typed; a generated password is counted, never printed.

Checks:
- S1 refusals before Argon2 end with exit code 2 and nothing on standard output: input that ends
  early, an invalid word (whose text is not echoed), a wrong checksum, an empty password, two
  passwords that differ, an invalid container, --words 24, a built-in check of a container that has
  none, an invalid fingerprint, a repair-word count of 3, --stdin without its required option;
- S2 the documented order of answers is read: encrypt (phrase, password, password again), decrypt
  (container, password), check --words (container, password), check --address and --fingerprint
  (container, password, reference, passphrase), each reaching the reservation (exit 4) with
  standard output empty;
- S3 repair-words and repair round-trip: four bare words on standard output, then the plate with
  one "?" repaired to the container, both without escape bytes;
- S4 `mhfe password` in a pipe gives five bare words and exit 0, without escape bytes; counts out of
  range give exit code 2;
- S5 a command refused for want of a terminal names only options that the command accepts;
- S6 every "✗ Error:" line fits the 78-column text width;
- S7 a script's --address without --coin: an EVM address is refused with a message that names the
  coin assumed (the --coin help: "a script means bitcoin");
- S8 every other line the tool writes on standard error (titles, facts, hints, warnings) fits the
  78-column text width.
Exits 1 when any check fails.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ptyrun import ZERO_12, ZERO_24, plain, run_pipe, visible_width  # noqa: E402

PROGRAM = sys.argv[1] if len(sys.argv) > 1 else "target/release/mhfe"
TEXT_WIDTH = 78
PASSWORD = "synthetic probe password"
BITCOIN_ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"  # BIP84 vector, docs/BROWSER-PACKAGE.md
EVM_ADDRESS = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"  # BIP39 "abandon ... about" account 0
MARKER = "zzqmarker"

results = []
error_lines = []
other_lines = []


def record(check, ok, detail):
    results.append((check, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'} {check}: {detail}")


def lines(*answers):
    return "".join(f"{answer}\n" for answer in answers).encode()


def run(arguments, stdin=b"", capped=False):
    code, out, err = run_pipe(PROGRAM, arguments, stdin=stdin, capped=capped)
    for line in err.split(b"\n"):
        if b"\xe2\x9c\x97 Error:" in line:
            error_lines.append((" ".join(arguments), visible_width(line), plain(line).decode()))
        elif line.strip():
            other_lines.append((" ".join(arguments), visible_width(line), plain(line).decode()))
    return code, out, err


def check_refusals():
    cases = [
        ("encrypt, input ended", ["encrypt", "--stdin"], b""),
        ("encrypt, invalid word", ["encrypt", "--stdin"],
         lines(" ".join(["abandon"] * 11 + [MARKER]), PASSWORD, PASSWORD)),
        ("encrypt, wrong checksum", ["encrypt", "--stdin"],
         lines(" ".join(["abandon"] * 12), PASSWORD, PASSWORD)),
        ("encrypt, empty password", ["encrypt", "--stdin"], lines(ZERO_12, "", "")),
        ("encrypt, passwords differ", ["encrypt", "--stdin"], lines(ZERO_12, PASSWORD, PASSWORD + "x")),
        ("decrypt, invalid container", ["decrypt", "--stdin"], lines("abandon about", PASSWORD)),
        ("check --words 24", ["check", "--stdin", "--words", "24"], lines(ZERO_24, PASSWORD)),
        ("check --words 12, 12-word container", ["check", "--stdin", "--words", "12"], lines(ZERO_12, PASSWORD)),
        ("check --fingerprint, invalid", ["check", "--stdin", "--fingerprint"], lines(ZERO_24, PASSWORD, "xyz", "")),
        ("repair-words --count 3", ["repair-words", "--stdin", "--count", "3"], lines(ZERO_24)),
        ("repair-words --stdin alone", ["repair-words", "--stdin"], lines(ZERO_24)),
        ("check --stdin alone", ["check", "--stdin"], lines(ZERO_24, PASSWORD)),
    ]
    wrong = []
    for label, arguments, stdin in cases:
        code, out, err = run(arguments, stdin)
        if code != 2 or out:
            wrong.append(f"{label}: exit {code}, stdout {len(out)} bytes")
        if MARKER.encode() in err:
            wrong.append(f"{label}: the typed word is echoed")
    record("S1 refusals", not wrong, "; ".join(wrong) or f"{len(cases)} refusals with exit 2, stdout empty")


def check_answer_order():
    cases = [
        ("encrypt", ["encrypt", "--stdin"], lines(ZERO_12, PASSWORD, PASSWORD), [b"Phrase", b"typed twice"]),
        ("decrypt", ["decrypt", "--stdin"], lines(ZERO_24, PASSWORD), [b"Password"]),
        ("check --words 12", ["check", "--stdin", "--words", "12"],
         lines(" ".join(["abandon"] * 23 + ["art"]), PASSWORD), [b"Password"]),
        ("check --address", ["check", "--stdin", "--address"],
         lines(ZERO_24, PASSWORD, BITCOIN_ADDRESS, ""), [b"native SegWit", b"Passphrase none"]),
        ("check --address --coin ethereum", ["check", "--stdin", "--address", "--coin", "ethereum"],
         lines(ZERO_24, PASSWORD, EVM_ADDRESS, ""), [b"Passphrase none"]),
        ("check --fingerprint", ["check", "--stdin", "--fingerprint"],
         lines(ZERO_24, PASSWORD, "73c5da0a", ""), [b"Passphrase none"]),
    ]
    wrong = []
    for label, arguments, stdin, expected in cases:
        code, out, err = run(arguments, stdin, capped=True)
        missing = [needle.decode() for needle in expected if needle not in plain(err)]
        if code != 4 or out or missing:
            wrong.append(f"{label}: exit {code}, stdout {len(out)} bytes, missing {missing}")
    record("S2 order of answers", not wrong, "; ".join(wrong) or f"{len(cases)} commands reached the reservation")


def check_repair_round_trip():
    code, card, err = run(["repair-words", "--stdin", "--count", "4"], lines(ZERO_24))
    words = card.decode().split()
    ok = code == 0 and len(words) == 4 and card.count(b"\n") == 1 and b"\x1b" not in card + err
    plate = ZERO_24.split()
    plate[2] = "?"
    code2, repaired, err2 = run(["repair", "--stdin"], lines(" ".join(plate), " ".join(words)))
    ok2 = code2 == 0 and repaired.decode().strip() == ZERO_24 and b"\x1b" not in repaired + err2
    record("S3 repair round trip", ok and ok2,
           f"repair-words exit {code}, {len(words)} words; repair exit {code2}, container restored "
           f"{repaired.decode().strip() == ZERO_24}")


def check_password():
    code, out, err = run(["password"])
    count = len(out.decode().split())
    ok = code == 0 and count == 5 and b"\x1b" not in out + err
    bad = []
    for arguments in (["password", "--words", "0"], ["password", "--words", "33"],
                      ["password", "--chars", "0"], ["password", "--chars", "65"]):
        refused, refused_out, _ = run(arguments)
        if refused != 2 or refused_out:
            bad.append(f"{' '.join(arguments)}: exit {refused}")
    record("S4 password", ok and not bad, f"exit {code}, {count} words (not printed); refusals: {bad or 'all exit 2'}")


def accepts_stdin(command):
    code, _, err = run_pipe(PROGRAM, [command, "--stdin", "--help"])
    return code == 0


def check_terminal_refusal_advice():
    cases = [
        ("password", ["password", "--dice"], b""),
        ("rekey", ["rekey", "--pim", "0"], lines("1", ZERO_24, "1")),
    ]
    wrong = []
    for command, arguments, stdin in cases:
        code, out, err = run(arguments, stdin)
        text = plain(err).decode()
        advises_stdin = "--stdin" in text
        if code != 2:
            wrong.append(f"{' '.join(arguments)}: exit {code}")
        if advises_stdin and not accepts_stdin(command):
            message = next(line for line in text.split("\n") if "--stdin" in line)
            wrong.append(f"{' '.join(arguments)} advises --stdin, which `mhfe {command}` refuses: {message.strip()!r}")
    record("S5 refusal advice", not wrong, "; ".join(wrong) or "only accepted options named")


def check_error_width():
    wide = [f"{label}: {width} columns: {text[:70]}..." for label, width, text in error_lines if width > TEXT_WIDTH]
    record("S6 error width", not wide, f"{len(wide)} of {len(error_lines)} error lines wider than {TEXT_WIDTH}:\n    "
           + "\n    ".join(wide))


def check_script_coin():
    code, out, err = run(["check", "--stdin", "--address"], lines(ZERO_24, PASSWORD, EVM_ADDRESS, ""))
    message = next((line for line in plain(err).decode().split("\n") if "Error" in line), "")
    names_coin = "bitcoin" in message.lower() or "coin" in message.lower()
    record("S7 script coin", code == 2 and names_coin, f"exit {code}, message {message.strip()!r}")


def check_other_width():
    # A prompt answered from a pipe is not echoed, so the next text follows it on the same line;
    # such joined lines are an effect of the pipe, not of the tool's layout.
    wide = sorted({f"{label}: {width} columns: {text.strip()}" for label, width, text in other_lines
                   if width > TEXT_WIDTH and "Choice [" not in text and "Choice: " not in text})
    record("S8 message width", not wide, f"{len(wide)} distinct lines of {len(other_lines)} wider than "
           f"{TEXT_WIDTH}:\n    " + "\n    ".join(wide))


def main():
    check_refusals()
    check_answer_order()
    check_repair_round_trip()
    check_password()
    check_terminal_refusal_advice()
    check_script_coin()
    check_error_width()
    check_other_width()
    failed = [check for check, ok, _ in results if not ok]
    print(f"scripts-mode: {len(results) - len(failed)} passed, {len(failed)} failed: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
