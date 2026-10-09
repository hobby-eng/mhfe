"""AUD-010 cli-terminal probe: help texts and colour rules of the mhfe tool (CHECK-UI-003).

    python3 docs/audits/AUD-010-harnesses/cli-terminal/help-and-colour.py target/release/mhfe

The workspace terminal rules (AGENTS.md "Terminal output") and the tool's own constants
(src/bin/mhfe/style.rs: HELP_WIDTH 80, TEXT_WIDTH 78) are the expected results. It checks:

- C1 every help text (`mhfe --help`, `-h` and `--help` of every command, `mhfe help <command>`) with
  CLICOLOR_FORCE=1 uses only the sixteen standard colours, bold and resets;
- C2 the same texts carry no escape byte in a pipe without colour variables;
- C3 no line of a help text is wider than HELP_WIDTH, 80 columns;
- C4 `mhfe --help` has the overview, then "Usage:", "Commands:", "Options:" and "Examples:" in this
  order, grey notes and a yellow (bold) safety line last;
- C5 every command's help has "Usage:", "Options:" and "Examples:";
- C6 a usage error (an unknown option) ends with exit code 2 and is shown as a red "✗ Error:";
- C7 colour variables in a pipe, for clap's help and for the tool's own messages (`mhfe
  repair-words --stdin --count 4` with the public 24-word zero container): none -> no colour;
  CLICOLOR_FORCE=1 -> colour; NO_COLOR=1 with CLICOLOR_FORCE=1 -> no colour; CLICOLOR=0 -> no
  colour; TERM=dumb with CLICOLOR_FORCE=1 -> colour;
- C8 the same in a pseudo-terminal: TERM=xterm-256color -> colour; NO_COLOR=1, TERM=dumb and
  CLICOLOR=0 -> no colour; CLICOLOR_FORCE=1 with TERM=dumb -> colour; and no colour code other
  than C1's.

Prints PASS or FAIL per check with the evidence and exits 1 when any check fails. Runs no Argon2
beyond the checks at start (1 MiB) and reads no secret.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ptyrun import ALLOWED_SGR, ZERO_24, Pty, plain, run_pipe, sgr_parameters, visible_width  # noqa: E402

PROGRAM = sys.argv[1] if len(sys.argv) > 1 else "target/release/mhfe"
HELP_WIDTH = 80
COMMANDS = [
    "new", "encrypt", "decrypt", "check", "rekey", "wallets", "repair", "repair-words",
    "password", "self-test", "serve", "test-vectors", "test-benchmark",
]

results = []


def record(check, ok, detail):
    results.append((check, ok, detail))
    print(f"{'PASS' if ok else 'FAIL'} {check}: {detail}")


def help_texts(**settings):
    """Every help text as (label, bytes); clap writes help to standard output."""
    texts = []
    for arguments in [["--help"], ["-h"]] + [[c, flag] for c in COMMANDS for flag in ("-h", "--help")] + [
        ["help", c] for c in COMMANDS
    ]:
        code, out, err = run_pipe(PROGRAM, arguments, **settings)
        texts.append((" ".join(arguments), code, out + err))
    return texts


def check_help_colours():
    coloured = help_texts(CLICOLOR_FORCE="1")
    bad = {}
    for label, _, text in coloured:
        extra = sgr_parameters(text) - ALLOWED_SGR
        if extra:
            bad[label] = sorted(extra)
    record("C1 help colours", not bad, f"parameters outside the sixteen colours: {bad or 'none'}")
    plain_texts = help_texts()
    escaped = [label for label, _, text in plain_texts if b"\x1b" in text]
    record("C2 help in a pipe", not escaped, f"texts with an escape byte: {escaped or 'none'}")
    wide = []
    for label, _, text in plain_texts:
        for line in text.split(b"\n"):
            if visible_width(line) > HELP_WIDTH:
                wide.append(f"{label}: {visible_width(line)} columns: {line.decode().strip()[:60]}...")
    record("C3 help width", not wide, f"{len(wide)} lines wider than {HELP_WIDTH}:\n    " + "\n    ".join(wide))
    return coloured, plain_texts


def check_main_help(coloured):
    text = dict((label, t) for label, _, t in coloured)["--help"]
    lines = text.split(b"\n")
    plain_lines = [plain(line).decode() for line in lines]
    order = [plain_lines.index(h) if h in plain_lines else -1 for h in ("Usage: mhfe <COMMAND>",)]
    headings = ["Commands:", "Options:", "Examples:"]
    positions = [plain_lines.index(h) if h in plain_lines else -1 for h in headings]
    usage = next((i for i, l in enumerate(plain_lines) if l.startswith("Usage:")), -1)
    ordered = usage > 0 and all(p > usage for p in positions) and positions == sorted(positions)
    overview = usage > 0 and any(l.strip() for l in plain_lines[:usage])
    last = next(line for line in reversed(lines) if plain(line).strip())
    params_last = sgr_parameters(last)
    yellow_last = 33 in params_last and 1 in params_last
    grey_note = any(90 in sgr_parameters(line) and b"trusted computer" in line for line in lines)
    ok = ordered and overview and yellow_last and grey_note and order[0] >= 0
    record(
        "C4 main help layout",
        ok,
        f"overview={overview}, Usage/Commands/Options/Examples in order={ordered}, "
        f"grey note={grey_note}, last line yellow bold={yellow_last}: {plain(last).decode()!r}",
    )


def check_command_help(plain_texts):
    missing = []
    for label, code, text in plain_texts:
        if label in ("--help", "-h"):
            continue
        lines = [plain(line).decode() for line in text.split(b"\n")]
        for heading in ("Options:", "Examples:"):
            if heading not in lines:
                missing.append(f"{label}: no {heading}")
        if not any(line.startswith("Usage:") for line in lines):
            missing.append(f"{label}: no Usage:")
    record("C5 command help sections", not missing, f"{len(missing)} missing:\n    " + "\n    ".join(missing))


def check_usage_error():
    code, out, err = run_pipe(PROGRAM, ["encrypt", "--no-such-option"], CLICOLOR_FORCE="1")
    first = next((line for line in err.split(b"\n") if line.strip()), b"")
    starts = plain(first).decode()
    red = 31 in sgr_parameters(first)
    ok = code == 2 and starts.startswith("✗ Error:") and red and not out
    record("C6 usage error", ok, f"exit {code}, stdout {len(out)} bytes, first line {starts!r}, red={red}")


def tool_run(**settings):
    code, out, err = run_pipe(
        PROGRAM, ["repair-words", "--stdin", "--count", "4"], stdin=(ZERO_24 + "\n").encode(), **settings
    )
    return code, out + err


def check_pipe_matrix():
    cases = [
        ("none", {}, False),
        ("CLICOLOR_FORCE=1", {"CLICOLOR_FORCE": "1"}, True),
        ("NO_COLOR=1 CLICOLOR_FORCE=1", {"NO_COLOR": "1", "CLICOLOR_FORCE": "1"}, False),
        ("CLICOLOR=0", {"CLICOLOR": "0"}, False),
        ("TERM=dumb CLICOLOR_FORCE=1", {"TERM": "dumb", "CLICOLOR_FORCE": "1"}, True),
    ]
    wrong = []
    for label, settings, colour in cases:
        _, out, err = run_pipe(PROGRAM, ["--help"], **settings)
        help_colour = bool(sgr_parameters(out + err) - {0})
        code, tool = tool_run(**settings)
        tool_colour = bool(sgr_parameters(tool) - {0})
        if code != 0:
            wrong.append(f"{label}: repair-words exit {code}")
        if help_colour != colour or tool_colour != colour:
            wrong.append(f"{label}: help colour {help_colour}, tool colour {tool_colour}, expected {colour}")
        if not colour and b"\x1b" in out + err + tool:
            wrong.append(f"{label}: an escape byte without colour")
    record("C7 colour variables in a pipe", not wrong, "; ".join(wrong) or "as expected for 5 settings")


def pty_output(arguments, stdin_line=None, **settings):
    session = Pty(PROGRAM, arguments, **settings)
    if stdin_line is not None:
        session.wait_for(b"Make repair words", limit=20)
        session.type(stdin_line)
    code = session.finish(limit=60)
    return code, session.output


def check_pty_matrix():
    cases = [
        ("TERM=xterm-256color", {}, True),
        ("NO_COLOR=1", {"NO_COLOR": "1"}, False),
        ("TERM=dumb", {"TERM": "dumb"}, False),
        ("CLICOLOR=0", {"CLICOLOR": "0"}, False),
        ("TERM=dumb CLICOLOR_FORCE=1", {"TERM": "dumb", "CLICOLOR_FORCE": "1"}, True),
    ]
    wrong = []
    for label, settings, colour in cases:
        code, help_text = pty_output(["--help"], **settings)
        code_tool, tool = pty_output(
            ["repair-words", "--stdin", "--count", "4"], stdin_line=(ZERO_24 + "\r").encode(), **settings
        )
        for what, data, exit_code in (("help", help_text, code), ("tool", tool, code_tool)):
            params = sgr_parameters(data)
            has_colour = bool(params - {0})
            if exit_code != 0:
                wrong.append(f"{label}: {what} exit {exit_code}")
            if has_colour != colour:
                wrong.append(f"{label}: {what} colour {has_colour}, expected {colour}")
            if params - ALLOWED_SGR:
                wrong.append(f"{label}: {what} SGR outside the sixteen colours {sorted(params - ALLOWED_SGR)}")
    record("C8 colour variables at a terminal", not wrong, "; ".join(wrong) or "as expected for 5 settings")


def main():
    coloured, plain_texts = check_help_colours()
    check_main_help(coloured)
    check_command_help(plain_texts)
    check_usage_error()
    check_pipe_matrix()
    check_pty_matrix()
    failed = [check for check, ok, _ in results if not ok]
    print(f"help-and-colour: {len(results) - len(failed)} passed, {len(failed)} failed: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
