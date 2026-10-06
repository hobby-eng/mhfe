#!/usr/bin/env python3
"""Recheck AUD-008 option and menu contracts with public fixtures and no Argon2."""

import fcntl
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys
import termios
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-008-evidence"
PROGRAM = Path(sys.argv[1]).resolve()
OUTPUT = Path(sys.argv[2]).resolve()
assert not OUTPUT.exists(), "Use a fresh evidence name."

spec = importlib.util.spec_from_file_location(
    "aud008_original_ui", ROOT / "docs/audits/AUD-008-harnesses/ui-terminal-probe.py"
)
ui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ui)
ui.PROGRAM = PROGRAM
records = []
failures = []


def retain(label, passed, **detail):
    records.append(dict(label=label, passed=passed, **detail))
    if not passed:
        failures.append(label)
    print(json.dumps({"label": label, "passed": passed, **{key: value for key, value in detail.items() if key != "transcript"}}))


def rekey(container_length, words):
    suite = 3 if container_length == 24 else 4
    filename = "zero-12.json" if suite == 3 else f"same-length-zero-{container_length}.json"
    vector = json.loads((ROOT / f"tests/fixtures/suite{suite}-vectors" / filename).read_text())
    args = ["rekey", "--pim", "0"]
    if words is not None:
        args += ["--words", str(words)]
    session = ui.Session(args, NO_COLOR="1")
    try:
        session.wait_for(b"backed up another way?")
        session.answer(b"1", b"original: ")
        session.type(vector["container"].encode() + b"\r")
        deadline = time.monotonic() + ui.DEADLINE_SECONDS
        while b"Old container password: " not in session.output and "✗ Error:".encode() not in session.output:
            assert time.monotonic() < deadline, session.output.decode(errors="replace")
            session.read()
        accepted = b"Old container password: " in session.output
        transcript = session.transcript()
    finally:
        code, restored = session.close()
    expected = words is None or words == container_length
    if suite == 3:
        expected = words in (12, 15, 18, 21, 24)
    retain(
        f"rekey container={container_length} words={words}",
        accepted == expected and restored,
        expectedPasswordPrompt=expected,
        observedPasswordPrompt=accepted,
        exitCode=code,
        settingsRestored=restored,
        transcript=transcript,
    )


def menu(columns):
    session = ui.Session(columns=columns, NO_COLOR="1")
    counts = []
    try:
        session.wait_for(b"Esc quits")
        for key in [b"\x1b[B"] * 3 + [b"\x1b[A"] * 2:
            session.answer(key, b"Esc quits")
            grid = ui.menu_grid(session.output, columns)
            assert not grid["unsupported"], grid["unsupported"]
            counts.append(sum(row.count("›") for row in grid["rows"]))
        transcript = session.transcript()
        session.type(b"\x1b")
    finally:
        code, restored = session.close(cancel=False)
    retain(
        f"menu columns={columns} five arrow redraws",
        counts == [1] * 5 and code == 0 and restored,
        selectedMarkerCounts=counts,
        exitCode=code,
        settingsRestored=restored,
        transcript=transcript,
    )


def resized_menu():
    session = ui.Session(columns=80, NO_COLOR="1")
    counts = []
    try:
        session.wait_for(b"Esc quits")
        for columns in [40, 40, 60, 60, 80]:
            fcntl.ioctl(session.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 100, columns, 0, 0))
            start = len(session.output)
            session.answer(b"\x1b[B", b"Esc quits")
            redraw = session.output[start:]
            cursor_up = re.search(rb"\x1b\[(\d+)A", redraw)
            assert cursor_up, redraw
            # Full menu repaints start after 2J/H, so earlier widths do not contaminate the grid.
            reset = session.output.rfind(b"\x1b[2J\x1b[H")
            visible = session.output[reset + len(b"\x1b[2J\x1b[H"):] if reset >= 0 else session.output
            grid = ui.menu_grid(visible, columns)
            assert not grid["unsupported"], grid["unsupported"]
            markers = sum(row.count("›") for row in grid["rows"])
            counts.append({"columns": columns, "cursorUpRows": int(cursor_up[1]), "selectedMarkerCount": markers})
        transcript = session.transcript()
        session.type(b"\x1b")
    finally:
        code, restored = session.close(cancel=False)
    # Two draws at the same new geometry must not keep the original 80-column count.
    changed = counts[1]["cursorUpRows"] > counts[-1]["cursorUpRows"]
    retain(
        "menu resize 80->40->60->80 recounts rows",
        changed and all(record["selectedMarkerCount"] == 1 for record in counts) and code == 0 and restored,
        cursorUpCounts=counts,
        exitCode=code,
        settingsRestored=restored,
        transcript=transcript,
        limit="PTY cursor sequences only; this probe does not model emulator scrollback reflow.",
    )


def resized_choice():
    session = ui.Session(["rekey", "--pim", "0"], columns=80, NO_COLOR="1")
    records = []
    question = b"Are the funds of any such wallet moved, or backed up another way?"
    try:
        session.wait_for(b"backed up another way?")
        session.wait_for(b"Esc cancels")
        # Only the question block is counted; the warning/title above it must stay visible.
        block = b"\r\n" + session.output[session.output.index(question):]
        for columns, key in [(40, b"\x1b[B"), (40, b"\x1b[A"), (60, b"\x1b[B"), (80, b"\x1b[A")]:
            expected = sum(max(1, (len(line) + columns - 1) // columns) for line in ui.plain(block).splitlines())
            fcntl.ioctl(session.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 100, columns, 0, 0))
            start = len(session.output)
            session.answer(key, b"Esc cancels")
            frame = session.output[start:]
            cursor_up = re.search(rb"\x1b\[(\d+)A", frame)
            assert cursor_up, frame
            records.append({"columns": columns, "expectedRows": expected, "observedRows": int(cursor_up[1]), "fullScreenCleared": b"\x1b[2J" in frame})
            block = b"\r\n" + frame[frame.index(question):]
        transcript = session.transcript()
        session.type(b"\x1b")
    finally:
        code, restored = session.close(cancel=False)
    retain(
        "choice resize recalculates logical widths without clearing preceding context",
        all(record["expectedRows"] == record["observedRows"] and not record["fullScreenCleared"] for record in records) and restored and code == 130,
        redraws=records,
        exitCode=code,
        settingsRestored=restored,
        transcript=transcript,
        limit="Row-count check assumes normal terminal reflow of prior logical lines; preceding phrase is not regenerated or copied.",
    )


def short_menu_dispatch():
    for columns, rows in [(40, 18), (60, 18), (80, 12)]:
        session = ui.Session(columns=columns, rows=rows, NO_COLOR="1")
        try:
            session.wait_for(b"Esc quits")
            # Help is the tenth entry without a packaged page. Down moves from 1 to 10.
            session.type(b"\x1b[B" * 9 + b"\r")
            session.wait_for(b"Press Enter to return to the menu")
            shown_help = b"Usage:" in session.output
            session.answer(b"\r", b"Esc quits")
            transcript = session.transcript()
            session.type(b"\x1b")
        finally:
            code, restored = session.close(cancel=False)
        retain(f"short menu {columns}x{rows} Help dispatch and Escape", shown_help and code == 0 and restored, exitCode=code, settingsRestored=restored, transcript=transcript, limit="Dispatch/cancellation check; no claim that every entry fits in a short viewport.")


for length in [12, 15, 18, 21]:
    for words in [None, 12, 15, 18, 21, 24, 0, 13, 25]:
        rekey(length, words)
for words in [12, 15, 18, 21, 24, 0, 13, 25]:
    rekey(24, words)
for columns in [80, 60, 40]:
    menu(columns)
resized_menu()
resized_choice()
short_menu_dispatch()
sources = [
    "src/bin/mhfe/rekey.rs",
    "src/bin/mhfe/menu.rs",
    "src/bin/mhfe/choice.rs",
    "src/bin/mhfe/style.rs",
    "src/bin/mhfe/hidden_input.rs",
    "docs/audits/AUD-008-harnesses/ui-terminal-probe.py",
]
result = {
    "auditId": "AUD-008",
    "binary": str(PROGRAM),
    "binarySha256": hashlib.sha256(PROGRAM.read_bytes()).hexdigest(),
    "sourceSha256": {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in sources},
    "cases": records,
    "failures": failures,
    "argon2Calls": 0,
    "outcome": "failed" if failures else "passed",
}
OUTPUT.write_text(json.dumps(result, indent=2) + "\n")
raise SystemExit(bool(failures))
