"""AUD-015 R2 probe: does the word hint below a typed line keep the cursor on the line in a narrow
terminal?

    python3 docs/audits/AUD-015-harnesses/r2-cli/hint_rows_narrow.py [path/to/mhfe]

src/bin/mhfe/typed_line.rs draws a hint below the line being typed and moves the cursor back up by
the number of hint rows it wrote, assuming each row fits the terminal. Hints are drawn from 24
columns on (NARROWEST_FOR_HINTS); the count hint after one letter, "  136 BIP39 words begin with this
letter", is 40 columns wide. The probe types "a" and then "b" at the container prompt of
`mhfe check --fingerprint --pim 0` in terminals 80 and 32 columns wide, replays the output on a
small VT100 model (pty_session.Screen) and looks where each letter landed.

Expected: "b" lands right after "a", on the line being typed. Exit 1 when it lands elsewhere (the
defect), 0 otherwise. Ctrl+C then ends the tool; nothing secret is typed and Argon2 never runs.
"""

import sys

from pty_session import Screen, Session, program

PROMPT = b"original seed phrase: "


def landed(tool, columns, rows=24):
    session = Session(tool, ["check", "--fingerprint", "--pim", "0"], columns=columns, rows=rows)
    session.wait_for(PROMPT)
    screen = Screen(columns, rows)
    screen.feed(session.output)
    start = (screen.row, screen.column)
    after_a = session.type(b"a")
    after_b = session.type(b"b")
    session.finish()
    screen.feed(after_a + after_b)
    first = screen.cells[start[0]][start[1]]
    row, column = start if start[1] + 1 < columns else (start[0] + 1, -1)
    second = screen.cells[row][column + 1]
    print(f"{columns} columns: line starts at row {start[0]}, column {start[1]}; there: "
          f"{first!r}, next cell: {second!r}")
    print(f"{columns} columns: bytes after 'a': {after_a!r}")
    print(f"{columns} columns: bytes after 'b': {after_b!r}")
    print(f"{columns} columns: screen:\n{screen.text()}")
    return first == "a" and second == "b"


def main():
    tool = program(sys.argv)
    failed = False
    if not landed(tool, 80):
        print("80 columns: FAIL: the screen model does not see 'ab' on the line (probe broken?)")
        failed = True
    else:
        print("80 columns: PASS: 'a' and 'b' side by side on the line")
    if not landed(tool, 32):
        print("32 columns: FAIL (defect reproduced): the hint row wrapped and 'b' was drawn off the "
              "line being typed")
        failed = True
    else:
        print("32 columns: PASS: 'a' and 'b' side by side on the line")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
