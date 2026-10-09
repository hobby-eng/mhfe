"""AUD-015 R2 probe: does `mhfe serve` write control sequences from its checksum file to the terminal?

    python3 docs/audits/AUD-015-harnesses/r2-cli/serve_checksum_name.py [path/to/mhfe]

A checksum file `mhfe-fast-mode.sha256` lies next to a page; its single line names another page
whose file name carries an OSC title sequence (ESC ] 0 ; ... BEL) and an erase-display sequence
(ESC [ 2 J). That name passes the tool's checks (no slash, no backslash, ends in .html), so the tool
refuses the page because the names differ. Expected: the refusal reaches the terminal without the
file's escape bytes (they are content of an untrusted file). The probe exits 1 when the raw bytes
reach the terminal (the defect), 0 when they do not. The tool stops at the checksum file: no socket
is opened and no browser is started.
"""

import hashlib
import sys
import tempfile
from pathlib import Path

from pty_session import Session, program

MARK = b"\x1b]0;AUD015-TITLE\x07"
ERASE = b"\x1b[2J"


def main():
    tool = program(sys.argv)
    page = b"<!doctype html><title>public probe page</title>"
    with tempfile.TemporaryDirectory(prefix="aud015-r2-serve-") as folder:
        folder = Path(folder)
        (folder / "tool.html").write_bytes(page)
        name = b"x" + MARK + ERASE + b"y.html"
        digest = hashlib.sha256(page).hexdigest().encode()
        (folder / "mhfe-fast-mode.sha256").write_bytes(digest + b"  " + name + b"\n")
        failed = False
        # In colour, and with NO_COLOR, where anstream strips its own colour codes.
        for colour in (True, False):
            session = Session(tool, ["serve", "--no-browser", str(folder / "tool.html")],
                              colour=colour)
            session.wait_exit(limit=20)
            code, _ = session.finish(limit=5)
            output = session.output
            mode = "colour" if colour else "NO_COLOR"
            print(f"{mode}: exit code {code}")
            print(f"{mode}: output {output!r}")
            if b"nothing was served" not in output:
                print(f"{mode}: FAIL: the tool did not refuse the page as expected")
                failed = True
            elif MARK in output or ERASE in output:
                print(f"{mode}: FAIL (defect reproduced): the checksum file's escape sequences "
                      "reached the terminal")
                failed = True
            else:
                print(f"{mode}: PASS: the refusal carries no escape bytes from the checksum file")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
