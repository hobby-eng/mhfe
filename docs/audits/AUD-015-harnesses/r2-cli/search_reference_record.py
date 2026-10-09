"""AUD-015 R2 probe: does the summary that a command leaves on the main screen hold control sequences
typed as the reference of a search for a missing container word?

    python3 docs/audits/AUD-015-harnesses/r2-cli/search_reference_record.py [path/to/mhfe]

`mhfe check --fingerprint --pim 0` reads the public zero-12 container with its last word typed as
"?", gets Enter alone at the repair words, chooses the container's own wallet and types an "address"
that holds an OSC title sequence and an erase-display sequence. WalletReference::
read_address_or_fingerprint (src/bin/mhfe/check.rs) takes any text that is not a fingerprint as an
address and records it in the summary at once, before the coin is asked. Ctrl+C at the coin
question then ends the tool, which writes the summary on the main screen. Argon2 never runs.

A second run types the public zero-12 seed phrase into the same field, as a person who pastes the
wrong line would. Other public fields record an answer only once it has been read as what they ask
for (read_public); this one records any text that is not a fingerprint.

Expected: the main screen gets no raw escape bytes from the typed text, and no text that was never
read as an address or a fingerprint. Exit 1 when either reaches it (the defect), 0 otherwise.
"""

import sys

from pty_session import CONTAINER, LEAVE_PRIVATE, PHRASE, Session, program

MARK = b"\x1b]0;AUD015-TITLE\x07"
ERASE = b"\x1b[2J"
TYPED = b"bc1" + MARK + ERASE + b"zz"


def summary_after(tool, typed):
    """The main screen after `typed` was given as the reference, and whether the terminal settings
    came back."""
    words = CONTAINER.split(b" ")
    words[23] = b"?"
    session = Session(tool, ["check", "--fingerprint", "--pim", "0"])
    session.wait_for(b"original seed phrase: ")
    session.type(b" ".join(words) + b"\r", then=b"Repair words: ")
    session.type(b"\r", then=b"No repair words: what do you know?")
    session.type(b"1", then=b"Address or master key fingerprint: ")
    session.type(typed + b"\r", then=b"Which coin is the address for?")
    code, settings = session.finish()
    summary = session.output[session.output.rfind(LEAVE_PRIVATE):]
    print(f"exit code {code}")
    print(f"main screen after the private screens: {summary!r}")
    return summary, settings == session.original


def main():
    tool = program(sys.argv)
    failed = False
    summary, restored = summary_after(tool, TYPED)
    if MARK in summary or ERASE in summary:
        print("FAIL (defect reproduced): the typed escape sequences reached the main screen in the "
              "summary record")
        failed = True
    else:
        print("PASS: the summary carries no typed escape bytes")
    summary, restored_again = summary_after(tool, PHRASE)
    if PHRASE in summary:
        print("FAIL (defect reproduced): a seed phrase typed into the reference field was recorded "
              "on the main screen although it is no address")
        failed = True
    else:
        print("PASS: the mistyped seed phrase did not reach the main screen")
    if not (restored and restored_again):
        print("FAIL: the terminal settings changed")
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
