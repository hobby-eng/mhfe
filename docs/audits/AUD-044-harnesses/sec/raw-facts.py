#!/usr/bin/env python3
"""AUD-044 SEC probe: what the raw stream of a terminal scenario held (drive.py, raw.txt).

    raw-facts.py <raw.txt>
"""
import sys

raw = open(sys.argv[1], "rb").read()
print("bytes:", len(raw))
print("alternate screen entered:", b"\x1b[?1049h" in raw)
print("erase sequences sent:", raw.count(b"\x1b[J"))
for label, text in (
    ("the 24-word phrase", b"hamster diagram private dutch cause delay private meat"),
    ("the password", b"audit-public-password-044"),
    ("the container's words", b"abandon"),
):
    print("%s in the stream: %d" % (label, raw.count(text)))
