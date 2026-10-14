"""Lists doc-comment blocks in which a line that ends a sentence is followed, without a blank ///
line, by a line that starts a new sentence with a capital, where the first line is the whole first
paragraph (a one-line block head): candidates for a doc comment of another item joined to this one
(the AUD-023-ARC003 pattern). Review each candidate by hand."""
import re, sys
for path in sys.argv[1:]:
    lines = open(path, encoding="utf-8").read().split("\n")
    i = 0
    while i < len(lines):
        if lines[i].lstrip().startswith("///"):
            start = i
            while i < len(lines) and lines[i].lstrip().startswith("///"):
                i += 1
            block = [l.strip()[3:].strip() for l in lines[start:i]]
            item = lines[i].strip() if i < len(lines) else ""
            if len(block) >= 2 and block[0].endswith(".") and block[1][:1].isupper() and block[0] and not block[0].startswith("-"):
                print(f"{path}:{start+1}: {block[0]!r} / {block[1][:60]!r} -> {item[:60]!r}")
        else:
            i += 1
