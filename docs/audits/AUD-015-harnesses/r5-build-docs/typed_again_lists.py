#!/usr/bin/env python3
"""AUD-015 R5 probe: lists of word counts typed again in message strings.

    python3 docs/audits/AUD-015-harnesses/r5-build-docs/typed_again_lists.py

AGENTS.md (Object-oriented design and no repetition, rule 6): "A value with a meaning (24 words,
a list of lengths, a limit, an error code) is a named constant defined once, and one that follows
from another is derived from it, never typed again." The library already derives such lists for
messages (src/phrase.rs counts_text / word_counts_text from WORD_COUNTS).

The probe reads the code (not comments) of src/**/*.rs and web/*.js and reports every string
literal that spells one of the constant lists below by hand. Help texts of the command-line tool
are reported too, marked "help". Exits 1 when any message string types a list again.
"""
import re
import sys
from pathlib import Path

ROOT = Path.cwd()
# The constant each spelled list follows from, and where that constant is defined.
LISTS = {
    "12, 15, 18, 21 or 24": "WORD_COUNTS (src/phrase.rs; web/client.js:60)",
    "12, 15, 18 or 21": "BUILT_IN_CHECK_WORD_COUNTS (src/container.rs; web/client.js:61)",
    "0, 2, 4, 6 or 8": "REPAIR_WORD_COUNTS with 0 (web/client.js:62)",
    "2, 4, 6 or 8": "REPAIR_WORD_COUNTS (src/repair.rs:45)",
}
COMMENT = re.compile(r"^\s*(//|/\*|\*|#)")
STRING = re.compile(r"\"(?:[^\"\\]|\\.)*\"|`(?:[^`\\]|\\.)*`|'(?:[^'\\]|\\.)*'")


def files():
    yield from sorted(ROOT.glob("src/**/*.rs"))
    yield from sorted(ROOT.glob("web/*.js"))


def main():
    found = []
    for path in files():
        rel = path.relative_to(ROOT).as_posix()
        in_tests = False
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if rel.endswith(".rs") and re.match(r"^\s*#\[cfg\(test\)\]", line):
                in_tests = True  # unit tests below compare messages; they are not sources
            if in_tests or COMMENT.match(line):
                continue
            code = line.split("//")[0] if rel.endswith(".rs") else line
            for literal in STRING.findall(code):
                for spelled, constant in LISTS.items():
                    # "2, 4, 6 or 8" is also inside "0, 2, 4, 6 or 8"; report the longer one once.
                    if spelled in literal and not any(
                            longer != spelled and spelled in longer and longer in literal
                            for longer in LISTS):
                        kind = "help" if rel.startswith("src/bin/") else "message"
                        found.append((rel, number, kind, spelled, constant))
    for rel, number, kind, spelled, constant in found:
        print(f"{rel}:{number}: {kind} types \"{spelled}\" again; derive it from {constant}")
    messages = [f for f in found if f[2] == "message"]
    print(f"{len(found)} lists typed again in strings, {len(messages)} of them in messages.")
    return 1 if messages else 0


if __name__ == "__main__":
    sys.exit(main())
