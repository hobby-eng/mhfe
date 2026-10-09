#!/usr/bin/env python3
"""AUD-015 R5 probe: command-line options named in the documents exist in the program.

    python3 docs/audits/AUD-015-harnesses/r5-build-docs/documented_options.py <help log>

<help log> is the output of capture_help.sh (every command's --help). The probe reads the
long options each command declares there, then every "mhfe <command> ... --option" written in
README.md, SECURITY.md, docs/API.md, docs/BROWSER-PACKAGE.md and docs/releases/v0.5.1.md (inline
code and code blocks), and reports an option that the named command does not declare. Options of
other programs (cargo, node, npm, sha256sum, gpg ...) are not read: only text that starts with
"mhfe <command>". Exits 1 when any documented option is unknown to its command.
"""
import re
import sys
from pathlib import Path

DOCS = ["README.md", "SECURITY.md", "docs/API.md", "docs/BROWSER-PACKAGE.md",
        "docs/releases/v0.5.1.md"]
COMMANDS = ["new", "encrypt", "decrypt", "check", "rekey", "wallets", "repair", "repair-words",
            "password", "self-test", "serve", "test-vectors", "test-benchmark"]


def declared(log):
    options, current = {}, None
    for line in log.splitlines():
        m = re.match(r"^=== mhfe (\S+) --help$", line)
        if m:
            current = m.group(1)
            options[current] = set()
            continue
        if line.startswith("=== "):
            current = None
            continue
        if current:
            m = re.match(r"^\s+(?:-\w, )?(--[a-z][a-z0-9-]*)", line)
            if m:
                options[current].add(m.group(1))
    return options


def documented(path):
    text = Path(path).read_text(encoding="utf-8")
    found = []
    # Each "mhfe <command> ..." up to the end of its line or code span.
    for number, line in enumerate(text.splitlines(), 1):
        for m in re.finditer(r"\bmhfe ([a-z-]+)((?: [^`|\n]*)?)", line):
            command, rest = m.group(1), m.group(2)
            if command not in COMMANDS:
                continue
            for option in re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", rest):
                found.append((number, command, option))
    return found


def main(argv):
    if len(argv) != 1:
        sys.exit(__doc__)
    options = declared(Path(argv[0]).read_text(encoding="utf-8"))
    missing = [c for c in COMMANDS if c not in options]
    if missing:
        sys.exit(f"help log lacks commands: {missing}")
    problems = 0
    for doc in DOCS:
        for number, command, option in documented(doc):
            if option in ("--help", "--version"):
                continue
            if option not in options[command]:
                # The option may belong to the next command named on the same line.
                print(f"{doc}:{number}: mhfe {command} does not declare {option}")
                problems += 1
    print(f"{problems} documented options unknown to their command.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
