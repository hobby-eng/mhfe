#!/usr/bin/env python3
"""AUD-015 R5 probe: relative links, anchors and loose lists in the repository's Markdown.

    python3 docs/audits/AUD-015-harnesses/r5-build-docs/markdown_links_lists.py [file.md ...]

Without arguments it reads every tracked or untracked, not ignored *.md outside docs/audits/,
vendor/phc-winner-argon2/ (upstream text) and node_modules/. For each file it checks:

- every relative link target [text](path) or [text](path#anchor) exists, and an anchor names a
  heading of the target file (GitHub's slug rules: lower case, punctuation other than - and _
  dropped, spaces to -, -1/-2 suffixes for repeats) or an explicit <a id> / <a name>;
- no blank line sits inside a Markdown list (the workspace rule; the same algorithm as
  multi-chain-wallet-tools/tooling/verify-project-facts.mjs, looseListLine).

Prints one line per problem and exits 1 when there is any, 0 otherwise. Read-only.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()
SKIP = ("docs/audits/", "vendor/phc-winner-argon2/", "node_modules/")
LINK = re.compile(r"(?<!!)\[(?:[^\]\\]|\\.)*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
IMAGE = re.compile(r"!\[(?:[^\]\\]|\\.)*\]\(([^)\s]+)\)")
REF_DEF = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)")
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s")
CODE_FENCE = re.compile(r"^\s*(?:```|~~~)")
INDENTED_TEXT = re.compile(r"^\s{2,}\S")


def markdown_files():
    out = subprocess.run(["git", "ls-files", "-co", "--exclude-standard", "-z", "*.md"],
                         cwd=ROOT, capture_output=True, text=True, check=True).stdout
    return sorted(p for p in out.split("\0") if p and not p.startswith(SKIP))


def slug(text):
    text = re.sub(r"<[^>]+>", "", text)          # inline HTML
    text = re.sub(r"`([^`]*)`", r"\1", text)     # code spans keep their text
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)  # links keep their text
    text = text.strip().lower()
    text = re.sub(r"[^\w\- ]", "", text, flags=re.UNICODE)
    return text.replace(" ", "-")


def anchors(path, cache={}):
    if path in cache:
        return cache[path]
    found, counts, fence = set(), {}, False
    for line in path.read_text(encoding="utf-8").splitlines():
        if CODE_FENCE.match(line):
            fence = not fence
            continue
        if fence:
            continue
        m = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", line)
        if m:
            base = slug(m.group(2))
            n = counts.get(base, 0)
            counts[base] = n + 1
            found.add(base if n == 0 else f"{base}-{n}")
        for m in re.finditer(r"<a\s+(?:id|name)=\"([^\"]+)\"", line):
            found.add(m.group(1))
    cache[path] = found
    return found


def strip_code(line):
    return re.sub(r"`[^`]*`", "", line)


def link_problems(rel):
    path = ROOT / rel
    problems, fence = [], False
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if CODE_FENCE.match(line):
            fence = not fence
            continue
        if fence:
            continue
        text = strip_code(line)
        targets = [m.group(1) for m in LINK.finditer(text)] + \
                  [m.group(1) for m in IMAGE.finditer(text)]
        m = REF_DEF.match(text)
        if m:
            targets.append(m.group(1))
        for target in targets:
            target = target.strip("<>")
            if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
                continue  # absolute URL or mailto:
            file_part, _, anchor = target.partition("#")
            dest = path if file_part == "" else (path.parent / file_part).resolve()
            if file_part and not dest.exists():
                problems.append(f"{rel}:{number}: link target missing: {target}")
                continue
            if anchor and dest.is_file() and dest.suffix == ".md":
                if anchor not in anchors(dest):
                    problems.append(f"{rel}:{number}: anchor not found: {target}")
    return problems


def loose_list_line(lines):
    in_fence = in_list = blank_in_list = False
    for index, line in enumerate(lines):
        if CODE_FENCE.match(line):
            indented = bool(re.match(r"^\s", line))
            if not in_fence and blank_in_list and indented:
                return index
            if not in_fence and not indented:
                in_list = False
            in_fence = not in_fence
            blank_in_list = False
            continue
        if in_fence:
            continue
        if line.strip() == "":
            if in_list:
                blank_in_list = True
            continue
        if LIST_ITEM.match(line) or (blank_in_list and INDENTED_TEXT.match(line)):
            if blank_in_list:
                return index
            in_list = True
            continue
        if blank_in_list or line.startswith("#"):
            in_list = False
        blank_in_list = False
    return None


def main(argv):
    files = argv or markdown_files()
    problems = []
    for rel in files:
        problems += link_problems(rel)
        line = loose_list_line((ROOT / rel).read_text(encoding="utf-8").split("\n"))
        if line is not None:
            problems.append(f"{rel}:{line}: blank line inside a list (loose list)")
    for problem in problems:
        print(problem)
    print(f"{len(files)} Markdown files read, {len(problems)} problems.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
