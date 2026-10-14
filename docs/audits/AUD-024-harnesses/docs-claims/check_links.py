#!/usr/bin/env python3
"""AUD-024 docs-claims harness: checks every Markdown link of the documents in scope.

Relative links must name a file or folder of the repository, and their anchors a heading of the
target file. Links to https://github.com/hobby-eng/mhfe/blob/main/<path>#<anchor> and
https://github.com/hobby-eng/mhfe#<anchor> are checked the same way against the working tree,
and https://github.com/hobby-eng/mhfe-spec#<anchor> against ../mhfe_spec/README.md. Anchors follow
GitHub's rule (lower case, punctuation other than '-' and '_' removed, spaces as '-', '-N' for a
repeated heading). Exits 1 when any link fails, and prints each failure.

    python3 docs/audits/AUD-024-harnesses/docs-claims/check_links.py   (from the repository root)
"""
import re
import sys
import unicodedata
from pathlib import Path

ROOT = Path.cwd()
SPEC = ROOT.parent / "mhfe_spec"
DOCS = [
    "README.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md", "AGENTS.md", "docs/API.md",
    "docs/BROWSER-PACKAGE.md", "docs/DEVELOPMENT.md", "docs/RELEASING.md",
    "docs/measurements/README.md", "docs/releases/unreleased.md", "docs/releases/v0.4.0.md",
    "docs/releases/v0.5.0.md", "docs/releases/v0.6.0.md",
    "docs/releases/history-rewrite-2026-10-09.md", "vendor/eff-large-wordlist.md",
    "vendor/phc-winner-argon2.md",
]
LINK = re.compile(r"(?<!!)\[(?:[^\[\]]|\[[^\]]*\])*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
HTML_LINK = re.compile(r"<(?:a|img)\s[^>]*(?:href|src)=\"([^\"]+)\"")


def strip_code_blocks(text):
    out, fence = [], False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            fence = not fence
            out.append("")
            continue
        out.append("" if fence else line)
    return out


def anchor_of(heading):
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    text = text.replace("`", "").strip().lower()
    kept = []
    for c in text:
        cat = unicodedata.category(c)
        if c in " -_" or cat[0] in "LMN" or cat == "Pc":
            kept.append(c)
    return "".join(kept).replace(" ", "-")


def anchors(path):
    seen, result = {}, set()
    for line in strip_code_blocks(path.read_text(encoding="utf-8")):
        m = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", line)
        if not m:
            continue
        base = anchor_of(m.group(2))
        n = seen.get(base, 0)
        result.add(base if n == 0 else f"{base}-{n}")
        seen[base] = n + 1
    for m in re.finditer(r"<a\s+(?:name|id)=\"([^\"]+)\"", path.read_text(encoding="utf-8")):
        result.add(m.group(1))
    return result


def check(doc, target, failures, line_no):
    where = f"{doc}:{line_no}: {target}"
    if target.startswith("https://github.com/hobby-eng/mhfe-spec"):
        rest = target[len("https://github.com/hobby-eng/mhfe-spec"):]
        if rest.startswith("#"):
            if rest[1:] not in anchors(SPEC / "README.md"):
                failures.append(f"{where}: no heading #{rest[1:]} in mhfe_spec/README.md")
        return
    for prefix in ("https://github.com/hobby-eng/mhfe/blob/main/",
                   "https://github.com/hobby-eng/mhfe/tree/main/"):
        if target.startswith(prefix):
            rel = target[len(prefix):]
            path, _, frag = rel.partition("#")
            file = ROOT / path
            if not file.exists():
                failures.append(f"{where}: {path} does not exist")
            elif frag and file.is_file() and frag not in anchors(file):
                failures.append(f"{where}: no heading #{frag} in {path}")
            return
    if target.startswith("https://github.com/hobby-eng/mhfe#"):
        frag = target.split("#", 1)[1]
        if frag not in anchors(ROOT / "README.md"):
            failures.append(f"{where}: no heading #{frag} in README.md")
        return
    if re.match(r"^[a-z]+:", target):
        return
    path, _, frag = target.partition("#")
    file = (ROOT / doc).parent / path if path else ROOT / doc
    if not file.exists():
        failures.append(f"{where}: {file.relative_to(ROOT) if file.is_relative_to(ROOT) else file} does not exist")
    elif frag and file.is_file() and frag not in anchors(file):
        failures.append(f"{where}: no heading #{frag} in {path or doc}")


def main():
    failures, count = [], 0
    for doc in DOCS:
        lines = strip_code_blocks((ROOT / doc).read_text(encoding="utf-8"))
        for number, line in enumerate(lines, 1):
            for m in list(LINK.finditer(line)) + list(HTML_LINK.finditer(line)):
                count += 1
                check(doc, m.group(1), failures, number)
    for failure in failures:
        print(failure)
    print(f"{count} links checked in {len(DOCS)} documents, {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
