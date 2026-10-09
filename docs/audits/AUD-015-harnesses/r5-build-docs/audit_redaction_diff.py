#!/usr/bin/env python3
"""AUD-015 R5 probe: the privacy redaction of older audit records changed metadata only.

    python3 docs/audits/AUD-015-harnesses/r5-build-docs/audit_redaction_diff.py [--ignore-commits]
        [BASE [NEW_HEAD]]

For every file under docs/audits/ and docs/measurements/ that is tracked in BASE (default HEAD)
and differs from it in the working tree, compares the BASE bytes with the working tree after
normalising what a privacy redaction may change. With NEW_HEAD, BASE is the head of the history
before a rewrite: the first-parent commits of both are paired by position, and every old commit
hash (full or abbreviated to 7 or more digits) in the BASE text is replaced by its new hash before
the comparison, so that an updated commit reference counts as equal and a reference left old
shows as a difference. --ignore-commits writes every 7- to 40-digit hex word as <commit> on both
sides, so that what remains is every change other than commit references.

- home directories (/home/<name>/ to /home/user/), the user name in other paths and texts;
- Markdown table padding and JSON layout (Prettier re-alignment, one-line arrays);
- timestamps: the same instant written in another time zone counts as equal.

JSON records are compared as data: every leaf that still differs after normalisation is printed
with its path, and keys that appear or vanish are listed. Leaves that carry the audit's substance
are then classed: findings (id, severity, status, title, kind, category), check outcomes, SHA-256
values, exit codes and counts. Markdown is compared line by line after normalisation.

Exits 1 when a substantive leaf (finding fields, outcomes, hashes, exit codes) changed, 0 when
only metadata did, and prints every residual difference either way for review.
"""
import datetime
import difflib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()
HOME = re.compile(r"/home/[A-Za-z0-9_.-]+(?=/|\b)")
SUBSTANTIVE_KEYS = {"id", "severity", "status", "title", "kind", "category", "outcome",
                    "exitCode", "exit_code", "result", "verdict", "releaseBlocking"}
HEX64 = re.compile(r"\b[0-9a-f]{64}\b")
TIMESTAMP = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})\b")


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, check=True).stdout


def instant(text):
    text = text.replace(" ", "T").replace("Z", "+00:00")
    if re.search(r"[+-]\d{4}$", text):
        text = text[:-2] + ":" + text[-2:]
    try:
        return datetime.datetime.fromisoformat(text).astimezone(datetime.timezone.utc)
    except ValueError:
        return None


COMMIT_MAP = {}
IGNORE_COMMITS = False
HEXWORD = re.compile(r"(?<![0-9a-f])[0-9a-f]{7,40}(?![0-9a-f])")


def map_commits(text):
    def new(match):
        word = match.group(0)
        for old, replacement in COMMIT_MAP.items():
            if old.startswith(word):
                return replacement[:len(word)]
        return word
    return HEXWORD.sub(new, text) if COMMIT_MAP else text


def normal_text(text, old_side=False):
    if old_side:
        text = map_commits(text)
    if IGNORE_COMMITS:
        text = HEXWORD.sub("<commit>", text)
    text = HOME.sub("/home/user", text)
    text = text.replace(Path.home().name, "user")
    text = TIMESTAMP.sub(lambda m: (instant(m.group(0)) or m.group(0)).isoformat()
                         if instant(m.group(0)) else m.group(0), text)
    return text


def normal_md_line(line, old_side=False):
    line = normal_text(line, old_side).rstrip()
    if line.lstrip().startswith("|"):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        cells = ["---" if re.fullmatch(r":?-{3,}:?", c) else c for c in cells]
        return "|" + "|".join(cells) + "|"
    return re.sub(r"[ \t]+", " ", line)


def leaves(value, path=""):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from leaves(item, f"{path}/{normal_text(str(key))}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from leaves(item, f"{path}[{index}]")
    else:
        yield path, value


def substantive(path, old, new):
    key = re.sub(r"\[\d+\]$", "", path.rsplit("/", 1)[-1])
    if key in SUBSTANTIVE_KEYS:
        return True
    for value in (old, new):
        if isinstance(value, str) and HEX64.search(value):
            return True
    return False


def compare_json(name, old_bytes, new_bytes):
    old = {normal_text(k, True): v for k, v in leaves(json.loads(old_bytes))}
    new = dict(leaves(json.loads(new_bytes)))
    residual, serious = [], []
    for path in sorted(set(old) | set(new)):
        a, b = old.get(path, "<absent>"), new.get(path, "<absent>")
        na = normal_text(a, old_side=True) if isinstance(a, str) else a
        nb = normal_text(b) if isinstance(b, str) else b
        if na == nb:
            continue
        line = f"{name}:{path}: {json.dumps(a)[:160]} -> {json.dumps(b)[:160]}"
        residual.append(line)
        if substantive(path, a, b):
            serious.append(line)
    return residual, serious


def compare_md(name, old_bytes, new_bytes):
    old = [normal_md_line(l, True) for l in old_bytes.decode("utf-8").splitlines()]
    new = [normal_md_line(l) for l in new_bytes.decode("utf-8").splitlines()]
    residual, serious = [], []
    for line in difflib.unified_diff(old, new, lineterm="", n=0):
        if line.startswith(("---", "+++", "@@")):
            continue
        residual.append(f"{name}: {line[:220]}")
        if HEX64.search(line) or re.search(
                r"\b(open|fixed|verified|accepted|wontfix|passed|failed|critical|high|medium|"
                r"low|info)\b", line):
            serious.append(f"{name}: {line[:220]}")
    return residual, serious


def main(argv):
    global IGNORE_COMMITS
    if argv and argv[0] == "--ignore-commits":
        IGNORE_COMMITS = True
        argv = argv[1:]
    base = argv[0] if argv else "HEAD"
    if len(argv) > 1:
        old = git("rev-list", "--first-parent", "--reverse", base).decode().split()
        new = git("rev-list", "--first-parent", "--reverse", argv[1]).decode().split()
        if len(old) != len(new):
            sys.exit("the two histories differ in length")
        COMMIT_MAP.update({a: b for a, b in zip(old, new) if a != b})
    names = [n for n in git("diff", "--name-only", base, "--", "docs/audits/",
                            "docs/measurements/").decode().splitlines()
             if n and (ROOT / n).is_file()]
    total_residual, total_serious = [], []
    for name in names:
        old = git("show", f"{base}:{name}")
        new = (ROOT / name).read_bytes()
        if name.endswith(".json"):
            residual, serious = compare_json(name, old, new)
        else:
            residual, serious = compare_md(name, old, new)
        print(f"== {name}: {len(residual)} residual differences, {len(serious)} substantive")
        for line in residual:
            print("   " + line)
        total_residual += residual
        total_serious += serious
    print(f"{len(names)} files; {len(total_residual)} residual differences; "
          f"{len(total_serious)} touch findings, outcomes, hashes or exit codes.")
    return 1 if total_serious else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
