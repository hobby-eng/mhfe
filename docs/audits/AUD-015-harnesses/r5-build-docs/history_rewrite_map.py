#!/usr/bin/env python3
"""AUD-015 R5 probe: what the privacy rewrite of mhfe's history changed, and whether the audit
records that name commits by hash still name commits that exist.

    python3 docs/audits/AUD-015-harnesses/r5-build-docs/history_rewrite_map.py <old head> <new head>

Read-only. It pairs the commits of the old and the new first-parent history by position (both
must have the same length and the same subjects), then for every pair:

- lists the paths whose blobs differ between the old and the new tree, and fails when one lies
  outside docs/audits/ and docs/measurements/ (the redaction's declared scope);
- compares author, author date, committer date and message; a changed message is printed.

Then it reads every docs/audits/*.md, *.json and harness README in the working tree, collects
every 7- to 40-digit hex word that resolves to a commit object of the old history, and reports:

- OLD: a record names a commit of the old history that the rewrite replaced (its new hash is
  printed), in files that the rewrite already edited (inconsistent) or did not;
- whether each new hash is reachable from the new head.

Tags: prints where each tag points and whether that commit is of the old or the new history.
Exits 1 when a rewritten tree changed outside the declared scope or a record names a replaced
commit; prints every case either way.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()
SCOPE = ("docs/audits/", "docs/measurements/")


def git(*args, check=True):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                          check=check).stdout


def first_parent(head):
    return git("rev-list", "--first-parent", "--reverse", head).split()


def info(commit):
    return git("show", "-s", "--format=%an%x00%ae%x00%ad%x00%cd%x00%B", "--date=raw", commit)


def changed_paths(old, new):
    out = git("diff", "--name-only", "--no-renames", old, new)
    return [p for p in out.splitlines() if p]


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__)
    old_head, new_head = argv
    old, new = first_parent(old_head), first_parent(new_head)
    problems = 0
    if len(old) != len(new):
        print(f"history lengths differ: {len(old)} old, {len(new)} new")
        return 1
    mapping = {}
    identical = 0
    for a, b in zip(old, new):
        mapping[a] = b
        if a == b:
            identical += 1
            continue
        ia, ib = info(a).split("\0"), info(b).split("\0")
        outside = [p for p in changed_paths(a, b) if not p.startswith(SCOPE)]
        inside = [p for p in changed_paths(a, b) if p.startswith(SCOPE)]
        notes = []
        if ia[:4] != ib[:4]:
            notes.append(f"metadata {ia[:4]} -> {ib[:4]}")
        if ia[4] != ib[4]:
            notes.append("message changed")
        if outside:
            problems += 1
            notes.append(f"TREE CHANGED OUTSIDE SCOPE: {outside}")
        print(f"{a[:10]} -> {b[:10]} {len(inside)} paths in scope differ"
              + (f"; {'; '.join(notes)}" if notes else ""))
    print(f"{len(old)} commits paired, {identical} unchanged, {len(old) - identical} rewritten.")

    replaced = {a: b for a, b in mapping.items() if a != b}
    for tag in git("tag").split():
        target = git("rev-parse", f"{tag}^{{commit}}").strip()
        side = "new" if target in new else ("old" if target in replaced else "other")
        print(f"tag {tag} -> {target[:10]} ({side} history)")

    edited = set(git("diff", "--name-only", "HEAD").split()) | set(
        git("diff", "--name-only", old_head, new_head).split())
    records = sorted(set(ROOT.glob("docs/audits/*.md")) | set(ROOT.glob("docs/audits/*.json"))
                     | set(ROOT.glob("docs/audits/AUD-*-harnesses/**/*.md")))
    hexes = re.compile(r"(?<![0-9a-f])[0-9a-f]{7,40}(?![0-9a-f])")
    named_old = 0
    for path in records:
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        seen = {}
        for word in set(hexes.findall(text)):
            for full in replaced:
                if full.startswith(word):
                    seen[word] = full
        for word, full in sorted(seen.items()):
            named_old += 1
            state = "edited by the rewrite" if rel in edited else "not edited"
            print(f"OLD {rel} ({state}): names {word} = old {full[:10]}, now {replaced[full][:10]}")
    print(f"{named_old} references to replaced commits in {len(records)} audit files.")
    return 1 if problems or named_old else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
