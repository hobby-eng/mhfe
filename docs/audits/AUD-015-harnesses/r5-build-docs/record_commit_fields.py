#!/usr/bin/env python3
"""AUD-015 R5 probe: commit fields of the JSON audit records name commits of the current history.

    python3 docs/audits/AUD-015-harnesses/r5-build-docs/record_commit_fields.py

Read-only. Walks every docs/audits/audit-*.json and takes each value of a key whose name says it
holds a commit (commit, head, fixCommit, verificationCommit, reviewedCommit, baseCommit,
sourceCommit, ...; any key ending in "Commit" or "commit", or "commits" lists). Each value that is
a 7- to 40-digit hex word is resolved:

- current: an ancestor of HEAD (or HEAD);
- unreachable: an object that exists but no branch or tag contains (replaced by a rewrite);
- spec: no such object here, but a commit of the sibling ../mhfe_spec checkout;
- missing: in neither repository (a commit a rewrite replaced and a prune removed, or a typo).

Prints every field that is not current; exits 1 when a structured field names an unreachable or
missing commit. Prose mentions of commits are left to history_rewrite_map.py.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()
HEX = re.compile(r"^[0-9a-f]{7,40}$")


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)


def resolve(word):
    found = git("rev-parse", "--verify", "--quiet", f"{word}^{{commit}}")
    if found.returncode != 0:
        spec = subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"{word}^{{commit}}"],
                              cwd=ROOT.parent / "mhfe_spec", capture_output=True, text=True)
        return ("spec" if spec.returncode == 0 else "missing"), None
    full = found.stdout.strip()
    if git("merge-base", "--is-ancestor", full, "HEAD").returncode == 0:
        return "current", full
    contained = git("for-each-ref", "--contains", full, "refs/heads", "refs/tags").stdout.strip()
    return ("other-ref" if contained else "unreachable"), full


def commit_fields(value, path=""):
    if isinstance(value, dict):
        for key, item in value.items():
            here = f"{path}/{key}"
            if (key.lower().endswith("commit") or key.lower().endswith("commits")
                    or key in ("head",)) and item is not None:
                items = item if isinstance(item, list) else [item]
                for each in items:
                    if isinstance(each, str) and HEX.match(each):
                        yield here, each
            yield from commit_fields(item, here)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from commit_fields(item, f"{path}[{index}]")


def main():
    bad = 0
    counts = {}
    for record in sorted(ROOT.glob("docs/audits/audit-*.json")):
        data = json.loads(record.read_text(encoding="utf-8"))
        for path, word in commit_fields(data):
            state, full = resolve(word)
            counts[state] = counts.get(state, 0) + 1
            if state != "current":
                print(f"{record.name}:{path}: {word} {state}")
            if state in ("unreachable", "missing"):
                bad += 1
    print(f"structured commit fields: {counts}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
