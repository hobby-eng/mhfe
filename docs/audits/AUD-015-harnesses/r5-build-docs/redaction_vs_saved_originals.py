#!/usr/bin/env python3
"""AUD-015 R5 probe: the redacted audit files against their exact pre-redaction bytes.

    python3 docs/audits/AUD-015-harnesses/r5-build-docs/redaction_vs_saved_originals.py \
        <baseline manifest> <after manifest> <originals folder>

<baseline manifest> and <after manifest> are AUD-015 snapshot manifests ("<sha256>  <path>" per
line, docs/audits/AUD-015-evidence/snapshot-*-manifest.txt). <originals folder> holds the exact
original bytes named "<sha256>.blob" (kept by the redaction session, outside the repository). For
every docs/audits/ or docs/measurements/ path whose SHA-256 differs between the two manifests, the
original is read from the folder by its baseline SHA-256 (refused when its bytes do not hash to
that value) and compared with the current file by audit_redaction_diff.py's rules, with every
commit reference written as <commit> on both sides, so that what is printed is every change other
than commit references (history_rewrite_map.py and record_commit_fields.py cover those). Read-only; exits 1 when an original is
missing or a finding, outcome, hash or exit code changed.
"""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import audit_redaction_diff as redaction  # noqa: E402

ROOT = Path.cwd()


def manifest(path):
    entries = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        entries[name] = digest
    return entries


def main(argv):
    if len(argv) != 3:
        sys.exit(__doc__)
    before, after, originals = argv
    redaction.IGNORE_COMMITS = True
    a, b = manifest(before), manifest(after)
    changed = sorted(n for n in set(a) | set(b) if a.get(n) != b.get(n)
                     and n.startswith(("docs/audits/", "docs/measurements/"))
                     and not n.startswith("docs/audits/AUD-015-"))
    missing, serious, residual = 0, 0, 0
    for name in changed:
        if name not in a or not (ROOT / name).is_file():
            print(f"== {name}: added or removed")
            continue
        blob = Path(originals) / f"{a[name]}.blob"
        if not blob.is_file() or hashlib.sha256(blob.read_bytes()).hexdigest() != a[name]:
            print(f"== {name}: no saved original with SHA-256 {a[name]}")
            missing += 1
            continue
        current = (ROOT / name).read_bytes()
        if name.endswith(".json"):
            lines, substantive = redaction.compare_json(name, blob.read_bytes(), current)
        else:
            lines, substantive = redaction.compare_md(name, blob.read_bytes(), current)
        print(f"== {name}: {len(lines)} residual differences, {len(substantive)} substantive")
        for line in lines:
            print("   " + line)
        residual += len(lines)
        serious += len(substantive)
    print(f"{len(changed)} changed files; {missing} without a saved original; {residual} residual "
          f"differences; {serious} touch findings, outcomes, hashes or exit codes.")
    return 1 if missing or serious else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
