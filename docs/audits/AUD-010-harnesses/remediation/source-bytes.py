#!/usr/bin/env python3
"""AUD-010 remediation harness: does the working tree still hold the bytes of a source snapshot?

    python3 docs/audits/AUD-010-harnesses/remediation/source-bytes.py SNAPSHOT [--captured UTC]

SNAPSHOT is the JSON that fingerprint.mjs printed: {"fingerprint", "paths", "head", "records"},
each record a [path, SHA-256 or "deleted"] pair. The script checks that
- the records reproduce the snapshot's fingerprint (fingerprint.mjs's rule: SHA-256 of their
  compact JSON text);
- every recorded file still has its recorded SHA-256, and every file recorded as deleted is still
  missing;
- with --captured, no recorded file was modified after that UTC time (YYYY-MM-DDTHH:MM:SSZ), so the
  bytes did not change and change back while the checks ran.

It compares bytes only, so it holds whether or not the changes have been committed since. Reads
only; prints one line per check and exits 0 when all pass, 1 when one fails, 2 on a usage error.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[4]
USAGE = "usage: source-bytes.py SNAPSHOT [--captured YYYY-MM-DDTHH:MM:SSZ]"


def arguments():
    args = sys.argv[1:]
    if len(args) not in (1, 3) or (len(args) == 3 and args[1] != "--captured"):
        print(USAGE, file=sys.stderr)
        sys.exit(2)
    captured = None
    if len(args) == 3:
        try:
            moment = datetime.strptime(args[2], "%Y-%m-%dT%H:%M:%SZ")
            captured = moment.replace(tzinfo=timezone.utc)
        except ValueError:
            print(USAGE, file=sys.stderr)
            sys.exit(2)
    return Path(args[0]), captured


def main():
    snapshot_path, captured = arguments()
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    records = snapshot["records"]
    failures = []

    # fingerprint.mjs hashes JSON.stringify(records): compact, no spaces.
    recomputed = hashlib.sha256(
        json.dumps(records, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    if recomputed != snapshot["fingerprint"] or len(records) != snapshot["paths"]:
        failures.append(f"the records give {recomputed}, not the recorded fingerprint")
    print(f"snapshot: fingerprint {snapshot['fingerprint']}, {len(records)} records")

    changed, missing, reappeared, newer = [], [], [], []
    present = 0
    for path, digest in records:
        file = REPO / path
        if digest == "deleted":
            if file.exists():
                reappeared.append(path)
            continue
        if not file.is_file():
            missing.append(path)
            continue
        present += 1
        if hashlib.sha256(file.read_bytes()).hexdigest() != digest:
            changed.append(path)
        if captured and datetime.fromtimestamp(file.stat().st_mtime, timezone.utc) > captured:
            newer.append(path)
    deleted = sum(1 for _, digest in records if digest == "deleted")
    print(f"files: {present} present, SHA-256 compared; {deleted} recorded as deleted")
    for label, paths in [
        ("changed", changed),
        ("missing", missing),
        ("deleted but present again", reappeared),
        ("modified after the capture", newer),
    ]:
        if paths:
            failures.append(f"{len(paths)} {label}: {', '.join(paths[:10])}")
    if captured and not newer:
        print(f"modification times: none after {captured.strftime('%Y-%m-%dT%H:%M:%SZ')}")

    for failure in failures:
        print(f"FAIL {failure}")
    if failures:
        sys.exit(1)
    print("PASS: the working tree holds the snapshot's bytes.")


if __name__ == "__main__":
    main()
