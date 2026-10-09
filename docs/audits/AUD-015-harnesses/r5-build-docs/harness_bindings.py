#!/usr/bin/env python3
"""AUD-015 R5 probe: the file hashes that audit records bind still describe the files.

    python3 docs/audits/AUD-015-harnesses/r5-build-docs/harness_bindings.py

Read-only. For every docs/audits/audit-*.json, collects each "<path>": "<sha256>" pair whose path
names a file under docs/audits/ (harness hashes, document hashes) and each privacyRedaction
documentBindings entry. A pair is:

- current: the file's SHA-256 today is the recorded one;
- redacted-and-bound: the recorded hash is the documentBindings' originalSha256 of that file and
  the file's SHA-256 today is that entry's redactedSha256 (an owner-authorized privacy edit, the
  original hash kept as the audit recorded it);
- broken: anything else (the file changed and no binding explains it, or a binding names a hash
  the file does not have).

Prints every pair that is not current; exits 1 when one is broken.
"""
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path.cwd()
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def pairs(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str) and HEX64.match(item) and key.startswith("docs/audits/"):
                yield key, item
            yield from pairs(item)
    elif isinstance(value, list):
        for item in value:
            yield from pairs(item)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    broken = counted = 0
    for record in sorted(ROOT.glob("docs/audits/audit-*.json")):
        data = json.loads(record.read_text(encoding="utf-8"))
        bindings = {b["document"]: b for b in
                    (data.get("privacyRedaction") or {}).get("documentBindings", [])}
        for document, binding in bindings.items():
            path = ROOT / document
            if not path.is_file() or sha256(path) != binding.get("redactedSha256"):
                print(f"{record.name}: binding of {document} names redacted "
                      f"{binding.get('redactedSha256', '')[:12]}, file is "
                      f"{sha256(path)[:12] if path.is_file() else 'missing'}: broken")
                broken += 1
        for document, recorded in pairs(data):
            path = ROOT / document
            if not path.is_file():
                continue
            counted += 1
            today = sha256(path)
            if today == recorded:
                continue
            binding = bindings.get(document)
            if binding and binding.get("originalSha256") == recorded \
                    and binding.get("redactedSha256") == today:
                print(f"{record.name}: {document} redacted-and-bound")
                continue
            print(f"{record.name}: {document} recorded {recorded[:12]}, file {today[:12]}: broken")
            broken += 1
    print(f"{counted} recorded file hashes read; {broken} broken.")
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
