#!/usr/bin/env python3
"""Verify checksum coverage and exact archive equality for cached/uncached canonical builds."""

import datetime
import hashlib
import json
from pathlib import Path


class CanonicalComparison:
    def __init__(self):
        self._root = Path(__file__).resolve().parents[3]

    def _manifest(self, directory):
        lines = (directory / "SHA256SUMS").read_text().splitlines()
        checksums = {}
        for line in lines:
            digest, name = line.split(maxsplit=1)
            assert name not in checksums and "/" not in name
            path = directory / name
            observed = hashlib.sha256(path.read_bytes()).hexdigest()
            assert digest == observed, (str(directory), name)
            checksums[name] = {"sha256": observed, "bytes": path.stat().st_size}
        assert len(checksums) == 4
        assert {p.name for p in directory.iterdir() if p.is_file()} == set(checksums) | {"SHA256SUMS"}
        return checksums

    def run(self):
        cached = self._root / "canonical-output-aud018/release"
        uncached = self._root / "canonical-output-aud018_uncached/release"
        left = self._manifest(cached)
        right = self._manifest(uncached)
        assert set(left) == set(right)
        rows = [{"name": name, "cached": left[name], "uncached": right[name],
                 "equal": (cached / name).read_bytes() == (uncached / name).read_bytes()}
                for name in sorted(left)]
        checksum_files_equal = (cached / "SHA256SUMS").read_bytes() == (uncached / "SHA256SUMS").read_bytes()
        record = {"auditId": "AUD-018", "checkedUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                  "cachedDirectory": str(cached), "uncachedDirectory": str(uncached),
                  "archives": rows, "checksumFilesEqual": checksum_files_equal,
                  "passed": all(row["equal"] for row in rows) and checksum_files_equal,
                  "meaning": "These exact canonical cached/REPRODUCIBLE_NO_CACHE=1 builds on this machine produced equal archives only if every equal flag is true. This is the documented local reproducibility comparison, not platform execution, upstream authenticity or a whole-machine compromise certificate."}
        evidence = self._root / "docs/audits/AUD-018-evidence/canonical-comparison.json"
        assert not evidence.exists(), "Retain earlier comparison evidence; use a new label."
        evidence.write_text(json.dumps(record, indent=2) + "\n")
        print(json.dumps({"archives": len(rows), "passed": record["passed"], "checksumFilesEqual": record["checksumFilesEqual"]}))
        return not record["passed"]


if __name__ == "__main__":
    raise SystemExit(CanonicalComparison().run())
