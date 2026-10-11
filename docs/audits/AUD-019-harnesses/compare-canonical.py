#!/usr/bin/env python3
"""Compare the uncached canonical export with the retained release candidate."""

import hashlib
import json
from pathlib import Path


class CanonicalComparison:
    def run(self):
        root = Path(__file__).resolve().parents[3]
        evidence = root / "docs/audits/AUD-019-evidence"
        fresh = root / "canonical-output-aud019_uncached/release"
        retained = root / "canonical-output-v0.6.0/release"
        candidate = root / "canonical-output-signing-v0.6.0"
        files = sorted(path.name for path in fresh.iterdir() if path.is_file())
        expected = sorted(path.name for path in retained.iterdir() if path.is_file())
        if files != expected or len(files) != 5:
            raise SystemExit("Canonical export inventory differs")
        rows = []
        for name in files:
            actual = (fresh / name).read_bytes()
            if actual != (retained / name).read_bytes():
                raise SystemExit(f"Uncached and retained canonical bytes differ: {name}")
            # The six-platform candidate checksum file includes the two macOS archives.
            candidate_match = None
            if name != "SHA256SUMS":
                candidate_match = actual == (candidate / name).read_bytes()
                if not candidate_match:
                    raise SystemExit(f"Candidate archive differs: {name}")
            rows.append({"file": name, "sha256": hashlib.sha256(actual).hexdigest(),
                         "bytes": len(actual), "retainedCanonicalByteMatch": True,
                         "candidateArchiveByteMatch": candidate_match})
        result = {"auditId": "AUD-019", "files": rows, "archiveCount": 4,
                  "checksumFileByteMatch": True,
                  "limits": "Four canonical targets compared; macOS archives are CI-built and attested, not locally reproduced."}
        (evidence / "canonical-comparison.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    CanonicalComparison().run()
