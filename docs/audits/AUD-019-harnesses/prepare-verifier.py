#!/usr/bin/env python3
"""Check the official download checksum and extract only the audit-local gh executable."""

import hashlib
import json
import tarfile
from pathlib import Path


class AttestationVerifier:
    def prepare(self):
        root = Path(__file__).resolve().parents[3]
        folder = root / "docs/audits/AUD-019-evidence/tools"
        archive = folder / "gh_2.101.0_linux_amd64.tar.gz"
        checksums = folder / "gh_2.101.0_checksums.txt"
        entries = [line.split() for line in checksums.read_text().splitlines()]
        expected = [parts[0] for parts in entries if parts[-1] == archive.name]
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        if expected != [actual]:
            raise SystemExit("Official gh download checksum mismatch or duplicate entry")
        with tarfile.open(archive) as source:
            member = source.getmember("gh_2.101.0_linux_amd64/bin/gh")
            if not member.isfile():
                raise SystemExit("Expected gh executable is not a regular archive member")
            executable = source.extractfile(member).read()
        output = folder / "gh"
        output.write_bytes(executable)
        output.chmod(0o700)
        print(json.dumps({"archiveSha256": actual, "executableSha256": hashlib.sha256(executable).hexdigest(), "version": "2.101.0", "trust": "official cli/cli release checksum obtained through GitHub HTTPS; no independent bootstrap signature claim"}))


if __name__ == "__main__":
    AttestationVerifier().prepare()
