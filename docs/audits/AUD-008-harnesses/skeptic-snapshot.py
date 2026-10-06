#!/usr/bin/env python3
"""AUD-008: bind the skeptic's first-wave review to captured source and evidence."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-008-evidence"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    snapshot = json.loads((EVIDENCE / "snapshot.json").read_text())["mhfe"]
    mismatches = []
    for name, expected in snapshot["files"].items():
        path = ROOT / name
        actual = digest(path) if path.is_file() else None
        if actual != expected:
            mismatches.append({"path": name, "expected": expected, "actual": actual})

    paths = [
        "src/bin/mhfe/protect.rs",
        "src/bin/mhfe/new_wallet.rs",
        "src/bin/mhfe/wallets.rs",
        "src/bin/mhfe/hidden_input.rs",
        "src/bin/mhfe/ask.rs",
        "src/password.rs",
        "src/phrase.rs",
        "src/repair.rs",
        "src/wallet_check.rs",
        "SECURITY.md",
        "README.md",
        "docs/API.md",
        "scripts/verify-hidden-input.py",
        "scripts/check.sh",
        "docs/audits/AUD-008-harnesses/secrets-uring.rs",
        "docs/audits/AUD-008-harnesses/secrets-uring.c",
        "docs/audits/AUD-008-harnesses/secrets-format.rs",
        "docs/audits/AUD-008-harnesses/secrets-password-lock.rs",
        "docs/audits/AUD-008-harnesses/crypto-api-probe.rs",
        "docs/audits/AUD-008-evidence/secrets-uring-probe",
        "docs/audits/AUD-008-evidence/crypto-api-probe",
        "docs/audits/AUD-008-evidence/secrets-format.log",
        "docs/audits/AUD-008-evidence/secrets-password-lock.log",
        "docs/audits/AUD-008-evidence/secrets-uring-host.log",
        "docs/audits/AUD-008-evidence/crypto-api-run.log",
        "docs/audits/AUD-008-evidence/skeptic-uring-host-replay.log",
        "docs/audits/AUD-008-evidence/skeptic-api-replay.log",
        "docs/audits/AUD-008-evidence/check-release-host.log",
        "docs/audits/AUD-008-evidence/procedure-hashes.json",
    ]
    # Include only present paths: the production prompt module may have another name.
    hashes = {name: digest(ROOT / name) for name in paths if (ROOT / name).is_file()}
    print(json.dumps({
        "auditId": "AUD-008",
        "commit": snapshot["commit"],
        "sourceFingerprint": snapshot["sourceFingerprint"],
        "capturedFilesChecked": len(snapshot["files"]),
        "sourceMismatches": mismatches,
        "fileSha256": hashes,
        "evidenceIsLocalOnly": True,
    }, indent=2))
    return bool(mismatches)


if __name__ == "__main__":
    raise SystemExit(main())
