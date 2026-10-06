"""Check retained AUD-007 evidence and commit signatures using the owner's public key."""

import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-007-evidence"
REPORT = ROOT / "docs/audits/audit-07-2026-10-05.json"
data = json.loads(REPORT.read_text())
original = json.loads(subprocess.check_output([
    "git", "show", "3c2793d:docs/audits/audit-07-2026-10-05.json",
], cwd=ROOT))
assert data["commands"] == original["commands"]
assert data["snapshot"] == original["snapshot"]
print("Original command register and snapshot are unchanged.")

for command in data["remediationUpdate"]["commands"]:
    label = command["label"]
    log = EVIDENCE / (label + ".log")
    saved = json.loads((EVIDENCE / (label + ".command.json")).read_text())
    assert hashlib.sha256(log.read_bytes()).hexdigest() == command["logSha256"], label
    assert saved.get("exitCode", saved.get("exit_code")) == command["exitCode"], label
    if "logSha256" in saved:
        assert saved["logSha256"] == command["logSha256"], label
    print(f"{label}: retained log and exit code verified")

# Trust this explicitly named local public key, not an automatically supplied remote identity.
# The temporary allowed-signers file stays in ignored evidence; Git configuration is untouched.
public_key = Path.home() / ".ssh/hobby-eng_signing.pub"
fields = public_key.read_text().split()
assert len(fields) >= 2 and fields[0].startswith("ssh-")
allowed = EVIDENCE / "recheck-allowed-signers"
allowed.write_text("hobby-eng " + " ".join(fields[:2]) + "\n")
commits = subprocess.check_output([
    "git", "rev-list", "--reverse", "3c2793d^..2a5e727",
], cwd=ROOT, text=True).splitlines()
assert len(commits) == 5
for commit in commits:
    result = subprocess.run([
        "git", "-c", "gpg.ssh.allowedSignersFile=" + str(allowed), "verify-commit", commit,
    ], cwd=ROOT, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    print(f"{commit}: {result.stderr.strip()}")
print("All five signatures verify against the owner's named local public key.")
