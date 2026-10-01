"""Record bounded audit commands and the immutable source inventory; never run full-cost MHFE."""

import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-004-evidence"
WORKSPACE = ROOT.parent
PROCEDURES = (
    "multi-chain-wallet-tools/docs/FULL_AUDIT_GUIDE.md",
    "multi-chain-wallet-tools/docs/audits/AUDIT_STANDARD.md",
    "multi-chain-wallet-tools/docs/audits/AUDIT_TEMPLATE.md",
    "multi-chain-wallet-tools/docs/audit-report.schema.json",
    "AGENTS.md",
    "mhfe/AGENTS.md",
)


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(name, value):
    (EVIDENCE / name).write_text(json.dumps(value, indent=2) + "\n")


def git(*args, cwd=ROOT):
    return subprocess.check_output(["git", *args], cwd=cwd).decode().strip()


def capture():
    target = EVIDENCE / "snapshot.json"
    if target.exists():
        raise ValueError("Snapshot already captured; do not overwrite it.")
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    inventory = {name: sha((ROOT / name).read_bytes()) for name in names if name}
    spec = WORKSPACE / "mhfe_spec"
    snapshot = {
        "capturedAt": now(), "commit": git("rev-parse", "HEAD"),
        "commitComplete": True, "branch": git("branch", "--show-current"),
        "workingTree": git("status", "--short"),
        "preExistingChanges": "Untracked AGENTS.md only; the audit harness is newly added.",
        "sourceFiles": inventory,
        "sourceFingerprint": sha("".join(f"{n}\0{h}\n" for n, h in inventory.items()).encode()),
        "fingerprintMethod": "SHA-256 of sorted git-tracked path + NUL + file SHA-256 + LF.",
        "specificationCommit": git("rev-parse", "HEAD", cwd=spec),
        "specificationFiles": {name: sha((spec / name).read_bytes()) for name in ("README.md", "docs/DESIGN-NOTES.md")},
    }
    save("snapshot.json", snapshot)
    hashes = {name: sha((WORKSPACE / name).read_bytes()) for name in PROCEDURES}
    skill = Path.home() / ".codex/skills/wallet-full-audit/SKILL.md"
    hashes[str(skill)] = sha(skill.read_bytes())
    save("procedure-hashes.json", hashes)
    (EVIDENCE / "environment.log").write_text(
        f"Captured: {now()}\nOS: {platform.platform()}\nPython: {sys.version}\n"
        "Full-cost vector computation is excluded by the user; builds are serialized.\n"
    )
    print(json.dumps({key: value for key, value in snapshot.items() if key != "sourceFiles"}, indent=2))


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    if sys.argv[1:] == ["capture"]:
        capture()
        return
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        raise SystemExit("Usage: run.py capture | LABEL -- COMMAND [ARG ...]")
    label = sys.argv[1]
    if (EVIDENCE / f"{label}.command.json").exists():
        raise ValueError("Command label already exists; preserve the earlier run.")
    command = sys.argv[3:]
    env = os.environ.copy()
    env.update({
        "CARGO_HOME": str(WORKSPACE / "workingspace/cargo"),
        "RUSTUP_HOME": str(WORKSPACE / "workingspace/rustup"),
        "CARGO_BUILD_JOBS": "1",
        "PATH": str(Path.home() / ".local/bin") + ":" + str(WORKSPACE / "workingspace/cargo/bin") + ":" + env["PATH"],
    })
    start = now()
    log_path = EVIDENCE / f"{label}.log"
    with log_path.open("wb") as log:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    record = {
        "command": command, "cwd": str(ROOT), "startedAt": start, "endedAt": now(),
        "exitCode": result.returncode, "logSha256": sha(log_path.read_bytes()),
        "environment": {name: env[name] for name in ("CARGO_HOME", "RUSTUP_HOME", "CARGO_BUILD_JOBS", "PATH")},
    }
    save(f"{label}.command.json", record)
    print(log_path.read_text(), end="")
    print(json.dumps(record))
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
