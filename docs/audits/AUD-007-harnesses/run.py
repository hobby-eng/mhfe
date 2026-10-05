"""Capture read-only AUD-007 checks and their local evidence; never supply real wallet secrets."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-007-evidence"
PROCEDURES = (
    "docs/FULL_AUDIT_GUIDE.md",
    "docs/audits/AUDIT_STANDARD.md",
    "docs/audits/AUDIT_TEMPLATE.md",
    "docs/audit-report.schema.json",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root)


def save(name, value):
    (EVIDENCE / name).write_text(json.dumps(value, indent=2) + "\n")


def snapshot():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    files = {}
    for raw in git(ROOT, "ls-files", "-z").split(b"\0"):
        if raw:
            name = raw.decode()
            files[name] = digest((ROOT / name).read_bytes())
    spec = ROOT.parent / "mhfe_spec"
    save("snapshot.json", {
        "capturedAt": datetime.now(timezone.utc).isoformat(),
        "commit": git(ROOT, "rev-parse", "HEAD").decode().strip(),
        "workingTree": git(ROOT, "status", "--porcelain").decode(),
        "sourceFiles": files,
        "sourceFingerprint": digest("".join(f"{n}\0{h}\n" for n, h in files.items()).encode()),
        "specificationCommit": git(spec, "rev-parse", "HEAD").decode().strip(),
        "specificationWorkingTree": git(spec, "status", "--porcelain").decode(),
        "specificationFiles": {
            name: digest((spec / name).read_bytes())
            for name in ("README.md", "docs/DESIGN-NOTES.md", "CHANGELOG.md")
        },
    })
    (EVIDENCE / "specification.diff").write_bytes(git(spec, "diff", "--binary"))
    save("procedure-hashes.json", {
        "multi-chain-wallet-tools/" + name: digest(
            (ROOT.parent / "multi-chain-wallet-tools" / name).read_bytes()
        )
        for name in PROCEDURES
    })


def run(label, cwd, command):
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc).isoformat()
    log = EVIDENCE / (label + ".log")
    with log.open("wb") as stream:
        result = subprocess.run(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT)
    record = {
        "label": label,
        "command": command,
        "cwd": str(Path(cwd).resolve()),
        "startedAt": started,
        "finishedAt": datetime.now(timezone.utc).isoformat(),
        "exitCode": result.returncode,
        "logSha256": digest(log.read_bytes()),
        "evidence": str(log.relative_to(ROOT)),
    }
    save(label + ".command.json", record)
    print(json.dumps(record))
    print(log.read_text(errors="replace")[-7000:])
    raise SystemExit(result.returncode)


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("action", choices=("snapshot", "run"))
parser.add_argument("label", nargs="?")
parser.add_argument("--cwd", default=str(ROOT))
parser.add_argument("command", nargs=argparse.REMAINDER)
args = parser.parse_args()
if args.action == "snapshot":
    snapshot()
else:
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not args.label or not command:
        parser.error("run needs a label and a command after --")
    run(args.label, args.cwd, command)
