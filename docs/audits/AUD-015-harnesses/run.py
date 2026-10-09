#!/usr/bin/env python3
"""AUD-015 command runner: runs one command and keeps its evidence.

    python3 docs/audits/AUD-015-harnesses/run.py <label> <command> [arguments...]
    python3 docs/audits/AUD-015-harnesses/run.py snapshot <label>

Run from the repository root. A command's output goes to docs/audits/AUD-015-evidence/<label>.log
and its record (exact argv, working directory, UTC start and end, exit code, log SHA-256, seconds)
to <label>.command.json. The runner exits with the command's exit code, so a failed check fails.
`snapshot` writes <label>.json: HEAD, branch, the status of every changed path, and the source
fingerprint, the SHA-256 of the sorted list of "<sha256>  <path>" lines of every tracked or
untracked, not ignored file outside the audit's own folders.
"""
import datetime, hashlib, json, os, subprocess, sys, time
from pathlib import Path

ROOT = Path.cwd()
EVIDENCE = ROOT / "docs/audits/AUD-015-evidence"
OWN = ("docs/audits/AUD-015-evidence/", "docs/audits/AUD-015-harnesses/",
       "docs/audits/audit-15-")


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True,
                          text=True).stdout


def snapshot(label):
    files = [line for line in git("ls-files", "-co", "--exclude-standard", "-z").split("\0")
             if line and not line.startswith(OWN)]
    lines = []
    for name in sorted(files):
        path = ROOT / name
        if path.is_file():
            lines.append(f"{sha256(path)}  {name}")
    manifest = "\n".join(lines) + "\n"
    (EVIDENCE / f"{label}-manifest.txt").write_text(manifest)
    record = {
        "capturedUtc": now(),
        "head": git("rev-parse", "HEAD").strip(),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD").strip(),
        "status": git("status", "--porcelain=v1").splitlines(),
        "files": len(lines),
        "sourceFingerprint": hashlib.sha256(manifest.encode()).hexdigest(),
    }
    (EVIDENCE / f"{label}.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({k: record[k] for k in ("head", "files", "sourceFingerprint")}))
    return 0


def run(label, argv):
    log = EVIDENCE / f"{label}.log"
    start, began = now(), time.monotonic()
    with log.open("wb") as out:
        code = subprocess.run(argv, cwd=ROOT, stdout=out, stderr=subprocess.STDOUT).returncode
    record = {
        "label": label, "argv": argv, "cwd": str(ROOT), "startUtc": start, "endUtc": now(),
        "seconds": round(time.monotonic() - began, 1), "exitCode": code,
        "logSha256": sha256(log),
    }
    (EVIDENCE / f"{label}.command.json").write_text(json.dumps(record, indent=2) + "\n")
    print(f"{label}: exit {code} in {record['seconds']} s")
    return code


if __name__ == "__main__":
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    if len(sys.argv) == 3 and sys.argv[1] == "snapshot":
        sys.exit(snapshot(sys.argv[2]))
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    sys.exit(run(sys.argv[1], sys.argv[2:]))
