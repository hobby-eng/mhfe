#!/usr/bin/env python3
"""Bind AUD-008 to the dirty MHFE source and its current specification."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-008-evidence"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def snapshot(repo):
    files = subprocess.check_output(["git", "ls-files", "-z"], cwd=repo).decode().split("\0")
    manifest = {p: sha((repo / p).read_bytes()) for p in sorted(files)
                if p and not p.startswith("docs/audits/") and (repo / p).is_file()}
    return {"commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo).decode().strip(),
            "branch": subprocess.check_output(["git", "branch", "--show-current"], cwd=repo).decode().strip(),
            "workingTree": subprocess.check_output(["git", "status", "--porcelain"], cwd=repo).decode(),
            "files": manifest, "sourceFingerprint": sha("".join(p + "\0" + s + "\n" for p,s in manifest.items()).encode())}


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    target = EVIDENCE / "snapshot.json"
    current = {"mhfe": snapshot(ROOT), "specification": snapshot(ROOT.parent / "mhfe_spec")}
    if target.exists():
        old = json.loads(target.read_text())
        results = {}
        for key, item in current.items():
            previous = old[key]
            changed = [p for p in sorted(set(previous["files"]) | set(item["files"]))
                       if previous["files"].get(p) != item["files"].get(p)]
            results[key] = {"commitUnchanged": previous["commit"] == item["commit"], "changedFiles": changed,
                            "sourceFingerprint": item["sourceFingerprint"]}
        result = {"unchanged": all(v["commitUnchanged"] and not v["changedFiles"] for v in results.values()), "repositories": results}
        (EVIDENCE / "snapshot-verification.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result))
        return 0 if result["unchanged"] else 1
    current.update(auditId="AUD-008", startedAt=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   requestedReviewers=11, verificationLevel="pre-release",
                   exclusions=["Long full Rust/Python vector replays explicitly excluded by the owner."])
    target.write_text(json.dumps(current, indent=2) + "\n")
    for key, repo in [("mhfe", ROOT), ("specification", ROOT.parent / "mhfe_spec")]:
        (EVIDENCE / (key + "-initial.patch")).write_bytes(subprocess.check_output(["git", "diff", "--binary"], cwd=repo))
    paths = [ROOT.parent / "multi-chain-wallet-tools" / p for p in
             ("docs/FULL_AUDIT_GUIDE.md", "docs/audits/AUDIT_STANDARD.md", "docs/audits/AUDIT_TEMPLATE.md", "docs/audit-report.schema.json")]
    paths += [ROOT.parent / "AGENTS.md", ROOT / "AGENTS.md", ROOT.parent / "mhfe_spec/AGENTS.md",
              Path.home() / ".codex/skills/wallet-full-audit/SKILL.md",
              Path.home() / ".codex/skills/wallet-release-verification/SKILL.md"]
    (EVIDENCE / "procedure-hashes.json").write_text(json.dumps({str(p):sha(p.read_bytes()) for p in paths}, indent=2) + "\n")
    print(json.dumps({key: {k:v for k,v in item.items() if k != "files"} for key,item in current.items() if isinstance(item,dict)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
