#!/usr/bin/env python3
"""Run the canonical recipe with audit-only untracked documents excluded from Git status."""

import os
import subprocess
from pathlib import Path


class CanonicalAuditBuild:
    def run(self):
        root = Path(__file__).resolve().parents[3]
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        if commit != "66f142566464255e331763966b00ea1681c2dabd":
            raise SystemExit("Reviewed release commit changed")
        subprocess.run(["git", "diff", "--exit-code", "HEAD"], cwd=root, check=True)
        untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"], cwd=root).decode().split("\0")
        permitted = ("docs/audits/AUD-019-harnesses/", "docs/audits/audit-19-")
        if any(name and not name.startswith(permitted) for name in untracked):
            raise SystemExit("An untracked file outside the audit exists; refuse a clean-source build")
        ignore = root / "docs/audits/AUD-019-evidence/canonical-git-ignore"
        ignore.write_text("/docs/audits/AUD-019-harnesses/\n/docs/audits/audit-19-*\n")
        environment = os.environ.copy()
        count = int(environment.get("GIT_CONFIG_COUNT", "0"))
        environment[f"GIT_CONFIG_KEY_{count}"] = "core.excludesFile"
        environment[f"GIT_CONFIG_VALUE_{count}"] = str(ignore)
        environment["GIT_CONFIG_COUNT"] = str(count + 1)
        environment["REPRODUCIBLE_NO_CACHE"] = "1"
        status = subprocess.check_output(["git", "status", "--porcelain"], cwd=root, env=environment, text=True)
        if status:
            raise SystemExit("Canonical build inputs differ from the reviewed commit")
        print("All tracked files match the signed release commit; only the current audit's new documents are ignored in process-local Git status. No Git configuration is changed on disk.", flush=True)
        # The historical wrapper only adds the task's kernel cgroup parent to BuildKit.
        return subprocess.run(["bash", "docs/audits/AUD-018-harnesses/canonical.sh", "canonical-output-aud019_uncached"], cwd=root, env=environment).returncode


if __name__ == "__main__":
    raise SystemExit(CanonicalAuditBuild().run())
