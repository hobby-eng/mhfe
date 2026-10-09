#!/usr/bin/env python3
"""Capture new release-check evidence while preserving the historical AUD-016 runner."""

import importlib.util
import sys
from pathlib import Path


class ReleaseEvidence:
    def __init__(self):
        self._root = Path(__file__).resolve().parents[3]
        source = self._root / "docs/audits/AUD-016-harnesses/run.py"
        # Reuse the retained command/snapshot implementation without editing its historical bytes.
        spec = importlib.util.spec_from_file_location("aud016_evidence", source)
        self._runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self._runner)
        self._runner.ROOT = self._root
        self._runner.EVIDENCE = self._root / "docs/audits/AUD-018-evidence"
        self._runner.OWN = ("docs/audits/AUD-018-", "docs/audits/audit-18-")
        self._runner.EVIDENCE.mkdir(parents=True, exist_ok=True)

    def execute(self, arguments):
        if len(arguments) == 2 and arguments[0] == "snapshot":
            return self._runner.snapshot(arguments[1])
        if len(arguments) < 2:
            raise SystemExit("Usage: run.py LABEL COMMAND [ARGS...] | run.py snapshot LABEL")
        return self._runner.run(arguments[0], arguments[1:])


if __name__ == "__main__":
    sys.exit(ReleaseEvidence().execute(sys.argv[1:]))
