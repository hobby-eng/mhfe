#!/usr/bin/env python3
"""Capture AUD-019 evidence using the retained, immutable command runner."""

import importlib.util
import sys
from pathlib import Path


class AuditEvidence:
    def __init__(self):
        root = Path(__file__).resolve().parents[3]
        source = root / "docs/audits/AUD-016-harnesses/run.py"
        spec = importlib.util.spec_from_file_location("audit_command_evidence", source)
        self._runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self._runner)
        self._runner.ROOT = root
        self._runner.EVIDENCE = root / "docs/audits/AUD-019-evidence"
        self._runner.OWN = ("docs/audits/AUD-019-", "docs/audits/audit-19-")
        self._runner.EVIDENCE.mkdir(parents=True, exist_ok=True)

    def execute(self, arguments):
        if len(arguments) == 2 and arguments[0] == "snapshot":
            return self._runner.snapshot(arguments[1])
        if len(arguments) < 2:
            raise SystemExit("Usage: run.py LABEL COMMAND [ARGS...] | snapshot LABEL")
        return self._runner.run(arguments[0], arguments[1:])


if __name__ == "__main__":
    sys.exit(AuditEvidence().execute(sys.argv[1:]))
