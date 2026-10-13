"""Capture AUD-020 evidence through the retained, immutable command runner."""

import importlib.util
from pathlib import Path
import sys


class AuditEvidence:
    def __init__(self):
        root = Path(__file__).resolve().parents[3]
        source = root / "docs/audits/AUD-016-harnesses/run.py"
        spec = importlib.util.spec_from_file_location("audit_command_evidence", source)
        self._runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self._runner)
        self._runner.ROOT = root
        self._runner.EVIDENCE = root / "docs/audits/AUD-020-evidence"
        self._runner.OWN = ("docs/audits/AUD-020-",)
        self._runner.EVIDENCE.mkdir(parents=True, exist_ok=True)

    def execute(self, arguments):
        if len(arguments) > 1 and arguments[1] == "--":
            arguments = [arguments[0], *arguments[2:]]
        if len(arguments) < 2:
            raise SystemExit("Usage: record.py LABEL -- COMMAND [ARGS...]")
        return self._runner.run(arguments[0], arguments[1:])


if __name__ == "__main__":
    sys.exit(AuditEvidence().execute(sys.argv[1:]))
