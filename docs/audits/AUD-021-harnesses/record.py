"""Capture AUD-021 remediation evidence using the retained command runner."""

import importlib.util
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
source = ROOT / "docs/audits/AUD-016-harnesses/run.py"
spec = importlib.util.spec_from_file_location("audit_command_evidence", source)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
runner.ROOT = ROOT
runner.EVIDENCE = ROOT / "docs/audits/AUD-021-evidence"
runner.OWN = ("docs/audits/AUD-021-",)
runner.EVIDENCE.mkdir(parents=True, exist_ok=True)


if __name__ == "__main__":
    arguments = sys.argv[1:]
    if len(arguments) > 1 and arguments[1] == "--":
        arguments = [arguments[0], *arguments[2:]]
    if len(arguments) < 2:
        raise SystemExit("Usage: record.py LABEL -- COMMAND [ARGS...]")
    sys.exit(runner.run(arguments[0], arguments[1:]))
