"""Bind the actual public PTY controls to one unchanged executable."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

if sys.flags.optimize:
    raise SystemExit("Run without -O: this control requires assertions.")

binary = Path("target/debug/mhfe").resolve()
before = hashlib.sha256(binary.read_bytes()).hexdigest()
print(json.dumps({"phase": "before", "binarySha256": before}), flush=True)
try:
    result = subprocess.run(
        [sys.executable, "docs/audits/AUD-033-harnesses/cli-retries.py", str(binary)],
        check=False,
    )
    assert result.returncode == 0, result.returncode
finally:
    after = hashlib.sha256(binary.read_bytes()).hexdigest()
    print(json.dumps({"phase": "after", "binarySha256": after}), flush=True)
    assert before == after, "CLI executable changed during the PTY controls"
