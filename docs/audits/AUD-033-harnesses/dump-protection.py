"""Linux process-local policy refusal must close an actual PTY before secret input."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

if sys.flags.optimize:
    raise SystemExit("Run without -O: this control requires assertions.")
if sys.platform != "linux":
    raise SystemExit("This fault-injection control requires Linux.")
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--binary", type=Path, default=Path("target/debug/mhfe"))
parser.add_argument("--shim", type=Path, required=True)
arguments = parser.parse_args()
binary, shim = arguments.binary.resolve(), arguments.shim.resolve()
# The shared PTY fixtures accept their own binary argument, without the probe's shim option.
sys.argv = [sys.argv[0], str(binary)]
sys.path.insert(0, str(Path.cwd() / "scripts"))
from terminal_suite.session import Session

before = {"binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
          "shimSha256": hashlib.sha256(shim.read_bytes()).hexdigest()}
print(json.dumps({"phase": "before", **before}), flush=True)
with patch.dict(os.environ, {"LD_PRELOAD": str(shim)}):
    session = Session(program=str(binary))
try:
    seen = session.wait_for(b"MEMORY_PROTECTION_FAILED", b"original seed phrase: ")
    assert b"public-probe: MADV_DONTDUMP refused" in session.output, "fault was not exercised"
    assert seen == b"MEMORY_PROTECTION_FAILED", "secret input opened after a policy refusal"
    assert session.drain_until_exit(5), "failed startup did not close"
finally:
    code, settings = session.close()
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == before["binarySha256"], "binary changed"
    assert hashlib.sha256(shim.read_bytes()).hexdigest() == before["shimSha256"], "shim changed"
assert code == 1 and settings == session.original, "fatal startup or terminal cleanup differs"
assert b"public-probe: MADV_DONTDUMP refused" in session.output, "fault was not exercised"
assert b"original seed phrase: " not in session.output, "secret prompt was admitted"
print(json.dumps({**before, "exitCode": code, "policyRefusalBeforeSecretPrompt": True}))
