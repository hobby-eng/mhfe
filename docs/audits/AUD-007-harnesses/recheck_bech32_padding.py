"""Compile a public-vector padding probe; write only ignored AUD-007 local evidence."""

import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
SOURCE = Path(__file__).with_suffix(".rs")
EVIDENCE = ROOT / "docs/audits/AUD-007-evidence"
DEPENDENCIES = ROOT / "target/debug/deps"
ENVIRONMENT = dict(os.environ)
ENVIRONMENT["CARGO_HOME"] = str(ROOT.parent / "workingspace/cargo")
ENVIRONMENT["RUSTUP_HOME"] = str(ROOT.parent / "workingspace/rustup")
RUSTUP = ROOT.parent / "workingspace/cargo/bin/rustup"
rustc = subprocess.check_output(
    [str(RUSTUP), "which", "rustc"], cwd=ROOT, env=ENVIRONMENT, text=True
).strip()
executable = EVIDENCE / "recheck-bech32-padding"
command = [
    rustc, "--edition=2021", str(SOURCE), "-L", "dependency=" + str(DEPENDENCIES),
    "-o", str(executable),
]
inputs = {str(SOURCE.relative_to(ROOT)): hashlib.sha256(SOURCE.read_bytes()).hexdigest()}
for name in ("mhfe", "bech32"):
    candidates = list(DEPENDENCIES.glob("lib" + name + "-*.rlib"))
    if not candidates:
        raise SystemExit("Run cargo build --locked --bin mhfe first.")
    library = max(candidates, key=lambda path: path.stat().st_mtime)
    inputs[str(library.relative_to(ROOT))] = hashlib.sha256(library.read_bytes()).hexdigest()
    command.extend(["--extern", name + "=" + str(library)])
subprocess.run(command, cwd=ROOT, env=ENVIRONMENT, check=True)
inputs[str(executable.relative_to(ROOT))] = hashlib.sha256(executable.read_bytes()).hexdigest()
print(json.dumps({"inputSha256": inputs}), flush=True)
subprocess.run([str(executable)], cwd=ROOT, env=ENVIRONMENT, check=True)
