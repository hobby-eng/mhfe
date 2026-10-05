"""Compile the retained AUD-007 public-vector probe against this checkout's built library."""

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
SOURCE = Path(__file__).with_suffix(".rs")
DEPENDENCIES = ROOT / "target/debug/deps"
ENVIRONMENT = dict(os.environ)
ENVIRONMENT["CARGO_HOME"] = str(ROOT.parent / "workingspace/cargo")
ENVIRONMENT["RUSTUP_HOME"] = str(ROOT.parent / "workingspace/rustup")

rustc = subprocess.check_output(
    ["rustup", "which", "rustc"], cwd=ROOT, env=ENVIRONMENT, text=True
).strip()
libraries = {}
for name in ("mhfe", "bech32"):
    candidates = list(DEPENDENCIES.glob("lib" + name + "-*.rlib"))
    if not candidates:
        raise SystemExit("Run cargo build --locked --lib in the authoritative checkout first.")
    libraries[name] = max(candidates, key=lambda path: path.stat().st_mtime)

# Only the tiny probe executable is temporary; no source checkout is copied.
with tempfile.TemporaryDirectory(prefix="mhfe-aud007-wallet-") as temporary:
    executable = Path(temporary) / "wallet-bech32-variant"
    command = [
        rustc,
        "--edition=2021",
        "--crate-name",
        "wallet_bech32_variant",
        str(SOURCE),
        "-L",
        "dependency=" + str(DEPENDENCIES),
        "-o",
        str(executable),
    ]
    for name, path in libraries.items():
        command.extend(["--extern", name + "=" + str(path)])
    subprocess.run(command, cwd=ROOT, env=ENVIRONMENT, check=True)
    subprocess.run([str(executable)], cwd=ROOT, env=ENVIRONMENT, check=True)
