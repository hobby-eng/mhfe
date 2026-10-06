#!/usr/bin/env python3
"""Compile a 16 KiB retention probe from the current hidden-wallet copy expression."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

repo = Path(__file__).resolve().parents[3]
out = repo / "docs/audits/AUD-008-evidence"
out.mkdir(exist_ok=True)
source = repo / "src/bin/mhfe/wallets.rs"
expression = "used.push(Zeroizing::new(password.as_bytes().to_vec()));"
if expression not in source.read_text():
    raise SystemExit("The reviewed retention expression changed; reassess the probe.")
harness = Path(__file__).with_suffix(".rs").read_text().replace("// SOURCE_RETENTION_EXPRESSION", expression)
generated = out / "secrets-password-lock-generated.rs"
generated.write_text(harness)
env = os.environ.copy()
env.update(CARGO_HOME=str(repo.parent / "workingspace/cargo"), RUSTUP_HOME=str(repo.parent / "workingspace/rustup"))
libs = {crate: max((repo / "target/debug/deps").glob(f"lib{crate}-*.rlib"), key=lambda p: p.stat().st_mtime) for crate in ("mhfe", "zeroize")}
command = [str(repo.parent / "workingspace/cargo/bin/rustc"), "--edition=2021", str(generated), "--crate-name", "aud008_secrets_password_lock", "-L", f"dependency={repo / 'target/debug/deps'}", "-o", str(out / "secrets-password-lock-probe")]
for crate, path in libs.items():
    command.extend(["--extern", f"{crate}={path}"])
print(json.dumps({"sourceSha256": hashlib.sha256(source.read_bytes()).hexdigest(), "linkedLibraries": {k: str(v) for k, v in libs.items()}, "compileCommand": command}), flush=True)
subprocess.run(command, cwd=repo, env=env, check=True)
sys.exit(subprocess.run([str(out / "secrets-password-lock-probe")], cwd=repo, env=env).returncode)
