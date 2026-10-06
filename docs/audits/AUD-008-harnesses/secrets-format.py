#!/usr/bin/env python3
"""Compile a bounded source-expression allocation probe with existing pinned Rust libraries."""
import glob
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

repo = Path(__file__).resolve().parents[3]
out = repo / "docs/audits/AUD-008-evidence"
out.mkdir(exist_ok=True)
new_source = (repo / "src/bin/mhfe/new_wallet.rs").read_text()
match = re.search(r"Ok\((Zeroizing::new\(mnemonic\.to_string\(\)\))\)", new_source)
if not match:
    raise SystemExit("The reviewed formatter changed; reassess the probe before running.")
phrase_source = (repo / "src/phrase.rs").read_text()
start = phrase_source.index("pub(crate) fn phrase_text(")
end = phrase_source.index("\n}\n", start) + 2
safe = phrase_source[start:end].replace("pub(crate) fn", "fn", 1)
harness = Path(__file__).with_suffix(".rs").read_text()
harness = harness.replace("// SOURCE_EXPRESSION", match[1]).replace("// SOURCE_SAFE_FORMATTER", safe)
compiled = out / "secrets-format-generated.rs"
compiled.write_text(harness)
env = os.environ.copy()
env.update(CARGO_HOME=str(repo.parent / "workingspace/cargo"), RUSTUP_HOME=str(repo.parent / "workingspace/rustup"))
libs = {}
for crate in ("bip39", "zeroize"):
    paths = list((repo / "target/debug/deps").glob(f"lib{crate}-*.rlib"))
    libs[crate] = max(paths, key=lambda p: p.stat().st_mtime)
command = [str(repo.parent / "workingspace/cargo/bin/rustc"), "--edition=2021", str(compiled), "--crate-name", "aud008_secrets_format", "-L", f"dependency={repo / 'target/debug/deps'}", "-o", str(out / "secrets-format-probe")]
for crate, library in libs.items():
    command.extend(["--extern", f"{crate}={library}"])
print(json.dumps({"sourceHashes": {str(p): hashlib.sha256((repo / p).read_bytes()).hexdigest() for p in (Path("src/bin/mhfe/new_wallet.rs"), Path("src/phrase.rs"))}, "linkedLibraries": {k: str(v) for k, v in libs.items()}, "compileCommand": command}), flush=True)
subprocess.run(command, cwd=repo, env=env, check=True)
result = subprocess.run([str(out / "secrets-format-probe")], cwd=repo, env=env)
sys.exit(result.returncode)
