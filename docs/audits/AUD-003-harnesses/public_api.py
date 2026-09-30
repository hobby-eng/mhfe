"""Compile a production-library consumer, using Cargo's exact artifact path; no Argon2 calls."""

import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
result = subprocess.run(
    ["cargo", "build", "--locked", "--offline", "--lib", "--message-format=json"],
    cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE,
)
artifacts = [json.loads(line) for line in result.stdout.splitlines()]
library = next(
    path for item in artifacts
    if item.get("reason") == "compiler-artifact" and item["target"]["name"] == "mhfe"
    for path in item["filenames"] if path.endswith(".rlib")
)
binary = ROOT / "docs/audits/AUD-003-evidence/public-api-probe"
subprocess.run([
    "rustc", "--edition=2021", str(Path(__file__).with_suffix(".rs")),
    "--extern", f"mhfe={library}", "-L", f"dependency={ROOT / 'target/debug/deps'}",
    "-o", str(binary),
], check=True, cwd=ROOT)
subprocess.run([str(binary)], check=True, cwd=ROOT)
