#!/usr/bin/env python3
"""AUD-017 R4 probe: the canonical container runs every check.sh step its comment claims.

    python3 docs/audits/AUD-017-harnesses/r4-build-docs/docker_vs_check.py

packaging/Dockerfile.reproducible says its verified stage runs "the checks of scripts/check.sh
that need neither a terminal, a browser nor Node's packages". The probe lists the check commands
of scripts/check.sh, leaves out those that need a terminal (verify-hidden-input), a browser or
npm packages, and reports each remaining one that the verified stage's RUN does not contain.
Exits 1 when one is missing while the comment is still there.
"""
import re, sys
from pathlib import Path

check = Path("scripts/check.sh").read_text()
docker = Path("packaging/Dockerfile.reproducible").read_text()
claim = "need neither a terminal, a browser nor Node's packages" in " ".join(docker.split())
stage = docker.split("FROM dependencies AS verified", 1)[1].split("ARG RELEASE_VERSION", 1)[0]
stage = " ".join(stage.replace("\\\n", " ").split())

# One key phrase per check.sh step, and whether it needs a terminal, a browser or npm packages.
STEPS = {
    "vendored Argon2 hashes (sha256sum --check)": ("sha256sum --check --quiet", False),
    "third-party-licenses.py --check": ("third-party-licenses.py --check", False),
    "generate-published-rounds.py --check": ("generate-published-rounds.py --check", False),
    "cargo fmt --check": ("cargo fmt", False),
    "verify-no-copies.mjs": ("verify-no-copies.mjs", False),
    "clippy --all-features (native)": ("--all-targets --all-features -- -D warnings", False),
    "clippy wasm32 --features wasm": ("--target wasm32-unknown-unknown --features wasm", False),
    "clippy wasm32 per browser module": ("--no-default-features", False),
    "cargo test": ("cargo test --locked", False),
    "cargo doc -D warnings": ("cargo doc", False),
    "verify-hidden-input.py": ("verify-hidden-input.py", True),
    "build-wasm.sh": ("scripts/build-wasm.sh", False),
    "verify-argon2-wasm.mjs": ("verify-argon2-wasm.mjs", False),
    "verify-browser-package.mjs": ("verify-browser-package.mjs", False),
    "verify-cli-browser-parity.mjs": ("verify-cli-browser-parity.mjs", False),
    "verify-fast-mode-script.py": ("verify-fast-mode-script.py", False),
    "check-release-artifacts.sh": ("check-release-artifacts.sh", False),
}
missing = []
for name, (key, excluded) in STEPS.items():
    in_check = key in " ".join(check.replace("\\\n", " ").split())
    in_docker = key in stage
    print(f"{name}: check.sh {in_check}, container {in_docker}, excluded {excluded}")
    if in_check and not in_docker and not excluded:
        missing.append(name)
print(f"comment present: {claim}; steps missing from the container: {missing}")
sys.exit(1 if claim and missing else 0)
