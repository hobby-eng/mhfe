#!/usr/bin/env python3
"""Run bounded AUD-016 baseline phases sequentially, preserving each failure."""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RUNNER = str(Path(__file__).with_name("run.py"))
PHASES = {
    "small": [
        ("no-copies-self-test", ["node", "scripts/verify-no-copies.mjs", "--self-test"]),
        ("no-copies", ["node", "scripts/verify-no-copies.mjs"]),
        ("published-rounds", ["python3", "scripts/generate-published-rounds.py", "--check"]),
        ("third-party-licenses", ["python3", "scripts/third-party-licenses.py", "--check"]),
        ("audit-bindings", ["python3", "docs/audits/AUD-015-harnesses/r5-build-docs/harness_bindings.py"]),
        ("documented-symbols", ["python3", "docs/audits/AUD-015-harnesses/r5-build-docs/documented_symbols.py"]),
        ("fast-mode-script", ["python3", "scripts/verify-fast-mode-script.py"]),
    ],
    "rust": [
        ("rust-format", ["cargo", "fmt", "--check"]),
        ("clippy-native", ["cargo", "clippy", "--offline", "--locked", "--all-targets", "--all-features", "--", "-D", "warnings"]),
        ("clippy-wasm", ["cargo", "clippy", "--offline", "--locked", "--lib", "--target", "wasm32-unknown-unknown", "--features", "wasm", "--", "-D", "warnings"]),
        *[("clippy-" + feature, ["cargo", "clippy", "--offline", "--locked", "--lib", "--target", "wasm32-unknown-unknown", "--no-default-features", "--features", feature, "--", "-D", "warnings"])
          for feature in ("browser-core", "browser-repair", "browser-passwords", "browser-wallet")],
        ("rustdoc", ["env", "RUSTDOCFLAGS=-D warnings", "cargo", "doc", "--offline", "--locked", "--no-deps"]),
        ("build-native", ["bash", "-c", '. packaging/remap-builder-paths.sh\nremap_builder_paths "$PWD"\ncargo build --offline --locked --release -j 1']),
        ("cli-version", ["target/release/mhfe", "--version"]),
        ("cli-terminal", ["python3", "scripts/verify-hidden-input.py", "target/release/mhfe"]),
    ],
    "browser": [
        ("build-wasm", ["bash", "-c", "source ../workingspace/emsdk/emsdk_env.sh\nexport EMCC_CORES=1\nscripts/build-wasm.sh"]),
        ("argon2-wasm", ["node", "scripts/verify-argon2-wasm.mjs"]),
        ("browser-package", ["node", "scripts/verify-browser-package.mjs"]),
        ("cli-browser-parity", ["node", "scripts/verify-cli-browser-parity.mjs", "target/release/mhfe"]),
        ("real-browsers", ["node", "scripts/verify-browsers.mjs"]),
    ],
}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in PHASES:
        sys.exit("Usage: baseline.py small|rust|browser")
    os.chdir(ROOT)
    failures = []
    for label, argv in PHASES[sys.argv[1]]:
        code = subprocess.call([sys.executable, RUNNER, label, *argv])
        if code:
            failures.append(label)
            # Downstream browser evidence requires the newly built package.
            if label == "build-wasm":
                break
    print("Failed checks:", failures, flush=True)
    sys.exit(bool(failures))
