#!/usr/bin/env python3
"""Require the release remapping guard to reject set overriding flags."""

import os
from pathlib import Path
import subprocess


def main():
    root = Path(__file__).resolve().parents[3]
    clean = dict(os.environ)
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
        clean.pop(name, None)
    script = '. packaging/remap-builder-paths.sh; remap_builder_paths "$PWD"'
    cases = [({}, True)]
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
        cases.extend([({name: ""}, False), ({name: "--cfg witness"}, False)])
    mismatches = []
    for additions, expected in cases:
        result = subprocess.run(
            ["bash", "-c", script], cwd=root, env=dict(clean, **additions),
            capture_output=True, text=True, timeout=5,
        )
        if (result.returncode == 0) != expected:
            mismatches.append(list(additions))
    print({"cases": len(cases), "mismatches": mismatches})
    if mismatches:
        raise RuntimeError("Set overriding flags bypass remapping refusal")
    print("PASS: overriding flags are refused even when empty")


if __name__ == "__main__":
    main()
