#!/usr/bin/env python3
"""Require refusal diagnostics to withhold supplied synthetic arguments."""

from pathlib import Path
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[3]
    marker = "AUD028_SYNTHETIC_ARGUMENT_DO_NOT_ECHO"
    cases = (["--" + marker], ["public.html", marker])
    failures = []
    for arguments in cases:
        result = subprocess.run(
            [sys.executable, str(root / "packaging/mhfe-fast-mode.py"),
             *arguments], capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 2:
            raise RuntimeError("Argument refusal must exit 2")
        if marker in result.stdout or marker in result.stderr:
            failures.append(arguments)
        print({"exitCode": result.returncode,
               "syntheticArgumentEchoed": marker in result.stderr})
    if failures:
        raise RuntimeError("Refusal diagnostic repeated supplied arguments")
    print("PASS: launcher argument refusals withhold supplied text")


if __name__ == "__main__":
    main()
