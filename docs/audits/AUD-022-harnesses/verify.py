#!/usr/bin/env python3
"""Rerun bounded public-data native/launcher/terminal checks; no release/full-cost suite."""
import os
import pathlib
import subprocess
import sys
repo = pathlib.Path(__file__).resolve().parents[3]
env = os.environ.copy()
if not env.get('CARGO_HOME') or not env.get('RUSTUP_HOME') or not env.get('CARGO_TARGET_DIR'):
    sys.exit('Set the documented workspace CARGO_HOME, RUSTUP_HOME and external CARGO_TARGET_DIR.')
cargo = pathlib.Path(env['CARGO_HOME']) / 'bin/cargo'
commands = [
    [str(cargo), '+1.99.0', 'test', '--offline', '--locked', '--lib'],
    [str(cargo), '+1.99.0', 'test', '--offline', '--locked', '--bin', 'mhfe'],
    [str(cargo), '+1.99.0', 'check', '--offline', '--locked', '--lib', '--target', 'wasm32-unknown-unknown', '--features', 'wasm'],
    [str(cargo), '+1.99.0', 'build', '--offline', '--locked', '--bin', 'mhfe'],
    [sys.executable, 'scripts/verify-fast-mode-script.py', 'Routing', 'ChecksumFile'],
]
for command in commands:
    subprocess.run(command, cwd=repo, env=env, check=True)
