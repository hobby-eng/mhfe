#!/usr/bin/env python3
"""The bounded tail functions executed separately after stopping the broad terminal run."""
import os
import pathlib
import runpy
import sys
repo = pathlib.Path(__file__).resolve().parents[3]
os.chdir(repo)
if len(sys.argv) != 2:
    sys.exit('Usage: terminal_tail.py /absolute/path/to/mhfe')
sys.argv = ['scripts/verify-hidden-input.py', sys.argv[1]]
module = runpy.run_path('scripts/verify-hidden-input.py', run_name='audit_subset')
for name in ['check_password_sizes', 'check_usage_errors_and_help', 'check_script_messages', 'check_quiet_start', 'check_self_test', 'check_damaged_copies']:
    module[name]()
print('Selected remaining terminal checks passed.')
