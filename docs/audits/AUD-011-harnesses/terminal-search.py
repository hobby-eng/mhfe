"""Rerun search and the previously unreached terminal-check tail on a specified CLI."""

import importlib.util
import sys

assert len(sys.argv) == 2, "Usage: python3 terminal-search.py target/release/mhfe"
spec = importlib.util.spec_from_file_location("terminal_checks", "scripts/verify-hidden-input.py")
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
checks.check_container_search()
checks.check_usage_errors_and_help()
checks.check_script_messages()
checks.check_quiet_start()
checks.check_self_test()
checks.check_damaged_copies()
