"""Actual public-input retries and private-screen cancellation, without recovery."""
from pathlib import Path
import sys

if sys.flags.optimize:
    raise SystemExit("Run without -O: these controls require assertions.")
sys.path.insert(0, str(Path.cwd() / "scripts"))
from terminal_suite.line_retry import public_input_refusals_retry_before_any_recovery
from terminal_suite.passwords import password_input_hides_keys_and_restores_the_terminal

public_input_refusals_retry_before_any_recovery()
password_input_hides_keys_and_restores_the_terminal()
