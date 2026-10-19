"""Execute the actual ordinary PTY password/control group on an admitted CLI binary."""
from pathlib import Path
import sys

if sys.flags.optimize:
    raise SystemExit("Python optimization disables the terminal assertions; run without -O.")

sys.path.insert(0, str(Path.cwd() / "scripts"))
from terminal_suite.passwords import password_input_hides_keys_and_restores_the_terminal

password_input_hides_keys_and_restores_the_terminal()
