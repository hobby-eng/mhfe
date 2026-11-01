"""The private-screen oracle of scripts/verify-hidden-input.py against an output without the secret,
and the Ctrl+C case of its main() run as written, counting how often the typed secret was ever
shown. Only the public zero-12 container and the synthetic password are used; no Argon2 runs."""
import importlib.util
import sys

program, runs = sys.argv[1], int(sys.argv[2])
sys.dont_write_bytecode = True
sys.argv = ["suite", program]
spec = importlib.util.spec_from_file_location(
    "suite", "/home/sergio/Documents/bip_tools/mhfe/scripts/verify-hidden-input.py")
suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite)

silent = suite.ENTER_PRIVATE + b"Container password: " + suite.LEAVE_PRIVATE + b"summary\r\n"
suite.shown_privately("absent secret", silent, suite.SECRET)
print("shown_privately passes an output that never held the secret:", suite.SECRET not in silent)

shown = 0
for _ in range(runs):
    session = suite.Session()
    session.at_password_prompt()
    start = len(session.output)
    session.type(suite.SECRET + suite.CTRL_C)
    session.wait_for(b"Cancelled")
    code, settings = session.close()
    assert code == suite.CANCELLED
    suite.shown_privately("Ctrl+C", session.output, suite.SECRET)
    shown += suite.SECRET in session.output[start:]
print(f"SECRET + Ctrl+C in one write: {runs} runs, every one passed the check; "
      f"the secret was shown in {shown}")
