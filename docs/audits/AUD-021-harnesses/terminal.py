"""Run only the terminal controls adjacent to AUD-020-SEC002, using public data."""

import importlib.util
import json
from pathlib import Path
import re
import sys


if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "direct"):
    raise SystemExit("Usage: python3 terminal.py target/debug/mhfe [direct]")
spec = importlib.util.spec_from_file_location("terminal_checks", "scripts/verify-hidden-input.py")
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def direct_generation(kind, pattern):
    """The exact option path from SEC002, cancelled while displaying a synthetic password."""
    vector = json.loads(Path("tests/fixtures/suite3-vectors/zero-24.json").read_text())
    session = checks.Session((
        "encrypt", "--new-password", kind, "--pim", "0", "--mem", "0", "--repair-words", "0",
    ), capped=sys.platform == "linux")
    session.wait_for(b"seed phrase: ")
    start = len(session.output)
    session.answer(vector["inputs"]["phrase"].encode() + b"\r", b"Write it down now")
    match = re.search(pattern, session.output[start:])
    assert match, f"{kind}: generated password was not displayed"
    made = match.group(1)
    session.answer(checks.CTRL_C, b"Cancelled")
    assert session.drain_until_exit(10), f"{kind}: cancellation did not end the command"
    code, settings = session.close()
    assert code == checks.CANCELLED and settings == session.original
    checks.shown_privately(f"explicit {kind}", session.output, made)
    summary = session.output[session.output.rfind(checks.LEAVE_PRIVATE):]
    assert made not in summary, f"{kind}: generated password persisted on the main screen"
    print(f"explicit {kind}: private display, cancelled before Argon2, terminal restored")


if len(sys.argv) == 3:
    for kind, pattern in (
        ("words", rb"\r\n  ([a-z-]+(?: [a-z-]+){4})\r\n"),
        ("check-word", rb"\r\n  ([a-z-]+(?: [a-z-]+){5})\r\n"),
        ("chars", rb"\r\n  ([A-Za-z0-9]{16})\r\n"),
    ):
        direct_generation(kind, pattern)
else:
    checks.check_encrypt_numbered()
    checks.check_made_password()
    checks.check_private_reveals()
