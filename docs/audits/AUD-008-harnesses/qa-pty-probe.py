#!/usr/bin/env python3
"""Probe terminal fallback and explicit rekey length guards without entering Argon2."""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/audits/AUD-008-evidence"
PROGRAM = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "target/release/mhfe").resolve()
spec = importlib.util.spec_from_file_location(
    "mhfe_public_pty", ROOT / "scripts/verify-hidden-input.py"
)
pty = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pty)
pty.PROGRAM = str(PROGRAM)
records = []
failures = []


def retain(label, session, code, expected, observed):
    record = {
        "label": label,
        "arguments": session.process.args,
        "expected": expected,
        "observed": observed,
        "exitCode": code,
        "publicTranscript": session.output.decode(errors="replace"),
    }
    records.append(record)
    if expected != observed:
        failures.append(label)
    print(json.dumps({key: value for key, value in record.items() if key != "publicTranscript"}))


def fallback():
    session = pty.Session(term="dumb")
    try:
        session.wait_for(b"original: ")
        session.answer(pty.CONTAINER.encode() + b"\r", b"Container password (hidden): ")
        after_prompt = len(session.output)
        session.answer(b"synthetic\tx\r", b"again")
        secret_absent = b"synthetic" not in session.output[after_prompt:]
    finally:
        code, restored = session.close()
    observed = (
        secret_absent
        and pty.ENTER_PRIVATE not in session.output
        and restored == session.original
    )
    retain(
        "TERM=dumb rejects a control without echo and restores settings",
        session,
        code,
        True,
        observed,
    )


def rekey(fixture, words, should_accept):
    vector = json.loads((ROOT / "tests/fixtures" / fixture).read_text())
    arguments = ("rekey", "--pim", "0")
    if words is not None:
        arguments += ("--words", str(words))
    session = pty.Session(arguments, term="xterm-256color")
    try:
        session.wait_for(b"backed up another way?")
        session.answer(b"1", b"original: ")
        session.type(vector["container"].encode() + b"\r")
        # No password is typed: reaching its prompt proves only option dispatch, never a KDF.
        marker = session.wait_for(b"Old container password: ", "✗ Error:".encode())
        accepted = marker == b"Old container password: "
    finally:
        code, restored = session.close()
    assert restored == session.original, "rekey did not restore terminal settings"
    label = f"{vector['name']}: --words {words}"
    retain(label, session, code, should_accept, accepted)


fallback()
for words, should_accept in ((None, True), (12, True), (13, False), (15, False), (24, False)):
    rekey("suite4-vectors/same-length-zero-12.json", words, should_accept)
for length in (15, 18, 21):
    rekey(f"suite4-vectors/same-length-zero-{length}.json", 12, False)
rekey("suite3-vectors/zero-12.json", 13, False)
manifest_paths = [
    "scripts/verify-hidden-input.py",
    "src/bin/mhfe/terminal.rs",
    "src/bin/mhfe/rekey.rs",
    "src/rehearsal.rs",
    "src/mhfe.rs",
]
summary = {
    "checkId": "CHECK-BLD-002",
    "binary": str(PROGRAM),
    "binarySha256": hashlib.sha256(PROGRAM.read_bytes()).hexdigest(),
    "sourceSha256": {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in manifest_paths
    },
    "cases": records,
    "failures": failures,
    "argon2Calls": 0,
    "outcome": "failed" if failures else "passed",
}
(EVIDENCE / "qa-pty-probe.json").write_text(json.dumps(summary, indent=2) + "\n")
raise SystemExit(bool(failures))
