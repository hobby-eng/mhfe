#!/usr/bin/env python3
"""AUD-018 bounded native remediation probes; only public and synthetic inputs."""

import argparse
import ctypes
import hashlib
import importlib.util
import json
import locale
from pathlib import Path
import re
import subprocess
import sys
import unicodedata

ROOT = Path(__file__).resolve().parents[4]
PREVIOUS = ROOT / "docs/audits/AUD-016-harnesses/native/boundary-probes.py"
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("aud016_native_boundary", PREVIOUS)
boundary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boundary)


def fingerprint(program):
    # Preserve the original reproduction; add a distinct synthetic password in the wrong field.
    boundary.fingerprint_redaction(program)
    synthetic = b"AUD018-private-field-synthetic-password"
    result = subprocess.run(
        [program, "check", "--stdin", "--fingerprint", "--pim", "0"],
        input=boundary.CONTAINER + b"\nAUD018 synthetic password\n" + synthetic + b"\n",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=boundary.limits,
        timeout=boundary.WAIT_SECONDS, cwd=ROOT,
    )
    leaked = synthetic in result.stdout + result.stderr
    print(json.dumps({"case": "fingerprint-password", "exitCode": result.returncode,
                      "syntheticPasswordEmitted": leaked, "stdoutBytes": len(result.stdout),
                      "stderrEscaped": result.stderr.decode(errors="replace")}))
    assert result.returncode == 2 and not leaked and not result.stdout


def unicode_width(program, character, case):
    terminal = boundary.Terminal(program, ["check", "--fingerprint", "--pim", "0"])
    try:
        terminal.until(b"Container, 24 words")
        terminal.send(boundary.CONTAINER + b"\r")
        terminal.until(b"Container password: ")
        began = len(terminal.output)
        terminal.send((character + "a").encode())
        terminal.read()
        terminal.send(b"\x7f")
        terminal.read()
        fragment = bytes(terminal.output[began:])
        columns = [int(value) for value in re.findall(rb"\x1b\[(\d+)G", fragment)]
    finally:
        restored = terminal.finish()
    libc = ctypes.CDLL(None)
    libc.wcwidth.argtypes = [ctypes.c_wchar]
    libc.wcwidth.restype = ctypes.c_int
    width = libc.wcwidth(character)
    expected = len("Container password: ") + width + 1
    observed = columns[-1] if columns else None
    print(json.dumps({"case": case, "codePoint": f"U+{ord(character):04X}",
                      "eastAsianWidth": unicodedata.east_asian_width(character),
                      "hostWcwidth": width, "expectedCursorColumn": expected,
                      "observedCursorColumn": observed, "exitCode": terminal.process.returncode,
                      "terminalRestored": restored,
                      "fragmentEscaped": fragment.decode(errors="replace")}, ensure_ascii=True))
    assert width == 2, "The host does not supply the two-cell width assumed by this probe"
    assert restored and observed == expected


def low_memlock(program):
    # The original quota: below the actual typed-line capacity, above the former tiny probe.
    terminal = boundary.Terminal(
        program, ["encrypt", "--pim", "0", "--new-password", "own", "--repair-words", "0",
                  "--same-length"],
        memlock=4096,
    )
    try:
        terminal.until(b"Original seed phrase: ")
        terminal.send(b"abandon")
        terminal.read()
        status = Path(f"/proc/{terminal.process.pid}/status").read_text()
        vm_locked = int(re.search(r"^VmLck:\s+(\d+) kB$", status, re.M).group(1))
        before = re.sub(rb"\x1b\[[0-9;]*m", b"", bytes(terminal.output))
        # Complete only the public phrase; stop before the first password is accepted.
        terminal.send(boundary.PUBLIC_PHRASE[len(b"abandon"):] + b"\r")
        terminal.until(b"Container password: ")
    finally:
        restored = terminal.finish()
    plain = re.sub(rb"\x1b\[[0-9;]*m", b"", bytes(terminal.output))
    claimed = b"kept in locked memory, out of swap" in before
    warned = b"not locked, may reach swap" in before
    summary_claimed = b"kept in locked memory, out of swap" in plain
    summary_warned = b"not locked, may reach swap" in plain
    actual_warning = b"This answer's memory could not be locked, so it may reach swap." in plain
    print(json.dumps({"case": "low-memlock", "rlimitMemlockBytes": 4096,
                      "claimsSecretsLockedBeforeInput": claimed, "warnsBeforeInput": warned,
                      "claimsSecretsLockedInSummary": summary_claimed,
                      "warnsInSummary": summary_warned,
                      "vmLockedKiBWhileTyping": vm_locked, "actualBufferWarning": actual_warning,
                      "exitCode": terminal.process.returncode, "terminalRestored": restored}))
    # The flow defers its summary until it ends. Test that summary's accuracy, while retaining
    # the separate before-input observation instead of assuming the summary was already visible.
    assert not claimed and not summary_claimed and summary_warned and actual_warning and restored


def cli_options(program):
    required = {"decrypt": ["--passphrase-used"],
                "encrypt": ["--repair-words"], "new": ["--repair-words"],
                "rekey": ["--repair-words", "--passphrase-used", "--confirm"]}
    for command, flags in required.items():
        result = subprocess.run([program, command, "--help"], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, preexec_fn=boundary.limits,
                                timeout=boundary.WAIT_SECONDS, cwd=ROOT)
        output = result.stdout + result.stderr
        present = {flag: flag.encode() in output for flag in flags}
        print(json.dumps({"case": "cli-options", "command": command,
                          "exitCode": result.returncode, "present": present}))
        assert result.returncode == 0 and all(present.values())
    # Invalid public choices must be refused before secret reads or Argon2 allocation.
    for arguments in (["encrypt", "--repair-words", "3"],
                      ["decrypt", "--passphrase-used", "maybe"],
                      ["rekey", "--confirm", "invalid"]):
        result = subprocess.run([program, *arguments], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                preexec_fn=boundary.limits, timeout=boundary.WAIT_SECONDS, cwd=ROOT)
        print(json.dumps({"case": "invalid-public-option", "argv": arguments,
                          "exitCode": result.returncode,
                          "stderrEscaped": result.stderr.decode(errors="replace")}))
        assert result.returncode == 2


def main():
    locale.setlocale(locale.LC_CTYPE, "")
    parser = argparse.ArgumentParser()
    parser.add_argument("case", choices=["fingerprint", "path-controls", "unicode-original",
                                          "unicode-rocket", "low-memlock", "cli-options"])
    parser.add_argument("program", nargs="?", default="target/release/mhfe")
    arguments = parser.parse_args()
    program = str((ROOT / arguments.program).resolve())
    print(json.dumps({"binarySha256": hashlib.sha256(Path(program).read_bytes()).hexdigest(),
                      "reusedHarnessSha256": hashlib.sha256(PREVIOUS.read_bytes()).hexdigest()}))
    cases = {"fingerprint": fingerprint, "path-controls": boundary.path_controls,
             "unicode-original": lambda p: unicode_width(p, "\u754c", "unicode-original"),
             "unicode-rocket": lambda p: unicode_width(p, "\U0001f680", "unicode-rocket"),
             "low-memlock": low_memlock, "cli-options": cli_options}
    cases[arguments.case](program)


if __name__ == "__main__":
    main()
