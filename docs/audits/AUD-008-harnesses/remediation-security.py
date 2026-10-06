#!/usr/bin/env python3
"""Build focused AUD-008 security remediation probes against the current production source."""

import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
HARNESS = Path(__file__).resolve().parent
EVIDENCE = ROOT / "docs/audits/AUD-008-evidence"
SOURCES = (
    "src/bin/mhfe/protect.rs",
    "src/bin/mhfe/new_wallet.rs",
    "src/bin/mhfe/wallets.rs",
    "src/bin/mhfe/hidden_input.rs",
    "src/bin/mhfe/terminal.rs",
    "src/mhfe.rs",
    "src/phrase.rs",
    "src/password.rs",
    "src/memory.rs",
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    # Fail on a changed call path instead of silently checking an unrelated helper.
    new = (ROOT / SOURCES[1]).read_text()
    assert "Ok(mhfe::phrase_from_entropy(&entropy[..])?)" in new
    assert "mnemonic.to_string()" not in new
    wallets = (ROOT / SOURCES[2]).read_text()
    assert "let mut used: Vec<Password> = Vec::new();" in wallets
    assert "used.push(password);" in wallets
    assert "password.as_bytes().to_vec()" not in wallets
    terminal = (ROOT / SOURCES[4]).read_text()
    assert "hidden_input::output_on_error_terminal()" in terminal
    assert "if !terminal::can_show_privately(&input)" in wallets
    assert "if !terminal::can_show_privately(&input)" in new
    hidden = (ROOT / SOURCES[3]).read_text()
    start = hidden.index("    pub fn same_terminal(")
    end = hidden.index("\n    }", start) + len("\n    }")
    same_terminal = hidden[start:end].replace("pub fn", "fn", 1)
    assert "same_terminal(libc::STDOUT_FILENO, libc::STDERR_FILENO)" in hidden

    EVIDENCE.mkdir(exist_ok=True)
    generated = EVIDENCE / "remediation-security-generated.rs"
    binary = EVIDENCE / "remediation-security-probe"
    source = (HARNESS / "remediation-security.rs").read_text()
    source = source.replace("// SOURCE_SAME_TERMINAL", same_terminal)
    generated.write_text(source)
    libraries = {
        name: max((ROOT / "target/debug/deps").glob(f"lib{name}-*.rlib"), key=lambda path: path.stat().st_mtime)
        for name in ("mhfe", "bip39", "zeroize", "libc")
    }
    environment = os.environ.copy()
    environment.update(
        CARGO_HOME=str(ROOT.parent / "workingspace/cargo"),
        RUSTUP_HOME=str(ROOT.parent / "workingspace/rustup"),
    )
    command = [
        str(ROOT.parent / "workingspace/cargo/bin/rustc"),
        "--edition=2021", str(generated), "--crate-name", "aud008_remediation_security",
        "-L", f"dependency={ROOT / 'target/debug/deps'}", "-o", str(binary),
    ]
    for name, path in libraries.items():
        command.extend(["--extern", f"{name}={path}"])
    print(json.dumps({
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "sourceHashes": {name: digest(ROOT / name) for name in SOURCES},
        "harnessHashes": {path.name: digest(path) for path in (Path(__file__), HARNESS / "remediation-security.rs")},
        "linkedLibraries": {name: {"path": str(path), "sha256": digest(path)} for name, path in libraries.items()},
        "compileCommand": command,
    }), flush=True)
    subprocess.run(command, cwd=ROOT, env=environment, check=True)
    for mode in ("formatter", "retention", "terminals", "isolation"):
        result = subprocess.run([str(binary), mode], cwd=ROOT, env=environment, timeout=20)
        if result.returncode:
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
