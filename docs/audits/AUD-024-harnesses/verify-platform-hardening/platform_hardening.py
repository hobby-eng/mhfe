#!/usr/bin/env python3
"""AUD-024 static trace: which process and memory protections the Windows and macOS release
builds of mhfe compile, and whether each has the platform equivalent that the coding guide's
RUST-09 and RUST-13 ask for. Run from the repository root. Exits 1 while an equivalent is missing,
0 once each is present. Reads files only; builds and runs nothing but `rustc --print cfg`.
"""

import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path.cwd()
TARGETS = ["x86_64-pc-windows-gnu", "x86_64-apple-darwin", "aarch64-apple-darwin"]


def lines_of(path):
    return (ROOT / path).read_text(encoding="utf-8").splitlines()


def show(path, pattern, after=0):
    """Prints every line of `path` that matches `pattern`, with `after` following lines."""
    text = lines_of(path)
    found = False
    for number, line in enumerate(text, 1):
        if re.search(pattern, line):
            found = True
            for offset in range(after + 1):
                if number - 1 + offset < len(text):
                    print(f"  {path}:{number + offset}: {text[number - 1 + offset].rstrip()}")
    if not found:
        print(f"  {path}: no line matches {pattern!r}")


def target_cfg():
    rustc = shutil.which("rustc")
    if rustc is None:
        print("rustc not on PATH: target cfg not printed")
        return
    for target in TARGETS:
        result = subprocess.run([rustc, "--print", "cfg", "--target", target],
                                capture_output=True, text=True, check=False)
        keys = [line for line in result.stdout.splitlines()
                if line in ("unix", "windows") or line.startswith(("target_os=", "target_family="))]
        print(f"  {target}: {' '.join(keys) or result.stderr.strip()}")


def sources():
    files = sorted(ROOT.glob("src/**/*.rs")) + [ROOT / "Cargo.toml", ROOT / "build.rs"]
    files += sorted(ROOT.glob("scripts/*.sh")) + sorted(ROOT.glob(".github/workflows/*.yml"))
    return {f.relative_to(ROOT).as_posix(): f.read_text(encoding="utf-8", errors="replace")
            for f in files if f.is_file()}


def hits(texts, pattern):
    return [(name, number, line.strip()) for name, text in texts.items()
            for number, line in enumerate(text.splitlines(), 1) if re.search(pattern, line)]


def main():
    print("cfg of the release targets (rustc --print cfg):")
    target_cfg()

    print("\nWhat a build that is not Unix compiles for page locking (src/engine/ffi.rs):")
    show("src/engine/ffi.rs", r"^#\[cfg\(not\(unix\)\)\]", after=3)
    print("\nThe memory-locking check off Unix (src/memory.rs):")
    show("src/memory.rs", r"if !cfg!\(unix\)", after=4)
    print("\nharden_process, the whole of its body (src/bin/mhfe/protect.rs):")
    text = lines_of("src/bin/mhfe/protect.rs")
    start = next(i for i, line in enumerate(text)
                 if re.match(r"pub(?:\([^)]*\))? fn harden_process\b", line))
    end = next(i for i in range(start, len(text)) if text[i] == "}")
    for number in range(start, end + 1):
        print(f"  src/bin/mhfe/protect.rs:{number + 1}: {text[number]}")
    print("\nThe core-dumps check where no RLIMIT_CORE exists (src/bin/mhfe/protect.rs):")
    show("src/bin/mhfe/protect.rs", r"^const NO_CORE_DUMP_SETTING", after=4)
    print("\nwindows-sys features (Cargo.toml):")
    show("Cargo.toml", r"^windows-sys", after=4)

    texts = sources()
    checks = [
        ("RUST-13", "Windows: secret pages locked with VirtualLock",
         r"\bVirtualLock\b"),
        ("RUST-09", "Windows: crash dumps of the process or its secrets excluded from Windows "
         "Error Reporting", r"\bWer(RegisterExcludedMemoryBlock|AddExcludedApplication)\b"
         r"|SetErrorMode\([^\n]*SEM_NOGPFAULTERRORBOX"),
        ("RUST-09", "Windows: other processes of the user denied reading the process memory "
         "(process DACL)", r"\b(SetSecurityInfo|SetKernelObjectSecurity)\b"),
        ("RUST-09", "macOS: debugger attachment denied (ptrace PT_DENY_ATTACH, or the hardened "
         "runtime when the binary is signed)",
         r"\bPT_DENY_ATTACH\b|codesign[^\n]*(--options[ =]runtime|-o runtime)"),
    ]
    print("\nPlatform equivalents searched in src/, Cargo.toml, build.rs, scripts/*.sh and the "
          "workflows:")
    failed = 0
    for rule, what, pattern in checks:
        found = hits(texts, pattern)
        if found:
            print(f"  present  {rule}  {what}")
            for name, number, line in found[:5]:
                print(f"           {name}:{number}: {line}")
        else:
            failed += 1
            print(f"  MISSING  {rule}  {what}  (pattern {pattern!r}: no match)")
    if failed:
        print(f"\nFAIL: {failed} platform equivalent(s) of RUST-09/RUST-13 missing in the Windows "
              "or macOS build")
        return 1
    print("\nPASS: each platform equivalent is present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
