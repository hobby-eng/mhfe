#!/usr/bin/env python3
"""AUD-024 harness of the verify-rekey-ka-tests verifier, reviewed commit b6fca69.

Checks, on a scratch copy of the crate (the repository itself is never written), that the rekey
and Argon2 known-answer tests reach the failures they name and that the rekey self-check's
comparison, refusals and second confirmation cannot be disabled with every test still green.

- probes: appends probes/*.rs to the copy and runs them (filter aud024_verify). Each probe prints
  the outcome the existing test accepts and asserts the failure its comment names.
- mutants: three changes to src/rekey/known_answers.rs, each alone; a mutant "survives" when every
  non-ignored test of the crate (library, binary and integration tests) still passes.

Exit 1 when a probe fails or a mutant survives; 0 when the tests reach what they name and every
mutant is killed.

Usage, from the repository root:
    python3 docs/audits/AUD-024-harnesses/verify-rekey-ka-tests/run.py probes|mutants|all [work dir]
CARGO_TARGET_DIR is honoured (default: ../tmp/aud024/target beside the repository).
"""

import os
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path.cwd()
HERE = pathlib.Path(__file__).resolve().parent
COPIED = ["src", "tests", "Cargo.toml", "Cargo.lock", "build.rs", "vendor", "rust-toolchain.toml",
          "clippy.toml", "README.md"]
FILE = "src/rekey/known_answers.rs"

MUTANTS = [
    ("M5 sealed_as's container comparison always true",
     "sealed.container() == to.container,", "true,"),
    ("M6 every rekey refusal passes",
     "expect_refusal(result.map(|_| ()), self.code)",
     'expect_refusal(Err::<(), _>(crate::MhfeError::Cancelled), "CANCELLED")'),
    ("M7 confirmed_again always passes",
     "    fn confirmed_again() -> Result<(), String> {\n",
     "    fn confirmed_again() -> Result<(), String> {\n        if true { return Ok(()); }\n"),
]

PROBES = [
    ("rekey_known_answers.rs", "src/rekey/known_answers.rs"),
    ("engine_known_answers.rs", "src/engine/known_answers.rs"),
]


def fresh_copy(work):
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    for name in COPIED:
        source = REPO / name
        if source.is_dir():
            shutil.copytree(source, work / name)
        else:
            shutil.copy2(source, work / name)
    (work / "scripts").mkdir()
    shutil.copy2(REPO / "scripts/independent-suite3.py", work / "scripts")


def cargo_test(work, targets, filters, nocapture=False):
    env = dict(os.environ)
    env.setdefault("CARGO_TARGET_DIR", str(REPO.parent / "tmp/aud024/target"))
    command = ["cargo", "test", "--locked", "--manifest-path", str(work / "Cargo.toml"), *targets,
               "--", *filters, "--test-threads=4"]
    if nocapture:
        command.append("--nocapture")
    result = subprocess.run(command, env=env, capture_output=True, text=True, check=False)
    output = result.stdout + result.stderr
    keep = [line for line in output.splitlines()
            if line.startswith("test result") or "AUD024" in line or line.startswith("error")
            or "panicked" in line or line.startswith("  left") or line.startswith(" right")
            or "FAILED" in line or line.startswith("     Running")]
    return result.returncode, keep


def probes(work):
    fresh_copy(work)
    for probe, path in PROBES:
        with open(work / path, "a", encoding="utf-8") as target:
            target.write("\n" + (HERE / "probes" / probe).read_text())
    code, lines = cargo_test(work, ["--lib"], ["aud024_verify"], nocapture=True)
    for line in lines:
        print(line)
    print(f"probes: cargo exit {code}")
    return 1 if code else 0


def mutants(work):
    fresh_copy(work)
    original = (REPO / FILE).read_text()
    survivors = 0
    for name, old, new in MUTANTS:
        assert original.count(old) == 1, (name, original.count(old))
        (work / FILE).write_text(original.replace(old, new))
        code, lines = cargo_test(work, ["--lib", "--bins", "--tests"], [])
        results = [line for line in lines if line.startswith("test result")]
        failed = [line for line in lines if "FAILED" in line or line.startswith("error")]
        passed = sum(int(line.split("ok. ")[1].split(" passed")[0])
                     for line in results if "ok. " in line)
        survived = code == 0 and bool(results)
        survivors += survived
        print(f"{name}: {'SURVIVES' if survived else 'killed'} (cargo exit {code}, "
              f"{passed} tests passed in {len(results)} test binaries)")
        for line in results + failed:
            print(f"    {line}")
    (work / FILE).write_text(original)
    print(f"{survivors} of {len(MUTANTS)} mutants survive every non-ignored test of the crate")
    return 1 if survivors else 0


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("probes", "mutants", "all"):
        print(__doc__)
        return 2
    work = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else (
        REPO.parent / "tmp/aud024/verify-rekey-ka-tests/work")
    status = 0
    if sys.argv[1] in ("probes", "all"):
        status |= probes(work / "probes")
    if sys.argv[1] in ("mutants", "all"):
        status |= mutants(work / "mutants")
    return status


if __name__ == "__main__":
    sys.exit(main())
