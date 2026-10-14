#!/usr/bin/env python3
"""AUD-024 harness of the guide-lib-wallet reviewer, reviewed commit b6fca69.

Two parts, both on a scratch copy of the crate (the repository itself is never written):

- mutants: seven changes, each applied alone, to library answers the front ends show and to the
  rekey self-check. A mutant "survives" when the startup self-check set and the known-answer tests
  of its part still pass. The library mutants are also run against the unit test that covers them,
  as a control that the change is real. Exit 1 when any mutant survives.
- probes: Rust tests appended to the copy (probes/*.rs) that assert the behaviour the coding guide
  or the code's own documentation asks for. Exit 1 when any probe fails.

Usage, from the repository root:
    python3 docs/audits/AUD-024-harnesses/guide-lib-wallet/run.py mutants|probes|all [work dir]
CARGO_TARGET_DIR is honoured (default: ../tmp/aud024/target beside the repository).
"""

import os
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path.cwd()
HERE = pathlib.Path(__file__).resolve().parent
COPIED = ["src", "Cargo.toml", "Cargo.lock", "build.rs", "vendor", "rust-toolchain.toml", "clippy.toml"]

STARTUP_SET = "self_check::sets::tests::every_set_passes_at_startup"

# (name, file, old text, new text, self-check tests that should notice, control unit test)
MUTANTS = [
    ("M1 wallet-check evidence always a pass", "src/rehearsal.rs",
     'other => Some(detection.source_check(other.passphrase().unwrap_or(""))?),',
     "_ => Some(true),",
     [STARTUP_SET, "rehearsal::known_answers"],
     "rehearsal::tests::a_check_lists_the_checks_of_the_phrase_itself"),
    ("M2 own_checks_passed lists nothing", "src/rehearsal.rs",
     "        let mut passed = Vec::new();\n        match (self.built_in_check",
     "        let mut passed = Vec::new();\n        if passed.is_empty() { return passed; }\n"
     "        match (self.built_in_check",
     [STARTUP_SET, "rehearsal::known_answers"],
     "rehearsal::tests::the_passed_own_checks_are_listed_in_order"),
    ("M3 old container kept without its passwords", "src/operation.rs",
     "let mut items = vec![KeepItem::OldContainer, KeepItem::OldPasswords];",
     "let mut items = vec![KeepItem::OldContainer];",
     [STARTUP_SET, "operation::known_answers"],
     "operation::tests::the_old_container_is_kept_with_settings_that_are_not_the_defaults"),
    ("M4 replacement always rehearsed by a built-in check", "src/rekey.rs",
     "        if self.phrase.verified() {\n            return Ok(ReplacementRehearsal::BuiltInCheck);",
     "        if self.phrase.verified() || passphrase.len() < usize::MAX {\n"
     "            return Ok(ReplacementRehearsal::BuiltInCheck);",
     [STARTUP_SET, "rekey::known_answers"],
     "rekey::tests::the_replacement_is_rehearsed_with_what_confirms_it"),
    ("M5 rekey check's container comparison always true", "src/rekey/known_answers.rs",
     "sealed.container() == to.container,", "true,",
     ["rekey::known_answers"], None),
    ("M6 rekey check's refusals always pass", "src/rekey/known_answers.rs",
     "expect_refusal(result.map(|_| ()), self.code)",
     'expect_refusal(Err::<(), _>(crate::MhfeError::Cancelled), "CANCELLED")',
     ["rekey::known_answers"], None),
    ("M7 rekey check's second confirmation always passes", "src/rekey/known_answers.rs",
     "    fn confirmed_again() -> Result<(), String> {\n",
     "    fn confirmed_again() -> Result<(), String> {\n        if true { return Ok(()); }\n",
     ["rekey::known_answers"], None),
]

# (probe file, file of the crate it is appended to)
PROBES = [
    ("rekey_known_answers.rs", "src/rekey/known_answers.rs"),
    ("engine_known_answers.rs", "src/engine/known_answers.rs"),
    ("self_test.rs", "src/self_test.rs"),
    ("wallet_keys.rs", "src/wallet/keys.rs"),
    ("wallet_encodings.rs", "src/wallet/encodings.rs"),
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
    shutil.copytree(REPO / "tests/fixtures", work / "tests/fixtures")
    (work / "scripts").mkdir()
    shutil.copy2(REPO / "scripts/independent-suite3.py", work / "scripts")


def cargo_test(work, filters, nocapture=False):
    env = dict(os.environ)
    env.setdefault("CARGO_TARGET_DIR", str(REPO.parent / "tmp/aud024/target"))
    command = ["cargo", "test", "--locked", "--manifest-path", str(work / "Cargo.toml"), "--lib",
               "--", *filters, "--test-threads=4"]
    if nocapture:
        command.append("--nocapture")
    result = subprocess.run(command, env=env, capture_output=True, text=True, check=False)
    lines = [line for line in (result.stdout + result.stderr).splitlines()
             if line.startswith("test ") or "AUD024" in line or line.startswith("error")
             or "panicked" in line or line.startswith("  left") or line.startswith(" right")]
    return result.returncode, lines


def mutants(work):
    fresh_copy(work)
    survivors = 0
    for name, path, old, new, notice, control in MUTANTS:
        target = work / path
        original = (REPO / path).read_text()
        assert original.count(old) == 1, (name, original.count(old))
        target.write_text(original.replace(old, new))
        code, lines = cargo_test(work, notice)
        tests = [line for line in lines if line.startswith("test ") and not line.startswith("test result")]
        survived = code == 0 and tests
        survivors += bool(survived)
        print(f"{name}: {'SURVIVES' if survived else 'killed'} ({len(tests)} self-check tests, "
              f"exit {code})")
        for line in tests:
            print(f"    {line}")
        if control:
            code, lines = cargo_test(work, [control])
            print(f"    control {control}: {'fails (mutation is real)' if code else 'passes'}")
        target.write_text(original)
    print(f"{survivors} of {len(MUTANTS)} mutants survive the self-checks")
    return 1 if survivors else 0


def probes(work):
    fresh_copy(work)
    for probe, path in PROBES:
        with open(work / path, "a", encoding="utf-8") as target:
            target.write("\n" + (HERE / "probes" / probe).read_text())
    code, lines = cargo_test(work, ["aud024"], nocapture=True)
    for line in lines:
        print(line)
    failed = sum(1 for line in lines if line.startswith("test ") and line.endswith("FAILED"))
    print(f"{failed} probe(s) fail")
    return 1 if code else 0


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("mutants", "probes", "all"):
        print(__doc__)
        return 2
    work = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else (
        REPO.parent / "tmp/aud024/guide-lib-wallet/harness-work")
    status = 0
    if sys.argv[1] in ("mutants", "all"):
        status |= mutants(work / "mutants")
    if sys.argv[1] in ("probes", "all"):
        status |= probes(work / "probes")
    return status


if __name__ == "__main__":
    sys.exit(main())
