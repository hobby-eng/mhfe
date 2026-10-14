#!/usr/bin/env python3
"""AUD-024 verifier harness verify-selfcheck-answers, reviewed commit b6fca69.

Four faults, each applied alone to a scratch copy of the crate, in library answers the front ends
show: the 16-bit evidence of a rehearsal check, the list of the phrase's own checks that passed,
the old-container keep list of a rekey and the rehearsal reference of a rekey's replacement. For
each, the startup self-check of every set and the known-answer tests of the part are run; a fault
"survives" when they all pass. The unit test that covers the answer is run as a control and must
fail, which shows that the fault is real. Exit 1 when any fault survives (or a control passes).

Usage, from the repository root:
    python3 docs/audits/AUD-024-harnesses/verify-selfcheck-answers/run.py [work dir]
CARGO_TARGET_DIR is honoured (default: ../tmp/aud024/target beside the repository).
"""

import os
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path.cwd()
COPIED = ["src", "Cargo.toml", "Cargo.lock", "build.rs", "vendor", "rust-toolchain.toml", "clippy.toml"]
STARTUP = "self_check::sets::tests::every_set_passes_at_startup"

# (name, file, old text, new text, known-answer tests of the part, control unit test)
FAULTS = [
    ("V1 the 16-bit evidence is inverted", "src/rehearsal.rs",
     'other => Some(detection.source_check(other.passphrase().unwrap_or(""))?),',
     'other => Some(!detection.source_check(other.passphrase().unwrap_or(""))?),',
     "rehearsal::known_answers",
     "rehearsal::tests::a_check_lists_the_checks_of_the_phrase_itself"),
    ("V2 the verified reading's built-in check is not listed", "src/rehearsal.rs",
     "(Some(words), _) => passed.push(PassedCheck::BuiltInCheck(words)),",
     "(Some(_), _) => {}",
     "rehearsal::known_answers",
     "rehearsal::tests::the_passed_own_checks_are_listed_in_order"),
    ("V3 the old container is kept without its changed settings", "src/operation.rs",
     "items.extend(changed_settings(old_work));",
     "let _ = old_work;",
     "operation::known_answers",
     "operation::tests::the_old_container_is_kept_with_settings_that_are_not_the_defaults"),
    ("V4 a phrase confirmed by a reference is rehearsed by a fingerprint", "src/rekey.rs",
     "if !self.by_owner {",
     "if !self.by_owner && passphrase.len() == usize::MAX {",
     "rekey::known_answers",
     "rekey::tests::the_replacement_is_rehearsed_with_what_confirms_it"),
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


def cargo_test(work, filters):
    env = dict(os.environ)
    env.setdefault("CARGO_TARGET_DIR", str(REPO.parent / "tmp/aud024/target"))
    command = ["cargo", "test", "--locked", "--manifest-path", str(work / "Cargo.toml"), "--lib",
               "--", *filters, "--test-threads=4"]
    result = subprocess.run(command, env=env, capture_output=True, text=True, check=False)
    output = result.stdout + result.stderr
    tests = [line for line in output.splitlines()
             if line.startswith("test ") and not line.startswith("test result")]
    errors = [line for line in output.splitlines() if line.startswith("error")]
    return result.returncode, tests, errors


def main():
    work = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else (
        REPO.parent / "tmp/aud024/verify-selfcheck-answers/work")
    fresh_copy(work)
    code, tests, errors = cargo_test(work, [STARTUP, "rehearsal::known_answers",
                                            "operation::known_answers", "rekey::known_answers"])
    print(f"unchanged copy: exit {code}, {len(tests)} tests")
    if code != 0 or not tests:
        print("\n".join(errors))
        return 2
    bad = 0
    for name, path, old, new, part, control in FAULTS:
        original = (REPO / path).read_text()
        assert original.count(old) == 1, (name, original.count(old))
        (work / path).write_text(original.replace(old, new))
        code, tests, errors = cargo_test(work, [STARTUP, part])
        survives = code == 0 and bool(tests)
        print(f"{name}: {'SURVIVES' if survives else 'killed'} (exit {code})")
        for line in tests + errors:
            print(f"    {line}")
        control_code, control_tests, _ = cargo_test(work, [control])
        real = control_code != 0
        print(f"    control {control}: {'fails (the fault is real)' if real else 'PASSES'}")
        for line in control_tests:
            print(f"        {line}")
        bad += survives or not real
        (work / path).write_text(original)
    print(f"{bad} of {len(FAULTS)} faults survive the self-checks or have no failing control")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
