"""Audit AUD-024, role gap-1-unapplied-review-rules: checks of the review rules that no gate
enforces, at commit b6fca69. Run from the repository root:

    python3 docs/audits/AUD-024-harnesses/gap-1-unapplied-review-rules/verify_review_rules.py \
        <path to mhfe> [<scratch folder>]

Each check prints PASS or FAIL with what it saw; the script exits 1 when any check fails. No check
runs Argon2: the help screens run no work, and the test-vectors cases stop before their first
vector. Public test data only (the published fixtures in tests/fixtures).
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

BINARY = os.path.abspath(sys.argv[1])
SCRATCH = sys.argv[2] if len(sys.argv) > 2 else None
COMMANDS = ["new", "encrypt", "decrypt", "check", "rekey", "wallets", "repair", "repair-words",
            "password", "self-test", "serve", "test-vectors", "test-benchmark"]
YELLOW_BOLD = "\x1b[1m\x1b[33m"
GREY = "\x1b[90m"
results = []


def check(name, passed, detail):
    results.append(passed)
    print(f"{'PASS' if passed else 'FAIL'}  {name}: {detail}")


def coloured_help(arguments):
    environment = dict(os.environ, CLICOLOR_FORCE="1", COLUMNS="80")
    environment.pop("NO_COLOR", None)
    run = subprocess.run([BINARY, *arguments], capture_output=True, text=True, env=environment)
    return run.stdout + run.stderr


def last_lines(text):
    return [line for line in text.split("\n") if line.strip()]


def helps():
    """CORE-37: every help screen ends with grey notes and the yellow safety line."""
    screens = {f"mhfe {command} {flag}": coloured_help([command, flag])
               for command in COMMANDS for flag in ("-h", "--help")}
    environment = dict(os.environ, CLICOLOR_FORCE="1")
    launcher = subprocess.run([sys.executable, "packaging/mhfe-fast-mode.py", "--help"],
                              capture_output=True, text=True, env=environment)
    screens["packaging/mhfe-fast-mode.py --help"] = launcher.stdout + launcher.stderr
    no_safety = [name for name, text in screens.items()
                 if not last_lines(text)[-1].startswith(YELLOW_BOLD)]
    check("every_help_screen_ends_with_the_yellow_safety_line", not no_safety,
          f"{len(screens) - len(no_safety)} of {len(screens)} screens end with it; without it: "
          + ", ".join(no_safety[:6]) + (" ..." if len(no_safety) > 6 else ""))
    no_notes = []
    for name, text in screens.items():
        lines = [line for line in last_lines(text) if not line.startswith(YELLOW_BOLD)]
        if not lines[-1].startswith(GREY):
            no_notes.append(name)
    check("every_help_screen_has_grey_notes_at_its_end", not no_notes,
          f"without grey notes at the end: {', '.join(no_notes) or 'none'}")


def test_vectors(scratch):
    """test-vectors: an --only that matches nothing, and a vector file that cannot be read."""
    folder = os.path.join(scratch, "only-nothing")
    run = subprocess.run([BINARY, "test-vectors", "--output", folder, "--only", "zero-13"],
                         capture_output=True, text=True)
    check("test_vectors_refuses_an_only_that_matches_no_vector", run.returncode != 0,
          f"exit {run.returncode}; "
          + " ".join(line.strip() for line in run.stderr.splitlines() if "Wrote" in line))
    folder = os.path.join(scratch, "truncated")
    os.makedirs(folder)
    with open("tests/fixtures/suite3-vectors/zero-12.json", "rb") as source:
        head = source.read(200)
    with open(os.path.join(folder, "zero-12.json"), "wb") as target:
        target.write(head)
    run = subprocess.run([BINARY, "test-vectors", "--output", folder, "--only", "negative-cases"],
                         capture_output=True, text=True)
    says_missing = "write that vector first" in " ".join(run.stderr.split())
    check("test_vectors_reports_an_unreadable_vector_as_unreadable", not says_missing,
          f"exit {run.returncode}; a truncated zero-12.json is reported as "
          + ("missing ('write that vector first')" if says_missing else "unreadable"))


def glossary():
    """CORE-17: GLOSSARY.md lists 'expected value' under Known answer as _Avoid_."""
    found = subprocess.run(["git", "grep", "-n", "-i", "-w", "-e", "expected value",
                            "-e", "expected values", "--", "src", "web", "scripts"],
                           capture_output=True, text=True).stdout.split("\n")
    found = [line.split(":")[0] + ":" + line.split(":")[1] for line in found if line]
    check("no_source_says_expected_value_for_a_known_answer", not found,
          f"{len(found)} lines: {', '.join(found)}")


def option_cases():
    """CORE-33: every option family has a terminal-suite case."""
    suite = "\n".join(open(path, encoding="utf-8").read() for path in
                      ["scripts/verify-hidden-input.py"] + sorted(
                          os.path.join("scripts/terminal_suite", name)
                          for name in os.listdir("scripts/terminal_suite") if name.endswith(".py")))
    calls = re.findall(r"\(\(?\"([a-z-]+)\"([^()]*)\)", re.sub(r"\s+", " ", suite))
    ran = {(command, option) for command, rest in calls for option in re.findall(r'"(--[a-z-]+)"', rest)}
    wanted = [("decrypt", "--scan-gap"), ("check", "--scan-gap"), ("rekey", "--scan-gap"),
              ("wallets", "--scan-gap"), ("repair", "--scan-gap"), ("check", "--path"),
              ("password", "--check-word"), ("decrypt", "--repair"), ("rekey", "--repair"),
              ("wallets", "--repair"), ("decrypt", "--passphrase-used"),
              ("rekey", "--passphrase-used"), ("rekey", "--repair-words"),
              ("test-vectors", "--only")]
    missing = [f"{command} {option}" for command, option in wanted if (command, option) not in ran]
    check("every_option_family_has_a_terminal_suite_case", not missing,
          f"no case runs: {', '.join(missing) or 'none'}")


def browser_search_wallet():
    """CORE-33: the real-browser suite runs a searchWallet that finds the word."""
    text = "\n".join(open(os.path.join("scripts/browser-check", name), encoding="utf-8").read()
                     for name in sorted(os.listdir("scripts/browser-check")))
    flat = re.sub(r"\s+", " ", text)
    calls = [match.start() for match in re.finditer(r"\.searchWallet\(", flat)]
    successful = [at for at in calls if "expectRejection(" not in flat[max(0, at - 60):at]]
    check("the_browser_suite_runs_a_search_wallet_that_finds_the_word", bool(successful),
          f"{len(calls)} searchWallet calls, {len(calls) - len(successful)} of them refusals")


def benchmark_engine():
    """CORE-10, CORE-14 and CORE-18: test-benchmark asks the engine which Argon2 code ran."""
    source = open("src/bin/mhfe/test_tools.rs", encoding="utf-8").read()
    copies = [needle for needle in ("is_x86_feature_detected", "4 threads", "\"SHA256SUMS\"",
                                    "about two minutes") if needle in source]
    check("test_tools_takes_its_engine_facts_and_names_from_their_sources", not copies,
          f"typed again in src/bin/mhfe/test_tools.rs: {', '.join(copies) or 'none'}")


def main():
    scratch = tempfile.mkdtemp(prefix="aud024-review-rules-", dir=SCRATCH)
    try:
        helps()
        test_vectors(scratch)
        glossary()
        option_cases()
        browser_search_wallet()
        benchmark_engine()
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    print(f"{sum(results)} of {len(results)} checks pass")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
