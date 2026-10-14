"""AUD-024 (guide-cli-infra): can main.rs's test every_result_is_written_through_one_function fail?

The test reads each file of src/bin/mhfe only up to its first "#[cfg(test)]" and looks for
println!/print!. This script exports commit b6fca69 into SCRATCH (git archive), adds one
`println!` to production code after the first "#[cfg(test)]" of four files (style.rs, self_test.rs,
choice.rs, startup.rs), and runs the test with CARGO_TARGET_DIR=TARGET. A guard able to fail must
fail on them. As a control it then adds one `println!` to menu.rs, which the scan does read, and
expects the test to fail.

Usage, from the repository root:
  python3 -B docs/audits/AUD-024-harnesses/guide-cli-infra/stdout_guard_mutation.py SCRATCH TARGET

Exit 1 (DEFECT REPRODUCED) when the test passes with the four writes, 0 when it fails on them.
"""
import os, shutil, subprocess, sys

COMMIT = "b6fca69238344dd2525b06270ee6ff3b055e68c1"
scratch, target = (os.path.abspath(path) for path in sys.argv[1:3])
MUTANTS = [
    ("src/bin/mhfe/style.rs", "fn error_lines(text: &str) -> Vec<String> {"),
    ("src/bin/mhfe/self_test.rs", "fn show_table(rows: &[Row]) {"),
    ("src/bin/mhfe/choice.rs",
     "pub fn draw_entries(entries: &[(&str, &str)], selected: usize) -> usize {"),
    ("src/bin/mhfe/startup.rs", "fn install_panic_hook() {"),
]
CONTROL = ("src/bin/mhfe/menu.rs", "fn draw_header() -> usize {")


def export(folder):
    if os.path.exists(folder):
        shutil.rmtree(folder)
    os.makedirs(folder)
    archive = subprocess.run(
        ["git", "archive", COMMIT, "Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain.toml",
         "clippy.toml", "README.md", "src", "vendor", "tests", "scripts/independent-suite3.py"],
        check=True, capture_output=True).stdout
    subprocess.run(["tar", "-x", "-C", folder], input=archive, check=True)


def mutate(folder, edits):
    for path, signature in edits:
        full = os.path.join(folder, path)
        text = open(full, encoding="utf-8").read()
        assert text.count(signature) == 1, (path, signature)
        text = text.replace(signature, signature + '\n    println!("AUD-024 mutant");')
        open(full, "w", encoding="utf-8").write(text)


def guard_passes(folder):
    env = dict(os.environ, CARGO_TARGET_DIR=target)
    run = subprocess.run(
        ["cargo", "test", "--locked", "--bin", "mhfe", "every_result_is_written_through_one_function"],
        cwd=folder, env=env, capture_output=True, text=True)
    summary = [line for line in run.stdout.splitlines() if line.startswith("test ")]
    print("\n".join(summary))
    return run.returncode == 0


mutant = os.path.join(scratch, "mutant")
export(mutant)
mutate(mutant, MUTANTS)
print("Four writes to standard output outside style::out:", ", ".join(path for path, _ in MUTANTS))
missed = guard_passes(mutant)
print(f"the guard test {'PASSES: it missed them' if missed else 'fails, as it must'}")
control = os.path.join(scratch, "control")
export(control)
mutate(control, [CONTROL])
caught = not guard_passes(control)
print(f"control, one write in {CONTROL[0]}: the guard test {'fails, as it must' if caught else 'PASSES'}")
print("DEFECT REPRODUCED" if missed else "DEFECT NOT REPRODUCED")
sys.exit(1 if missed else 0)
