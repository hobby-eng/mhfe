#!/usr/bin/env bash
# AUD-024, adversarial verifier "verify-help-constants", commit b6fca69. Reproduces the candidate
# finding that help texts of the command modules still type library values that AUD-023-ARC007
# asked to derive, and that the guard test every_help_states_the_limits_of_the_constants passes
# when those values drift.
#
# A copy of HEAD (git archive; the working tree is not touched) gets four library constants moved
# to other valid values and one test that prints the rendered helps. The CLI's guard test and the
# printing test are then run on the copy with cargo test (no Argon2 is run).
#
# Exit 0: no rendered help keeps a stale value, or the guard test fails on the drift.
# Exit 1: the guard test passes while a rendered help keeps a stale value (the defect).
# Exit 2: setup or build error.
#
#   CARGO_TARGET_DIR=<audit target> docs/audits/AUD-024-harnesses/verify-help-constants/probe.sh <scratch folder>
set -euo pipefail

scratch="$1"
repo="$(git rev-parse --show-toplevel)"
: "${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR to the shared audit target}"
copy="$scratch/mutant"
rm -rf "$copy"
mkdir -p "$copy"
echo "HEAD: $(git -C "$repo" rev-parse HEAD)"
git -C "$repo" archive --format=tar HEAD | tar -x -C "$copy"

mutate() { # file, old line, new line
  grep -qxF "$2" "$copy/$1" || { echo "setup: line not found in $1: $2"; exit 2; }
  python3 - "$copy/$1" "$2" "$3" <<'PY'
import sys
path, old, new = sys.argv[1:]
text = open(path).read()
assert text.count(old + "\n") == 1, old
open(path, "w").write(text.replace(old + "\n", new + "\n", 1))
PY
  echo "mutated $1: '$2' -> '$3'"
}
mutate src/suite.rs "pub const MAX_PIM: u32 = 1023;" "pub const MAX_PIM: u32 = 1000;"
mutate src/suite.rs "pub const MAX_MEMORY_LEVEL: u32 = 21;" "pub const MAX_MEMORY_LEVEL: u32 = 20;"
mutate src/new_password.rs "pub const DEFAULT_WORDS: usize = 5;" "pub const DEFAULT_WORDS: usize = 6;"
mutate src/repair.rs "pub const RECOMMENDED_REPAIR_WORDS: usize = 4;" "pub const RECOMMENDED_REPAIR_WORDS: usize = 6;"

# One printing test, placed before the guard test in the CLI's test module.
python3 - "$copy/src/bin/mhfe/main.rs" <<'PY'
import sys
path = sys.argv[1]
text = open(path).read()
marker = "    #[test]\n    fn every_help_states_the_limits_of_the_constants() {"
assert text.count(marker) == 1
probe = '''    #[test]
    fn verify_help_constants_print() {
        use clap::CommandFactory;
        let mut cli = Cli::command();
        for name in ["rekey", "repair-words", "encrypt"] {
            for long in [false, true] {
                let command = cli.find_subcommand_mut(name).unwrap();
                let text = if long { command.render_long_help() } else { command.render_help() };
                println!("===== {name} {} =====", if long { "--help" } else { "-h" });
                println!("{text}");
            }
        }
    }

'''
open(path, "w").write(text.replace(marker, probe + marker, 1))
PY

cd "$copy"
set +e
NO_COLOR=1 cargo test --locked --bin mhfe -- --nocapture --test-threads=1 \
  every_help_states_the_limits_of_the_constants verify_help_constants_print \
  > "$scratch/probe-test.out" 2>&1
code=$?
set -e
cat "$scratch/probe-test.out"
echo "cargo test exit code: $code"
[ "$code" -eq 0 ] || { echo "a guard test failed on the drift, or the build failed"; exit 2; }

python3 - "$scratch/probe-test.out" <<'PY'
import re, sys
out = open(sys.argv[1]).read()
flat = " ".join(out.split())
guard = "tests::every_help_states_the_limits_of_the_constants ... ok" in out
print("guard test every_help_states_the_limits_of_the_constants passed on the mutant:", guard)
controls = {
    "derived --pim short help follows MAX_PIM = 1000": r"--pim <N> Pass multiplier, 0 to 1000 \(default 0\)",
    "derived --mem short help follows MAX_MEMORY_LEVEL = 20": r"--mem <LEVEL> Memory level, 0 to 20 \(default 0: 2 GiB\)",
    "derived --new-mem long help follows MAX_MEMORY_LEVEL = 20": r"Memory level of the new container, 0 to 20",
    "derived bits follow DEFAULT_WORDS = 6": r"about 77\.6 bits",
}
for label, pattern in controls.items():
    print(f"control ({label}):", bool(re.search(pattern, flat)))
stale = []
checks = {
    "rekey --new-pim help keeps '0 to 1023' (MAX_PIM is 1000)": r"PIM of the new container, 0 to 1023",
    "rekey --new-mem short help keeps '0 to 21' (MAX_MEMORY_LEVEL is 20)": r"New memory level, 0 to 21",
    "--new-password long help says 'five dice words' beside the bits of six (DEFAULT_WORDS is 6)": r"words: five dice words, about 77\.6 bits",
    "repair-words example keeps 'Four repair words, the recommended number' (RECOMMENDED_REPAIR_WORDS is 6)": r"Four repair words, the recommended number",
}
for label, pattern in checks.items():
    if re.search(pattern, flat):
        stale.append(label)
        print(f"STALE: {label}")
print(f"{len(stale)} stale help texts")
sys.exit(1 if guard and stale else 0)
PY
