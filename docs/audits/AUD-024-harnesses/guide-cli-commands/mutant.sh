#!/usr/bin/env bash
# AUD-024, role guide-cli-commands, commit b6fca69. Mutation probe of the command-line tool's
# help texts and self-test verdicts: a copy of HEAD (git archive, the working tree is not touched)
# gets library constants and two self-check ids changed, plus two printing tests; the CLI's own
# guard tests are then run on it. The probe exits 0 only when every typed copy follows its
# constant or a guard test fails on the drift; it exits 1 when a rendered help keeps a stale
# value while the guards stay green (the defect), and 2 on a setup error.
#
#   docs/audits/AUD-024-harnesses/guide-cli-commands/mutant.sh <scratch folder>
set -euo pipefail

scratch="$1"
repo="$(git rev-parse --show-toplevel)"
target="${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR to the shared audit target}"
copy="$scratch/mutant"
rm -rf "$copy"
mkdir -p "$copy"
git -C "$repo" archive --format=tar HEAD | tar -x -C "$copy"

# The mutations: each constant moves to another valid value.
sed -i 's/^pub const MAX_PIM: u32 = 1023;/pub const MAX_PIM: u32 = 1000;/' "$copy/src/suite.rs"
sed -i 's/^pub const MAX_MEMORY_LEVEL: u32 = 21;/pub const MAX_MEMORY_LEVEL: u32 = 20;/' "$copy/src/suite.rs"
sed -i 's/^pub const DEFAULT_WORDS: usize = 5;/pub const DEFAULT_WORDS: usize = 6;/' "$copy/src/new_password.rs"
sed -i 's/^pub const RECOMMENDED_REPAIR_WORDS: usize = 4;/pub const RECOMMENDED_REPAIR_WORDS: usize = 6;/' "$copy/src/repair.rs"
sed -i 's/^        "random-source"$/        "random-health"/' "$copy/src/random/health.rs"
sed -i 's/^        "memory-locking"$/        "memory-lock"/' "$copy/src/memory.rs"
for check in "MAX_PIM: u32 = 1000" "MAX_MEMORY_LEVEL: u32 = 20"; do
  grep -q "$check" "$copy/src/suite.rs" || { echo "mutation missing: $check"; exit 2; }
done
grep -q "DEFAULT_WORDS: usize = 6" "$copy/src/new_password.rs" || { echo "mutation missing"; exit 2; }
grep -q "RECOMMENDED_REPAIR_WORDS: usize = 6" "$copy/src/repair.rs" || { echo "mutation missing"; exit 2; }
grep -q '"random-health"' "$copy/src/random/health.rs" || { echo "mutation missing"; exit 2; }
grep -q '"memory-lock"' "$copy/src/memory.rs" || { echo "mutation missing"; exit 2; }

# Two printing tests: the rendered helps, and the self-test verdict of every part's id.
python3 - "$copy/src/bin/mhfe/main.rs" "$copy/src/bin/mhfe/self_test.rs" <<'PY'
import sys
main, self_test = sys.argv[1:]
text = open(main).read()
marker = "    /// Every command that reads a secret checks every part first"
assert marker in text
text = text.replace(marker, '''    #[test]
    fn aud024_print_helps() {
        use clap::CommandFactory;
        let mut cli = Cli::command();
        for (name, long) in [("rekey", false), ("rekey", true), ("encrypt", true),
                             ("repair-words", false), ("password", false)] {
            let command = cli.find_subcommand_mut(name).unwrap();
            let text = if long { command.render_long_help() } else { command.render_help() };
            println!("===== {name} {} =====", if long { "--help" } else { "-h" });
            println!("{text}");
        }
    }

''' + marker, 1)
open(main, "w").write(text)
text = open(self_test).read()
marker = "    #[test]\n    fn each_outcome_reads_as_its_kind() {"
assert marker in text
text = text.replace(marker, '''    #[test]
    fn aud024_print_verdicts() {
        for id in startup::every_part(None).ids() {
            let (passed, failed) = verdicts(id);
            println!("verdict {id}: {passed} / {failed}");
        }
    }

''' + marker, 1)
open(self_test, "w").write(text)
PY

cd "$copy"
set +e
cargo test --locked --bin mhfe -- --nocapture --test-threads=1 \
  every_help_states_the_limits_of_the_constants each_outcome_reads_as_its_kind \
  chars_alone_means_the_default aud024_print_helps aud024_print_verdicts > "$scratch/mutant-test.out" 2>&1
code=$?
set -e
cat "$scratch/mutant-test.out"
echo "cargo test exit code: $code"
[ "$code" -eq 0 ] || { echo "a guard test failed on the drift, or the build failed"; exit 2; }

python3 - "$scratch/mutant-test.out" <<'PY'
import re, sys
out = open(sys.argv[1]).read()
flat = " ".join(out.split())
stale = []
def stale_if(label, pattern):
    if re.search(pattern, flat):
        stale.append(label)
        print(f"STALE: {label}: /{pattern}/")
stale_if("rekey --new-pim short help keeps 0 to 1023 (MAX_PIM is 1000)", r"PIM of the new container, 0 to 1023")
stale_if("rekey --new-mem short help keeps 0 to 21 (MAX_MEMORY_LEVEL is 20)", r"New memory level, 0 to 21")
stale_if("--new-password help: 'five dice words' beside the bits of six (DEFAULT_WORDS is 6)", r"words: five dice words, about (?!64\.6 )\d+(\.\d)? bits")
stale_if("repair-words example keeps four as the recommended number (RECOMMENDED_REPAIR_WORDS is 6)", r"Four repair words, the recommended number")
stale_if("self-test verdict of the renamed random-source check falls back to 'as published'", r"verdict random-health: as published / NOT as published")
stale_if("self-test verdict of the renamed memory-locking check falls back to 'as published'", r"verdict memory-lock: as published / NOT as published")
for guard in ("every_help_states_the_limits_of_the_constants", "each_outcome_reads_as_its_kind"):
    if f"tests::{guard} ... ok" in out:
        print(f"GUARD PASSED ON THE MUTANT: {guard}")
derived = re.search(r"Pass multiplier, 0 to 1000", flat)
print("the derived --pim help follows MAX_PIM:", bool(derived))
sys.exit(1 if stale else 0)
PY
