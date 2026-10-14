#!/usr/bin/env bash
# AUD-024 verifier harness: does the guard test every_result_is_written_through_one_function
# (src/bin/mhfe/main.rs:409-442) fail when production code writes to standard output outside
# style::out? Exports the commit into a scratch tree, applies one mutation at a time, runs the
# guard test, and restores the file. Exits 0 only when the guard fails on every mutation.
#   guard_reach.sh <scratch dir> [commit]   (run from the repository root)
set -uo pipefail
repo="$(pwd)"
scratch="$1"
commit="${2:-b6fca69}"
: "${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR to a scratch target folder}"
rm -rf "$scratch/tree"; mkdir -p "$scratch/tree"
git -C "$repo" archive "$commit" | tar -x -C "$scratch/tree"
cd "$scratch/tree" || exit 2
missed=0
# name|file|line after which the write is added|added line
mutations=(
  "println! in choice.rs draw_entries, after the #[cfg(test)] item at choice.rs:300|src/bin/mhfe/choice.rs|pub fn draw_entries(entries: &[(&str, &str)], selected: usize) -> usize {|    println!(\"PROBE\");"
  "println! in style.rs error_lines, after the #[cfg(test)] item at style.rs:330|src/bin/mhfe/style.rs|fn error_lines(text: &str) -> Vec<String> {|    println!(\"PROBE\");"
  "write_all on io::stdout() in decrypt.rs print_result, a file the guard reads whole|src/bin/mhfe/decrypt.rs|fn print_result(phrase: &RecoveredPhrase, input: &Input) -> Result<(), Failure> {|    let _ = std::io::Write::write_all(&mut std::io::stdout(), b\"PROBE\\n\");"
  "control: println! in menu.rs start loop, before menu.rs's only #[cfg(test)]|src/bin/mhfe/menu.rs|        menu_lines = 0;|        println!(\"PROBE\");"
)
for entry in "${mutations[@]}"; do
  IFS='|' read -r name file anchor added <<< "$entry"
  python3 - "$file" "$anchor" "$added" <<'PY' || { echo "cannot apply: $name"; exit 2; }
import sys
path, anchor, added = sys.argv[1:]
text = open(path).read()
assert text.count(anchor + "\n") == 1, "anchor not unique"
open(path, "w").write(text.replace(anchor + "\n", anchor + "\n" + added + "\n"))
PY
  output="$(cargo test --locked --offline --bin mhfe every_result_is_written_through_one_function 2>&1)"
  if grep -q 'every_result_is_written_through_one_function ... ok' <<< "$output"; then
    echo "MISSED: $name (the guard test passes)"; missed=$((missed + 1))
  elif grep -q 'writes to standard output' <<< "$output"; then
    echo "caught: $name"
  else
    echo "$output" | tail -20; echo "build or test error: $name"; exit 2
  fi
  git -C "$repo" show "$commit:$file" > "$file"
done
echo "mutations the guard missed: $missed"
[ "$missed" -eq 0 ]
