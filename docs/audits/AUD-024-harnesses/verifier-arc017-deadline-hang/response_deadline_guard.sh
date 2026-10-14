#!/usr/bin/env bash
# AUD-024 verifier (commit b6fca69): do the two launchers' response-deadline tests fail, within a
# time limit, when the response timeout is lost? Builds scratch copies of the committed tree
# (git archive HEAD) and runs one test in each:
#   - unchanged: scripts/verify-fast-mode-script.py's
#     Server.test_a_client_that_does_not_read_is_dropped_at_the_response_deadline (control);
#   - Python mutant: packaging/mhfe-fast-mode.py answer() with connection.settimeout(None)
#     (the mutation AUD-023-ARC017 names);
#   - Rust mutant: src/bin/mhfe/serve.rs write_until() with stream.set_write_timeout(None), and
#     serve::tests::a_client_that_does_not_read_is_dropped_at_the_response_deadline.
# Usage, from the repository root: <this script> <scratch folder> [limit in seconds, 60]
# Exit 0 when the control passes and both mutants fail within the limit; 1 otherwise.
set -u
scratch="$1"; limit="${2:-60}"
repo="$(pwd)"
status=0
verdict() {  # $1 label, $2 exit code
  case "$2" in
    0) echo "$1: NOT GUARDED (the test passes on the mutant)"; status=1 ;;
    124) echo "$1: NOT GUARDED (the test is still running after ${limit} s)"; status=1 ;;
    *) echo "$1: guarded (the test fails, exit $2)" ;;
  esac
}
rm -rf "$scratch/tree-python" "$scratch/tree-rust"
mkdir -p "$scratch/tree-python" "$scratch/tree-rust"
git -C "$repo" archive HEAD | tar -x -C "$scratch/tree-python"
git -C "$repo" archive HEAD | tar -x -C "$scratch/tree-rust"

# Control: the unchanged Python test passes.
python_test=Server.test_a_client_that_does_not_read_is_dropped_at_the_response_deadline
(cd "$scratch/tree-python" && PYTHONDONTWRITEBYTECODE=1 timeout "$limit" \
  python3 scripts/verify-fast-mode-script.py "$python_test" > control.txt 2>&1)
code=$?
echo "control (unchanged Python test): exit $code"
[ "$code" -eq 0 ] || status=1

# Python mutant.
sed -i 's/^        connection.settimeout(RESPONSE_DEADLINE)$/        connection.settimeout(None)  # MUTANT/' \
  "$scratch/tree-python/packaging/mhfe-fast-mode.py"
grep -q "# MUTANT" "$scratch/tree-python/packaging/mhfe-fast-mode.py" || { echo "Python mutation not applied"; exit 2; }
start=$(date +%s)
(cd "$scratch/tree-python" && PYTHONDONTWRITEBYTECODE=1 timeout "$limit" \
  python3 scripts/verify-fast-mode-script.py "$python_test" > mutant.txt 2>&1)
code=$?
echo "Python mutant ran $(( $(date +%s) - start )) s"
verdict "Python answer() with settimeout(None)" "$code"

# Rust mutant: built first, then the one test is timed.
sed -i 's/^        stream.set_write_timeout(Some(remaining))?;$/        stream.set_write_timeout(None)?; \/\/ MUTANT/' \
  "$scratch/tree-rust/src/bin/mhfe/serve.rs"
grep -q "// MUTANT" "$scratch/tree-rust/src/bin/mhfe/serve.rs" || { echo "Rust mutation not applied"; exit 2; }
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$scratch/target}"
binary=$(cd "$scratch/tree-rust" && cargo test --locked --bin mhfe --no-run --message-format=json 2>/dev/null \
  | python3 -c 'import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if (m.get("reason") == "compiler-artifact" and m.get("profile", {}).get("test")
            and m["target"]["name"] == "mhfe" and "bin" in m["target"]["kind"]):
        print(m["executable"])')
[ -n "$binary" ] || { echo "Rust mutant did not build"; exit 2; }
start=$(date +%s)
timeout "$limit" "$binary" \
  serve::tests::a_client_that_does_not_read_is_dropped_at_the_response_deadline --exact \
  > "$scratch/tree-rust/mutant.txt" 2>&1
code=$?
echo "Rust mutant ran $(( $(date +%s) - start )) s"
verdict "Rust write_until() with set_write_timeout(None)" "$code"
exit "$status"
