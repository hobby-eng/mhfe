#!/usr/bin/env bash
# AUD-024, role gap-1 (commit b6fca69): can the startup budget test, which AUD-023-DOC002's fix
# says makes "a fixed wait such as the one AUD-023-DOC002 found" fail, catch that wait? Builds a
# copy of the commit in which compare_candidates (src/search.rs) sleeps a progress interval before
# it looks whether its workers ended, as it did before 253ca3c, then runs
# self_check::sets::tests::the_startup_set_stays_within_its_budget once in a debug build (as
# `cargo test --locked` in the gates runs it) and RUNS times in a release build.
#
#   docs/audits/AUD-024-harnesses/gap-1-aud023-required-verification-and-remediation-diff/doc002_budget_guard.sh \
#     <scratch folder> <cargo target folder of its own> [commit] [runs]
#
# The target folder must not be shared with builds of the real tree: cargo names the artifacts of
# two copies of the same package alike and reuses them across copies. Exit 0 when the test fails
# on the mutant in the debug run and in every release run; 1 otherwise; 2 on a setup error.
set -euo pipefail
scratch="$1"; target="$2"; commit="${3:-b6fca69}"; runs="${4:-10}"
tree="$scratch/doc002-mutant"
rm -rf "$tree"; mkdir -p "$tree"
git archive "$commit" | tar -x -C "$tree"
python3 - "$tree/src/search.rs" <<'PY' || exit 2
import sys
path = sys.argv[1]
text = open(path).read()
start = text.index("        let interval = Duration::from_millis(PROGRESS_INTERVAL_MS);\n        loop {")
end = text.index("    });\n    if let Some(error) = failure.into_inner()", start)
loop = """        // MUTANT (AUD-024): the wait loop before 253ca3c, which sleeps first.
        let workers_done = || *finished.lock().unwrap_or_else(|e| e.into_inner()) >= workers;
        while !workers_done() {
            std::thread::sleep(Duration::from_millis(PROGRESS_INTERVAL_MS));
            if abort.load(Ordering::Relaxed) {
                continue;
            }
            if let Err(error) = on_progress(done.load(Ordering::Relaxed).min(count), count) {
                abort_with(error);
            }
        }
"""
text = text[:start] + loop + text[end:]
text = text.replace("    let all_finished = Condvar::new();\n",
                    "    let all_finished = Condvar::new();\n    let _ = &all_finished;\n", 1)
open(path, "w").write(text)
PY
cd "$tree"
export CARGO_TARGET_DIR="$target"
test_name=the_startup_set_stays_within_its_budget
caught=yes
if cargo test --locked --lib "$test_name" > "$scratch/doc002-debug.txt" 2>&1; then
  echo "debug build (the gates): the test PASSES with the restored wait"; caught=no
else
  echo "debug build (the gates): the test fails with the restored wait"
fi
cargo test --release --locked --lib "$test_name" --no-run > /dev/null 2>&1
passed=0
for run in $(seq 1 "$runs"); do
  if out="$(cargo test --release --locked --lib "$test_name" -- --nocapture 2>&1)"; then
    result=PASSES; passed=$((passed + 1))
  else
    result=fails
  fi
  echo "release run $run: $(grep -E '^(container-search|startup set)' <<<"$out" | tr -s ' ' | tr '\n' ';') $result"
done
echo "release runs in which the test passes with the restored wait: $passed of $runs"
[ "$passed" -gt 0 ] && caught=no
if [ "$caught" = yes ]; then echo "GUARDED: the budget test catches the wait"; exit 0; fi
echo "NOT GUARDED: the budget test lets the AUD-023-DOC002 wait through"; exit 1
