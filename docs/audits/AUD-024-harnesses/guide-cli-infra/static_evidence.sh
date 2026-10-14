#!/usr/bin/env bash
# AUD-024 (guide-cli-infra): prints, from commit b6fca69 itself (git show), the source lines that
# the static findings of this role cite, with their line numbers, and the computed facts they
# rely on. Read-only. Run from the repository root:
#   bash docs/audits/AUD-024-harnesses/guide-cli-infra/static_evidence.sh
# Exit 1 when every cited defect is present (DEFECT REPRODUCED), 0 when none is.
set -uo pipefail
C=b6fca69238344dd2525b06270ee6ff3b055e68c1
show() { git show "$C:$1" | awk -v from="$2" -v to="$3" -v f="$1" 'NR>=from && NR<=to {printf "%s:%d: %s\n", f, NR, $0}'; }
present=0; total=0
check() { total=$((total+1)); if eval "$2"; then present=$((present+1)); echo "PRESENT: $1"; else echo "ABSENT: $1"; fi; }

echo "== S1 helpers of style.rs that write a line without wrapping it =="
show src/bin/mhfe/style.rs 123 137
show src/bin/mhfe/style.rs 195 203
show src/bin/mhfe/length_choice.rs 80 88
line='Every encrypted phrase has 24 words, so it does not show how long yours is.'
width=$(( 4 + ${#line} ))
echo "visible width of length_choice.rs:82 as style::gives writes it (\"  ✓ \" + text): $width; TEXT_WIDTH: $(git show $C:src/bin/mhfe/style.rs | grep -o 'TEXT_WIDTH: usize = [0-9]*')"
check "S1 a gives line wider than TEXT_WIDTH (78)" "[ $width -gt 78 ]"

echo; echo "== S2 a plan that the repository does not hold =="
git grep -n -e "G10" -e "the plan's" "$C" -- src | sed "s/^$C://"
plan_files=$(git ls-tree -r --name-only "$C" | grep -i -c "self-check-plan\|self_check_plan\|selfcheck-plan" || true)
# Audit records quote the code's own "G10" (the child-test pattern); they define no plan.
plan_text=$(git grep -l -e "G10:" -e "G10 " -e "G10\." "$C" -- '*.md' '*.json' '*.txt' ':!docs/audits' 2>/dev/null | wc -l)
echo "files named as a self-check plan: $plan_files; Markdown, JSON or text files outside docs/audits that mention G10: $plan_text"
check "S2 G10 cited but defined nowhere" "[ $plan_files -eq 0 ] && [ $plan_text -eq 0 ]"

echo; echo "== S3 two copies of two output helpers =="
show src/bin/mhfe/style.rs 108 121
show src/bin/mhfe/style.rs 142 149
show src/bin/mhfe/choice.rs 432 438
show src/bin/mhfe/terminal/private_screen.rs 200 204
check "S3 fact_wrapped has fact's body" "git show $C:src/bin/mhfe/style.rs | sed -n 144,149p | grep -q 'fact_lines(label, value)'"

echo; echo "== S4 values typed again =="
show src/bin/mhfe/settings.rs 213 236
show src/bin/mhfe/settings.rs 336 345
show src/bin/mhfe/terminal/progress.rs 129 137
show src/bin/mhfe/style.rs 512 513
show src/bin/mhfe/main.rs 151 154
show src/bin/mhfe/main.rs 190 193
show src/bin/mhfe/test_tools.rs 270 273
show src/bin/mhfe/test_tools.rs 350 361
show src/bin/mhfe/settings.rs 576 580
show src/bin/mhfe/settings.rs 593 596
check "S4 the round counts typed in the settings summary" "git show $C:src/bin/mhfe/settings.rs | grep -q '\"24 rounds (12 to encrypt, 12 to check)\"'"

echo; echo "== S5 the answer-line refusals, written twice =="
show src/bin/mhfe/terminal.rs 159 185
show src/bin/mhfe/terminal.rs 440 458
show src/bin/mhfe/hidden_input.rs 525 531
check "S5 two limits in two messages" "git show $C:src/bin/mhfe/terminal.rs | grep -q 'LINE_CAPACITY - 1' && git show $C:src/bin/mhfe/hidden_input.rs | grep -q 'longer than {LINE_CAPACITY} bytes'"

echo; echo "== S6 the progress bar's own stages =="
show src/bin/mhfe/encrypt.rs 260 264
show src/bin/mhfe/rekey.rs 419 423
show src/bin/mhfe/self_test.rs 302 312
show src/operation.rs 14 27
show src/bin/mhfe/terminal.rs 615 622
show src/suite.rs 82 90
check "S6 Progress derives the stage from round numbers" "git show $C:src/bin/mhfe/terminal/progress.rs | grep -q '(ENCRYPTION_ROUNDS, round) if round <= ROUNDS => \"Encrypting\"'"

echo; echo "== S7 the settings question re-asks the PIM =="
show src/bin/mhfe/settings.rs 247 300
echo; echo "$present of $total cited defects present"
if [ "$present" -eq "$total" ]; then echo "DEFECT REPRODUCED"; exit 1; fi
if [ "$present" -eq 0 ]; then echo "DEFECT NOT REPRODUCED"; exit 0; fi
echo "PARTLY"; exit 1
