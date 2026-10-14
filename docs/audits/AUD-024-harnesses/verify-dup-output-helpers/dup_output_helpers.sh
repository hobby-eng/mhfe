#!/usr/bin/env bash
# AUD-024, verifier of the candidate "two output helpers exist twice". Reads the source of COMMIT
# (default b6fca69) with git show, so the working tree does not matter, and checks five parts:
#   D1 style::fact (through fact_as) and style::fact_wrapped run the same three statements;
#   D2 the AUD-023 fix 253ca3c gave fact_as the wrap and left fact_wrapped as it was;
#   D3 fact_wrapped's doc still presents it as the wrapping variant of fact;
#   D4 src/bin/mhfe has two `fn write_control(sequence: &str)`, the private-screen one discarding
#      both io errors with `let _`, while its parent module terminal.rs calls choice::write_control;
#   D5 neither copy carries a "deliberate copy" marker (CORE-10).
# Prints DEFECT REPRODUCED and exits 1 while every part is present; DEFECT NOT REPRODUCED, exit 0,
# otherwise. Run from the repository root.
set -u
commit="${COMMIT:-b6fca69238344dd2525b06270ee6ff3b055e68c1}"
src() { git show "$commit:$1"; }
present=0; total=0
part() { total=$((total + 1)); if eval "$2"; then echo "PRESENT: $1"; present=$((present + 1)); else echo "ABSENT: $1"; fi; }
style="$(src src/bin/mhfe/style.rs)"
choice="$(src src/bin/mhfe/choice.rs)"
screen="$(src src/bin/mhfe/terminal/private_screen.rs)"
terminal="$(src src/bin/mhfe/terminal.rs)"
echo "commit $commit"
echo "== style.rs 108-121, 142-152"; printf '%s\n' "$style" | nl -ba | sed -n '108,121p;142,152p'
echo "== choice.rs 432-438"; printf '%s\n' "$choice" | nl -ba | sed -n '432,438p'
echo "== private_screen.rs 79-84, 102-107, 160-204"; printf '%s\n' "$screen" | nl -ba | sed -n '79,84p;102,107p;160,204p'
echo "== terminal.rs uses of choice::write_control"; printf '%s\n' "$terminal" | grep -n '^use crate::choice\|choice::write_control'
echo "== call sites of style::fact_wrapped"
git grep -n 'style::fact_wrapped(' "$commit" -- src/bin/mhfe | sed "s/^$commit://"
norm_as="$(printf '%s\n' "$style" | sed -n '/^pub fn fact_as/,/^}/p' | grep -v '^\s*//' | tr -d ' \n' \
  | sed 's/^pubfnfact_as(kind:Kind,label:&str,value:implDisplay){//; s/&value.to_string()/VALUE/; s/flow::keep(kind,/flow::keep(KIND,/')"
norm_wr="$(printf '%s\n' "$style" | sed -n '/^pub fn fact_wrapped/,/^}/p' | tr -d ' \n' \
  | sed 's/^pubfnfact_wrapped(label:&str,value:&str){//; s/fact_lines(label,value)/fact_lines(label,VALUE)/; s/flow::keep(Kind::Fact,/flow::keep(KIND,/')"
echo "fact_as, normalised:      $norm_as"
echo "fact_wrapped, normalised: $norm_wr"
part "D1 fact (fact_as with Kind::Fact) and fact_wrapped run the same statements" \
  '[ -n "$norm_as" ] && [ "$norm_as" = "$norm_wr" ] && printf "%s\n" "$style" | grep -q "^    fact_as(Kind::Fact, label, value);"'
before="$(git show 253ca3c^:src/bin/mhfe/style.rs | sed -n '/^pub fn fact_wrapped/,/^}/p')"
after="$(printf '%s\n' "$style" | sed -n '/^pub fn fact_wrapped/,/^}/p')"
part "D2 253ca3c added the wrap to fact_as (AUD-023-UI007) and left fact_wrapped unchanged" \
  'git show 253ca3c -- src/bin/mhfe/style.rs | grep -q "^+    // Wrapped under its column, so that a long value never passes the text width (AUD-023-UI007)." && [ "$before" = "$after" ]'
part "D3 fact_wrapped doc: \"[\`fact\`] for a value that may be longer than a line: wrapped\"" \
  'printf "%s\n" "$style" | grep -q "^/// \[\`fact\`\] for a value that may be longer than a line: wrapped"'
part "D4 two write_control, the private-screen copy discarding its io errors; terminal.rs calls choice's" \
  '[ "$(printf "%s\n%s\n" "$choice" "$screen" | grep -c "fn write_control(sequence: &str)")" -eq 2 ] && [ "$(printf "%s\n" "$screen" | sed -n "/^fn write_control/,/^}/p" | grep -c "let _ = terminal")" -eq 2 ] && printf "%s\n" "$terminal" | grep -q "choice::write_control("'
part "D5 no \"deliberate copy\" marker in private_screen.rs, choice.rs or style.rs" \
  '! printf "%s\n%s\n%s\n" "$screen" "$choice" "$style" | grep -qi "deliberate copy"'
echo "$present of $total parts present"
if [ "$present" -eq "$total" ]; then echo "DEFECT REPRODUCED"; exit 1; fi
echo "DEFECT NOT REPRODUCED"; exit 0
