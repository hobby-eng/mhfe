#!/usr/bin/env bash
# AUD-024 verifier harness: facts the command-line tool works out again instead of asking the
# library. See README.md. Exits 1 when the defect is present, 0 when it is not, 2 on a usage or
# build error. Run from the repository root.
set -uo pipefail

C="${1:-b6fca69238344dd2525b06270ee6ff3b055e68c1}"
work="${2:-${TMPDIR:-/tmp}/aud024-verify-cli-derived-facts}"
mkdir -p "$work" || exit 2
show() { git show "$C:$1"; }
present=0
total=0
check() {
    total=$((total + 1))
    if eval "$2"; then
        present=$((present + 1))
        echo "PRESENT: $1"
    else
        echo "ABSENT:  $1"
    fi
}

echo "== Part 1: the progress bar's stage names =="
# The library's constants, read from their sources at the commit.
rounds="$(show src/suite.rs | sed -n 's/^pub const ROUNDS: u32 = \([0-9]*\);$/\1/p')"
show src/mhfe.rs | grep -q '^pub const ENCRYPTION_ROUNDS: u32 = 2 \* ROUNDS;$' || {
    echo "ENCRYPTION_ROUNDS is no longer 2 * ROUNDS"
    exit 2
}
[ -n "$rounds" ] || { echo "no ROUNDS in src/suite.rs"; exit 2; }
# The bar's own stage function, verbatim from the commit.
stage_fn="$(show src/bin/mhfe/terminal/progress.rs | awk '/^fn stage\(/{p=1} p{print} p&&/^}$/{exit}')"
[ -n "$stage_fn" ] || { echo "no fn stage in progress.rs"; exit 2; }
cat > "$work/probe.rs" <<EOF
#![allow(dead_code)]
const ROUNDS: u32 = $rounds;
const ENCRYPTION_ROUNDS: u32 = 2 * ROUNDS;

$stage_fn

/// The bar's name for each of the library's stages.
fn bar_name(stage: &str) -> &'static str {
    match stage {
        "Encrypt" => "Encrypting",
        "Check" => "Checking",
        _ => "Recovering",
    }
}

/// Feeds the rounds exactly as the library reports them to the bar's stage function, without
/// any renumbering by the caller, and counts the rounds whose bar name differs from the stage
/// the library reported.
fn replay(name: &str, reports: &[(&str, u32, u32)]) -> usize {
    let mut wrong = 0;
    for &(library, round, rounds) in reports {
        let bar = stage(round, rounds, "Recovering");
        if bar != bar_name(library) {
            wrong += 1;
        }
    }
    let first = reports.iter().find(|r| stage(r.1, r.2, "Recovering") != bar_name(r.0));
    match first {
        Some(&(library, round, rounds)) => println!(
            "{name}: {wrong} of {} rounds named differently, first: library {library} round {round} of {rounds} -> bar {:?}",
            reports.len(),
            stage(round, rounds, "Recovering")
        ),
        None => println!("{name}: all {} rounds named as the library's stage", reports.len()),
    }
    wrong
}

fn main() {
    // Encryption::run (src/operation.rs:237-260): Encrypt 1-12 and Check 13-24, of 24.
    let encryption: Vec<_> = (1..=12).map(|r| ("Encrypt", r, 24))
        .chain((13..=24).map(|r| ("Check", r, 24))).collect();
    // SelfTest::replay (src/self_test.rs:100-123, asserted at :474-475): Encrypt 1-12 and
    // Recover 13-24, of 24.
    let self_test: Vec<_> = (1..=12).map(|r| ("Encrypt", r, 24))
        .chain((13..=24).map(|r| ("Recover", r, 24))).collect();
    // Rekey::seal (src/rekey.rs:313-336): Encryption::run counted after round 12 of 36.
    let rekey_seal: Vec<_> = (13..=24).map(|r| ("Encrypt", r, 36))
        .chain((25..=36).map(|r| ("Check", r, 36))).collect();
    let a = replay("Encryption::run as reported", &encryption);
    let b = replay("SelfTest::replay as reported", &self_test);
    let c = replay("Rekey::seal as reported", &rekey_seal);
    println!("rounds whose bar name differs from the library's stage: {}", a + b + c);
    std::process::exit(if b + c > 0 { 1 } else { 0 });
}
EOF
rustc --edition 2021 -O -o "$work/probe" "$work/probe.rs" || exit 2
"$work/probe"
probe_code=$?
check "S1 the bar names stages from round numbers, not from the library's Stage" "[ $probe_code -eq 1 ]"
check "S1 mhfe encrypt drops the library's Stage (encrypt.rs:261)" \
    "show src/bin/mhfe/encrypt.rs | sed -n '261p' | grep -qF '&mut |_, round, rounds| {'"
check "S1 rekey renumbers the library's rounds to fit the bar (rekey.rs:422)" \
    "show src/bin/mhfe/rekey.rs | sed -n '422p' | grep -qF 'progress(stage, round - ROUNDS, ENCRYPTION_ROUNDS)'"
check "S1 self-test renumbers the recovery's rounds to fit the bar (self_test.rs:309)" \
    "show src/bin/mhfe/self_test.rs | sed -n '309p' | grep -qF 'progress.round_starts(round - ROUNDS, ROUNDS);'"

echo
echo "== Part 2: the benchmark's Argon2 engine name =="
check "S2 test_tools.rs detects SSSE3 itself (test_tools.rs:354)" \
    "show src/bin/mhfe/test_tools.rs | sed -n '354p' | grep -qF 'is_x86_feature_detected!(\"ssse3\")'"
check "S2 the engine's own rule is not reachable from the binary (native.rs:34)" \
    "show src/engine/native.rs | sed -n '34p' | grep -qF 'pub(super) fn processor_has_ssse3() -> bool {'"
check "S2 the copy carries no 'deliberate copy' marker" \
    "! show src/bin/mhfe/test_tools.rs | sed -n '345,362p' | grep -qi 'deliberate copy'"
check "S2 the thread count is typed as '4 threads' (test_tools.rs:355,357,360)" \
    "[ \$(show src/bin/mhfe/test_tools.rs | sed -n '350,362p' | grep -c '4 threads') -eq 3 ]"

echo
echo "== Part 3: the summary's built-in check note =="
check "S3 terminal.rs decides the note from the Suite variant (terminal.rs:619)" \
    "show src/bin/mhfe/terminal.rs | sed -n '619p' | grep -qF 'Suite::SameLength => \" (no built-in check)\",'"

echo
echo "$present of $total checks show the defect"
if [ "$present" -eq "$total" ]; then echo "DEFECT REPRODUCED"; exit 1; fi
if [ "$present" -eq 0 ]; then echo "DEFECT NOT REPRODUCED"; exit 0; fi
echo "PARTLY"
exit 1
