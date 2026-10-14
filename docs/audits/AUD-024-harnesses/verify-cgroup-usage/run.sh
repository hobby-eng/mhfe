#!/usr/bin/env bash
# AUD-024 verify-cgroup-usage harness (reviewed commit b6fca69). Run from the repository root:
#   CARGO_TARGET_DIR=<folder outside the repository> \
#     docs/audits/AUD-024-harnesses/verify-cgroup-usage/run.sh unit|e2e
# unit: rustc --test of a copy of src/engine/cgroup.rs with probe.rs appended.
# e2e:  runs $MHFE_BIN (default $CARGO_TARGET_DIR/debug/mhfe, built from this commit with
#       `cargo build --locked --bin mhfe`) in a private user and mount namespace where the
#       process's own cgroup v2 group shows memory.max = 8 GiB and a memory.current it cannot read
#       (mode 000, capabilities dropped), with the real memory.stat and with an unreadable one,
#       then `mhfe decrypt --stdin --pim 0 --mem 0 </dev/null`, which ends before any Argon2 round
#       (refused for memory, or at the empty standard input). A control run gives a readable
#       memory.current of 1 GiB.
# Exits 1 when the check fails (an unreadable usage becomes a free-memory figure and level 0 is
# refused for lack of memory), 2 when the run is inconclusive, 0 when it passes. Writes only into
# a temporary folder (under $TMPDIR).
set -euo pipefail

check="${1:?usage: run.sh unit|e2e}"
repo="$(pwd)"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR to a folder outside the repository}"
work="$(mktemp -d)"
trap 'chmod -R u+rw "$work"; rm -rf "$work"' EXIT

case "$check" in
  unit)
    cat "$repo/src/engine/cgroup.rs" "$here/probe.rs" > "$work/cgroup.rs"
    cat > "$work/main.rs" <<EOF
#![allow(dead_code)]
mod engine {
    #[path = "$work/cgroup.rs"]
    pub mod cgroup;
}
EOF
    rustc --edition 2021 --remap-path-prefix "$work=work" --test -o "$work/probe" "$work/main.rs"
    "$work/probe" --test-threads 1 --nocapture
    ;;
  e2e)
    bin="${MHFE_BIN:-$CARGO_TARGET_DIR/debug/mhfe}"
    group="$(sed -n 's/^0:://p' /proc/self/cgroup)"
    dir="/sys/fs/cgroup$group"
    [ -n "$group" ] && [ "$group" != "/" ] && [ -e "$dir/memory.current" ] \
      || { echo "needs cgroup v2 and a non-root group with memory.current" >&2; exit 2; }
    printf '%s\n' $((8 << 30)) > "$work/max"
    printf '%s\n' $((1 << 30)) > "$work/current-readable"
    printf '%s\n' $((1 << 30)) > "$work/current-unreadable"
    chmod 000 "$work/current-unreadable"
    printf 'inactive_file 0\n' > "$work/stat-unreadable"
    chmod 000 "$work/stat-unreadable"
    run() { # $1: the file shown as memory.current; $2: one shown as memory.stat, or "" for the real one
      unshare -Urm sh -c '
        mount --bind "$1" "$3/memory.max" && mount --bind "$2" "$3/memory.current" || exit 99
        if [ -n "$5" ]; then mount --bind "$5" "$3/memory.stat" || exit 99; fi
        exec setpriv --bounding-set=-all --inh-caps=-all sh -c "
          printf \"memory.max: %s\n\" \"\$(cat \"\$1/memory.max\")\"
          printf \"memory.current: %s\n\" \"\$(cat \"\$1/memory.current\" 2>&1)\"
          printf \"memory.stat inactive_file: %s\n\" \"\$(grep ^inactive_file \"\$1/memory.stat\" 2>&1)\"
          \"\$2\" decrypt --stdin --pim 0 --mem 0 </dev/null 2>&1; echo \"mhfe exit \$?\"" sh "$3" "$4"
      ' sh "$work/max" "$1" "$dir" "$bin" "$2"
    }
    echo "== control: memory.current readable (1 GiB), real memory.stat"
    control="$(run "$work/current-readable" "")"
    echo "$control"
    echo "== memory.current unreadable, real memory.stat"
    probe="$(run "$work/current-unreadable" "")"
    echo "$probe"
    echo "== memory.current and memory.stat unreadable"
    probe_both="$(run "$work/current-unreadable" "$work/stat-unreadable")"
    echo "$probe_both"
    if grep -q "but only" <<<"$control"; then
      echo "INCONCLUSIVE: the control run is refused for memory too" >&2
      exit 2
    fi
    if grep -q "but only" <<<"$probe$probe_both"; then
      echo "FAIL: an unreadable memory.current is taken as a free-memory figure and every level is refused"
      exit 1
    fi
    echo "OK"
    ;;
  *) echo "unknown check: $check" >&2; exit 2 ;;
esac
