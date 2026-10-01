#!/bin/sh
# AUD-003-API002 follow-up: a native build for a 32-bit target must stop at the compile_error! in
# src/engine/native.rs. The machine needs no 32-bit C headers: a stand-in C compiler writes empty
# objects for the vendored Argon2 C code, and `cargo check` links nothing, so the Rust code is still
# checked in full. Exit 0 means the build stopped with exactly that error and no other.
set -eu
root=$(cd "$(dirname "$0")/../../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cat > "$work/cc" <<'CC'
#!/bin/sh
# Writes an empty file wherever an output is asked for: "-o path", "-opath" or MSVC-style "-Fopath".
while [ $# -gt 0 ]; do
  case "$1" in
    -o) : > "$2"; shift ;;
    -o*) : > "${1#-o}" ;;
    -Fo*) : > "${1#-Fo}" ;;
  esac
  shift
done
exit 0
CC
chmod +x "$work/cc"
rustup target add i686-unknown-linux-gnu >/dev/null
cd "$root"
if CC_i686_unknown_linux_gnu="$work/cc" AR_i686_unknown_linux_gnu=ar \
  cargo check --locked --target i686-unknown-linux-gnu --lib --target-dir target/i686-check \
  > "$work/log" 2>&1; then
  echo "The 32-bit check compiled; the 64-bit guard is missing." >&2
  exit 1
fi
grep '^error' "$work/log"
errors=$(grep -c '^error\[\|^error:' "$work/log")
grep -q '^error: the native MHFE engine needs a 64-bit target' "$work/log"
# The guard itself and the summary line "could not compile ... due to 1 previous error".
[ "$errors" -eq 2 ] || { echo "Unexpected further errors:" >&2; cat "$work/log" >&2; exit 1; }
grep -q 'due to 1 previous error' "$work/log"
echo "A 32-bit native build stops at the 64-bit guard and nothing else."
