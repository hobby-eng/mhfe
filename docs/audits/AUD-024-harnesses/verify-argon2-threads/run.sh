#!/usr/bin/env bash
# Audit AUD-024 harness: builds probe.c against the unmodified vendored Argon2 sources (the same
# five common sources build.rs compiles, with the portable ref.c core) and runs it. Run from the
# repository root. Writes only to a temporary folder, which it removes.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
argon2="vendor/phc-winner-argon2"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

"${CC:-cc}" -std=c99 -O1 -pthread \
    -I "$argon2/include" -I "$argon2/src" \
    "$here/probe.c" \
    "$argon2/src/argon2.c" "$argon2/src/core.c" "$argon2/src/encoding.c" \
    "$argon2/src/thread.c" "$argon2/src/blake2/blake2b.c" "$argon2/src/ref.c" \
    -Wl,--wrap=pthread_create,--wrap=pthread_join \
    -o "$work/probe"
"$work/probe"
