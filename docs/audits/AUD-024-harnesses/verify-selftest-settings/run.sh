#!/usr/bin/env bash
# AUD-024 verifier harness: SelfTest::run at settings other than the published vectors'.
# Copies the crate to a work directory, appends probe.rs to the copy's src/self_test.rs and runs
# the probe's tests. Exits non-zero when a probe fails. See README.md.
set -euo pipefail
repo="$(pwd)"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="${1:-${TMPDIR:-/tmp}/aud024-verify-selftest-settings}"
rm -rf "$work"
mkdir -p "$work/tests" "$work/scripts"
for name in src Cargo.toml Cargo.lock build.rs vendor rust-toolchain.toml clippy.toml; do
    cp -a "$repo/$name" "$work/"
done
cp -a "$repo/tests/fixtures" "$work/tests/"
cp -a "$repo/scripts/independent-suite3.py" "$work/scripts/"
printf '\n' >> "$work/src/self_test.rs"
cat "$here/probe.rs" >> "$work/src/self_test.rs"
cargo test --locked --offline --manifest-path "$work/Cargo.toml" --lib -- aud024_verify_settings \
    --nocapture --test-threads=1
