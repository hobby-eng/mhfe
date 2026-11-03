# AUD-045 harnesses

This Rust probe belongs to the pre-release audit of MHFE commit
`28200e75464aefb4ef42885f961783aec653063a`, with mhfe-core pinned to
`523f9e48a9dd2c84581e44f7f8636627dd496209`. It tests cancellation while a password is
being written, using only the public dice input `11111`, which gives the EFF word `abacus`.
It does not run Argon2 or replay the encryption vectors.

## What it measures

The driver starts the unmodified release executable in a real pseudo-terminal. Its write
interposer pauses the main thread immediately before the original password write, asks the driver
to send SIGINT, and lets the handler write the original leave-private-screen sequence. It then
pauses the handler while the main thread writes its original bytes. Both writes still reach the
kernel with their original descriptor, bytes and count. The extra markers contain no password or
terminal escape. This forces a possible thread schedule; it does not simulate a failed runtime.

A public password word after the leave sequence demonstrates that cancellation can put the
password on the main screen. Exit 1 with `word_after_leave=true` is the reproduced defect. An
unreached schedule or a timeout also exits nonzero, with a separate reason; it is not a passing
privacy check. A future fix that holds the shared drawing guard can prevent this schedule from
being reached, so this reproduction alone cannot certify that fix.

## Run

Requires x86-64 Linux, the pinned Rust 1.99.1 toolchain and the existing libc 0.2.191 source in
Cargo's workspace cache. No C compiler, Node.js, wallet or private test material is needed.
Build the executable from the reviewed checkout first with its documented path remapping. Run
the commands sequentially in the workspace's heavy-check slot and through `tmp/memguard.sh`.
The enclosing user scope must have `MemorySwapMax=0`, so that MHFE runs in that scope rather
than starting a replacement process whose PID differs from the driver's child.

From the repository root, with `CARGO_HOME`, `RUSTUP_HOME` and `PATH` set as `AGENTS.md` says:

```sh
export CARGO_TARGET_DIR="$(pwd)/../tmp/mhfe-aud045/probe-target"
cargo build --offline --manifest-path docs/audits/AUD-045-harnesses/Cargo.toml
cargo clippy --offline --locked --manifest-path docs/audits/AUD-045-harnesses/Cargo.toml --all-targets -- -D warnings
"$CARGO_TARGET_DIR/debug/aud045-probe" \
  "$(pwd)/target/release/mhfe" \
  "$CARGO_TARGET_DIR/debug/libaud045_probe.so"
```

The driver prints only the reached stages, process status and whether the public word followed
the leave sequence. It keeps no terminal transcript. It kills and reaps a live child on an
error. Its deadline is 30 seconds; each forced pause is bounded by three seconds. These are
audit-only files and must not be linked into the program or browser package.

The audit also reuses the unchanged command logger
[`AUD-044-harnesses/run-logged.sh`](../AUD-044-harnesses/run-logged.sh). Its evidence directory
argument is `docs/audits/AUD-045-evidence`; this preserves each exact command, UTC times, exit
code and log SHA-256. That directory is local and ignored by Git.
