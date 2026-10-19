# AUD-034 native acceptance controls

These controls belong to the scoped follow-up of the automatic CI run of signed commit
`804079743dd63794dfa747de0882b55c78284232`. The report's source manifest identifies the fixed,
pre-commit bytes. Only public fixtures and synthetic pending input are used.

From the repository root, with its pinned Rust toolchain active, run on Linux:

```sh
bash docs/audits/AUD-034-harnesses/checks.sh
```

The commands check exact owned-page dump flags and malformed/refused metadata, parallel work
areas, simultaneous C/RustCrypto known-answer calls, the original 160-input comparison and the
CLI reader's wiping/UTF-16 invariants. Every selected group must run tests and pass; the wrapper rejects an empty filter and propagates
nonzero command status. The C
concurrency test uses four callers and 64 public RFC-vector calls per caller; it does not use
production-size Argon2. No new check is added to application startup.

The existing bounded recorder can retain source/helper/log hashes and process-group resource
measurements without duplicating its implementation:

```sh
MHFE_CHECK_RSS_LIMIT_KIB=1048576 python3 docs/audits/AUD-033-harnesses/run.py \
  aud034-public-controls 180 bash docs/audits/AUD-034-harnesses/checks.sh
```

That recorder writes ignored local receipts under `AUD-033-evidence`; AUD-034 retains exact
copies of the selected receipts and their helper snapshots. A finite timeout, the per-command
RSS ceiling and the 3 GiB machine reserve remain mandatory. Coordinate heavy checks with other
sessions; do not run full-cost vectors for this follow-up.

Windows acceptance requires the native `cargo test --locked` job: the reader fixtures must
compile with the Windows-only console field and retain all byte-wiping assertions.

On a macOS test host authorized for noninteractive sudo:

```sh
MHFE_PUBLIC_MACOS_ATTACH_PROBE_SUDO=1 cargo test --locked
```

Only the fixed public monitor and its named probe subprocesses are elevated. Cargo, the rest of
the suite and production commands are not elevated. The unprotected attach/stop/detach control
must succeed before the protected child's real SIGSEGV is checked inside the monitor. A missing
permission or missing exact test is a failure, never proof of protection. No host security
setting is changed. Hosted native CI is recorded separately from local Linux execution.
