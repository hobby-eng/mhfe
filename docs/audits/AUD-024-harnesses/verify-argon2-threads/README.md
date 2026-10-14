# verify-argon2-threads

Audit AUD-024, commit b6fca69. This harness was used to verify the candidate "argon2id's SAFETY
argument holds only when threads equal lanes" (src/engine/ffi.rs:172-183).

## What it checks

The harness asks whether the vendored Argon2 C code ever joins a thread it has already joined
after a thread creation fails. That code is `argon2_ctx` → `fill_memory_blocks` in
vendor/phc-winner-argon2/src/core.c:375-385 and 291-370. `probe.c` is linked with the
unmodified vendored sources: the five common sources build.rs compiles, plus the portable
`ref.c` core. It is also linked with `-Wl,--wrap=pthread_create,--wrap=pthread_join`. The create
wrapper fails the Nth creation with EAGAIN. The join wrapper counts any join of a handle that was
joined before and not handed out again; it does not perform that join.

The cases cover the shapes MHFE passes (threads equal to lanes, and threads 1) and shapes that
`argon2id` accepts but no caller passes (1 < threads < lanes). The inputs are public counters,
and each run uses 64 KiB of memory.

## Inputs

None. It uses the vendored sources at vendor/phc-winner-argon2 and the C compiler in `$CC`
(default `cc`). It builds into a temporary folder and then removes it.

## Command (from the repository root)

```sh
docs/audits/AUD-024-harnesses/verify-argon2-threads/run.sh
```

## Expected output at b6fca69

Exit 1, ending in `FAIL: argon2_ctx joined a thread it had already joined after a failed
creation`.

- Threads 1 never reach the threaded code: 0 creations and 0 joins, even when every creation
  would fail.
- Threads equal to lanes join no thread twice, including after a failure in a later slice.
- With 1 < threads < lanes, a failed creation makes the C code join already-joined threads
  again: 1 or 2 second joins per case.

Exit 2 means that a case returned another code or another creation count than the one expected.
