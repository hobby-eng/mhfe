# AUD-013 browser probes

These audit-only probes belong to the read-only AUD-013 review of commit
`abb16671b641378c0fc3c4d855f8d126498e754b` plus the dirty source snapshot recorded in the report.
They use public synthetic input only and make no production changes.

`draw-utf8.mjs` loads the current built browser package, including the real Rust WebAssembly,
from `dist/`. It checks malformed UTF-8 draw input against two cleanup controls and exercises the
unchanged public `MhfeWallet` and actual worker source in bounded Node VM workers. It inspects
synthetic marker bytes in WASM linear memory after a refusal, verifies caller-owned bytes survive,
and verifies the worker's JS copies are wiped and the refused job is terminated. Retention of the
terminated VM is audit instrumentation; the probe does not demonstrate access to a terminated
browser worker, swap exposure, persistence or disclosure.

From the repository root, after the reviewed `dist/` package is available:

```sh
/home/user/.local/bin/node docs/audits/AUD-013-harnesses/browser/draw-utf8.mjs
```

Expected baseline output is two `REPRODUCED` cases and two passing cleanup controls, with an exit
code of 1 while the draw refusal leaves the repeat allocation unwiped. The final JSON gives the
exact reviewed WASM, worker, wallet class source and binding SHA-256 hashes. The script uses no
Argon2 and runs no real-browser acceptance suite.

`draw-setup.mjs` rechecks AUD-012-SEC001 through unchanged public JavaScript preparation. Startup
cryptography is bypassed and module jobs are stand-ins. Seven bounded cases cover an invalid
worker count, repetition encoding, the initial empty repeat-array constructor, draw-counter
allocation, first per-worker copy, second worker's repeat copy and second worker startup. It
checks owned-array wiping, stopping partial jobs and reuse of the operation slot. The constructor
case is injected, not a measured out-of-memory failure.

```sh
/home/user/.local/bin/node docs/audits/AUD-013-harnesses/browser/draw-setup.mjs
```

The current baseline gives six `PASS` lines and one `REPRODUCED` line for the empty repeat-array
allocation before the cleanup block, then exits 1. It exits 0 when all cases leave their owned
copies wiped. Both scripts accept `--evidence` to retain diagnostic stdout and command metadata in
the local ignored `docs/audits/AUD-013-evidence/` directory; this capture avoids the restricted
environment's nested `spawnSync` stdout failure.

Owner-authorized documentation-only amendment of 2026-10-09: commit references of the history replaced by the second privacy rewrite of 2026-10-09 now name the commits that replaced them: ca0086acf545d07bfe008ae340554124a48442bf -> abb16671b641378c0fc3c4d855f8d126498e754b.
