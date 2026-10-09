# AUD-013 quality probes

These audit-only probes review the current dirty source of MHFE, based on commit
`abb16671b641378c0fc3c4d855f8d126498e754b`. They do not change production source, run
Argon2, or create a second working tree. Their inputs are synthetic code only.

`clone-controls.mjs` executes the unchanged production `scripts/verify-no-copies.mjs`
in a VM linked to virtual source files. It verifies ordinary and exported-declaration
positive controls, threshold refusals and the production self-test, then challenges
semicolon-free imports and re-exports and deliberate-copy suppression. A terminated
import and a reversed enumeration order are matched controls. Every JavaScript fixture is
independently parsed as valid ESM. The probe prints the checker SHA-256, statuses and
output for each case, and exits nonzero if any required detection fails.

Run from the repository root with the documented Node toolchain:

```sh
/home/user/.local/bin/node --experimental-vm-modules docs/audits/AUD-013-harnesses/quality/clone-controls.mjs
```

Expected healthy behavior is exit 0 with every `passed` value true. A failing
exit is defect evidence, not a normal production test-suite failure. Retain
command metadata and the output under the ignored local `AUD-013-evidence/` folder.

An optional lowercase evidence label records the JSON output and command metadata
directly in the ignored evidence folder, without spawning another process:

```sh
/home/user/.local/bin/node --experimental-vm-modules docs/audits/AUD-013-harnesses/quality/clone-controls.mjs quality-clone-controls-resumed-direct
```

Owner-authorized documentation-only amendment of 2026-10-09: commit references of the history replaced by the second privacy rewrite of 2026-10-09 now name the commits that replaced them: ca0086acf545d07bfe008ae340554124a48442bf -> abb16671b641378c0fc3c4d855f8d126498e754b.
