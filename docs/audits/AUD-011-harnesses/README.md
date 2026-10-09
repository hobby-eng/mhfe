# AUD-011 audit harnesses

This ordinary full-scope, read-only audit reviews the current modular/DRY refactor of MHFE
on 2026-10-08. HEAD is `abb16671b641378c0fc3c4d855f8d126498e754b`, but the working tree
is dirty: use the source fingerprint in the report, not HEAD alone. Only synthetic and
published test data is used. No production changes or release approval are implied.

Run from the MHFE repository root with its pinned Node 26.10.0 and workspace Rust 1.99.0:

```sh
node docs/audits/AUD-011-harnesses/record.mjs snapshot snapshot
node docs/audits/AUD-011-harnesses/record.mjs secret-refusals node docs/audits/AUD-011-harnesses/browser/secret-refusals.mjs
node docs/audits/AUD-011-harnesses/record.mjs dry-probe node docs/audits/AUD-011-harnesses/dry-probe.mjs
node docs/audits/AUD-011-harnesses/record.mjs doc-count node docs/audits/AUD-011-harnesses/doc-count.mjs
bash docs/audits/AUD-011-harnesses/feature-clippy.sh
node docs/audits/AUD-011-harnesses/record.mjs final snapshot
```

`record.mjs LABEL COMMAND ARGS...` writes the exact command, UTC times, result and combined
log hash to local ignored `AUD-011-evidence/`. It preserves the child exit code. Its special
`LABEL snapshot` mode writes sorted hashes of tracked/untracked nonignored files outside
`docs/audits/`, HEAD, git status, selected artifact hashes and the shared procedure hashes.
The fingerprint is SHA-256 of JSON-serialized sorted [path, SHA-256(bytes)] pairs; missing
tracked files are marked `deleted`. It records data, not copies of project source.

`browser/secret-refusals.mjs` demonstrates missing wipe after invalid repeated-password
encoding in a hidden-wallet session. It isolates encoding with a mocked ready worker and
bypassed startup check; see its [README](browser/README.md). It runs the unchanged public
class method and fails with exit 1 at the audited baseline. This is not real-browser or
cryptographic startup evidence. After remediation the assertion must pass and exit 0.

`dry-probe.mjs` checks two specifically identified password-size message copies: library
error text and CLI code that discards/rebuilds it. Both are the same root cause. It prints
the observed copies and exits 1 while either remains. It does not assert that all other
code is duplicate-free, and a syntactic spelling change is not substantive remediation.

`doc-count.mjs` compares the API's stated native self-test count with the tested inventory
in `src/self_check/sets.rs`. It prints 23 versus 24 and exits 1 on the baseline. This source
witness supplements the executed composition unit tests; it does not itself run self-tests.

`feature-clippy.sh` compiles each declared browser feature and their union with two build
jobs and warnings denied. Run heavy checks sequentially. It exits on the first failure.
The production verification scripts and earlier AUD-010 freshness harness used by this
audit are listed with their exact commands and limitations in the report.

`python3 docs/audits/AUD-011-harnesses/terminal-search.py target/release/mhfe` imports the
existing terminal suite without changing it and runs its container-search scenario plus
the tail not reached after the debug timeout. Build that CLI from the audited source with
`cargo build --locked --release -j 2` first, using the workspace toolchain environment.
It uses the suite's public fixtures and unchanged assertions/timeouts; it runs native
self-test KATs but no full-size operational Argon2. A failure exits nonzero. This scoped
rerun does not erase the original timeout or claim a full uninterrupted terminal run.

Evidence is local only and ignored; harnesses/report are publishable source. No full-size
Argon2 vectors, canonical Docker builds, dependency installation or remote CI are started
by these harnesses.

After both report files and the final snapshot exist, run `python3
docs/audits/AUD-011-harnesses/validate.py` from the repository root. It needs the already
installed `jsonschema` package and the neighboring shared schema, not network access.
It rejects duplicate keys, missing paired IDs, inconsistent check outcomes, changed source
or procedure/harness/log hashes, broken report links, and staged/nonignored evidence.
On success it prints a validation record, exits 0, and refreshes local
`report-validation.json` and `SHA256SUMS`. Hash verification covers completed command logs
listed in the report; the report does not recursively hash itself or its validation record.

Owner-authorized documentation-only amendment of 2026-10-09: commit references of the history replaced by the second privacy rewrite of 2026-10-09 now name the commits that replaced them: ca0086acf545d07bfe008ae340554124a48442bf -> abb16671b641378c0fc3c4d855f8d126498e754b.
