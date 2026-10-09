# AUD-012 harnesses

Read-only full-scope follow-up of the uncommitted MHFE clone-elimination refactor and
AUD-011 fixes. Use public fixtures only, the existing checkout and its pinned toolchains.
The report identifies the exact dirty source fingerprint; HEAD alone is insufficient.

From the MHFE root, run `node docs/audits/AUD-012-harnesses/record.mjs snapshot snapshot`.
`record.mjs LABEL COMMAND ARGS...` retains exact arguments, UTC times, status and log hash
in ignored local `AUD-012-evidence/`. It buffers output until the child ends and propagates
its failure status. `record.mjs final snapshot` records the final source identity.

Snapshots hash tracked/nonignored untracked paths outside `docs/audits/`, mark deleted
tracked paths, and compute SHA-256 of JSON-serialized sorted [path, file SHA-256] pairs.
Generated artifact hashes and shared procedure hashes are recorded separately. No source
copy or worktree is created. Logs are local only and contain synthetic/public test data.
Production source is not edited; no commit, push or release is authorized by these tools.

Subfolders describe the synthetic browser cleanup, clone-checker and Rust compile witnesses.
The report lists production verification commands and their limitations, including all
feature Clippy through the preserved AUD-011 harness and artifact freshness through AUD-010.
Run heavy runtime suites sequentially, never full-size Argon2 or Docker implicitly.

After the final report pair, AUD-011 follow-up and final snapshot exist, run
`python3 docs/audits/AUD-012-harnesses/validate.py` from the MHFE root. It requires the already
installed `jsonschema`, checks duplicate keys/schema/paired IDs/all 32 outcomes, source and
procedure/harness/log hashes, report links and prior finding follow-up consistency, and
rejects staged/nonignored evidence. It prints a success record and exits 0, refreshing local
`report-validation.json` and `SHA256SUMS`. Nonzero means publication checks did not pass.
