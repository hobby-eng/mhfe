# AUD-013 rerunnable evidence

This fresh audit reviews the dirty MHFE checkout based on commit
`abb16671b641378c0fc3c4d855f8d126498e754b`; the report's source manifest identifies
the actual reviewed bytes. The aborted preparation is not verification evidence.
The coordinator's GPT-6.1 / ultra setting was supplied by the user; three fresh
reviewers were explicitly configured as `gpt-6.1-sol` with `ultra` reasoning.

Run from the MHFE root using the existing pinned tools, public fixtures and synthetic
inputs only. No production changes, repository copy, installation or publication
is authorized. Logs and generated probes remain local in ignored evidence.

```sh
node docs/audits/AUD-013-harnesses/record.mjs snapshot snapshot
node docs/audits/AUD-013-harnesses/record.mjs clones node scripts/verify-no-copies.mjs
node docs/audits/AUD-013-harnesses/record.mjs clones-self-test node scripts/verify-no-copies.mjs --self-test
```

The recorder accepts a unique label followed by the exact command and arguments,
retains stdout/stderr plus UTC times and SHA-256, and propagates the command's exit.
Use new labels for reruns, preserving failures. Snapshot mode hashes tracked and
nonignored source paths outside audit records, including deletion markers, existing
artifacts and the four common audit procedure files.

The paired report lists all additional commands, scopes, expected defect witnesses
and exclusions. Do not implicitly run full-size Argon2, vector replays, Docker or
release suites; bounded runtime checks run sequentially.

`memory-guard.py LABEL COMMAND...` samples the command and its descendants once per
second. It stops its own workload above 3 GiB aggregate RSS or below a 2 GiB system
available-memory reserve, and refuses to start with less than 3 GiB available. It
retains `LABEL.memory.json`; RSS sampling can double-count shared pages and is not a
hard allocation cap or diagnosis of the host's earlier interruption. It never terminates an
unrelated user's process. No all-card generation or workload above 13 GB is included.

After the paired report and AUD-012 follow-up exist, run:

```sh
python3 docs/audits/AUD-013-harnesses/validate.py
```

The already installed `jsonschema` is required. Exit 0 confirms report schema,
unique IDs and JSON keys, all 32 coverage checks, actual final source bytes,
procedure/harness/log hashes, retained incomplete evidence, report links,
preserved AUD-012 baseline and its matching follow-up, and ignored/not-staged
evidence. It refreshes local validation JSON and SHA256SUMS. Nonzero is a failure.

Owner-authorized documentation-only amendment of 2026-10-09: commit references of the history replaced by the second privacy rewrite of 2026-10-09 now name the commits that replaced them: ca0086acf545d07bfe008ae340554124a48442bf -> abb16671b641378c0fc3c4d855f8d126498e754b.
