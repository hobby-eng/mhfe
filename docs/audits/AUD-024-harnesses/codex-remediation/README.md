# AUD-024 remediation continuation controls

These are the retained in-place controls of the Codex continuation on `aud023-remediation`,
starting from `ec93057`. They accompany the current source fingerprint and per-command evidence
in AUD-024's JSON continuation. They are remediation checks, not another audit. The original
report and earlier failures remain preserved.

Run from the `mhfe` checkout root, using its documented Rust/Node toolchains and Python's standard
library. Only public fixtures and synthetic data are used. No script copies the checkout or runs
full-cost Argon2, Docker, or an actual browser. Raw outputs and result manifests belong only to
ignored `docs/audits/AUD-024-evidence/` and workspace `tmp/aud024/`. Create the latter first.

The Python drivers independently check Rust/CLI outcomes; `published-evidence-values.py` is an
independent BIP39/BIP32 implementation. The PTY coverage driver uses the existing Python-only
terminal runtime. These retained original probes have no third-party Python dependencies.

## Positive controls

```sh
cargo build --locked --release --bin mhfe
python3 -B docs/audits/AUD-024-harnesses/codex-remediation/published-evidence-values.py
python3 -B docs/audits/AUD-024-harnesses/codex-remediation/verify-case-names.py
python3 -B docs/audits/AUD-024-harnesses/codex-remediation/verify-new-option-paths.py target/release/mhfe
node docs/audits/AUD-024-harnesses/codex-remediation/launcher-process-controls.mjs
node scripts/verify-cli-questions.mjs --self-test
node scripts/verify-cli-questions.mjs
node scripts/verify-single-modules.mjs --self-test
```

Expected: zero exit codes; the case-name check preserves the pinned base's original call order,
21 required command/flag pairs execute, independent seed checks/fingerprints reproduce, and both
localhost launchers serve the exact checked page with all policy headers and refuse changed bytes.
The two full-cost terminal cases remain excluded unless the owner separately requests `--full`.

The normal terminal suite is `python3 -B scripts/verify-hidden-input.py target/release/mhfe`.
Its recorded continuation coverage was segmented after two stale expectations were corrected;
the report does not present those failed runs as a clean all-in-one pass.

## Negative controls

Run these alone, with no other source edits, builds or checks in progress. They temporarily alter
files in this checkout, run the nearest tests and restore every original byte in `finally`.
Interruption outside that cleanup requires checking the working tree before continuing.

```sh
python3 -B docs/audits/AUD-024-harnesses/codex-remediation/cli-option-mutants.py
python3 -B docs/audits/AUD-024-harnesses/codex-remediation/launcher-parity-mutants.py
python3 -B docs/audits/AUD-024-harnesses/codex-remediation/known-answer-mutants.py
```

Expected: the driver exits zero only after its deliberate regressions are rejected and original
bytes are restored. CLI controls freeze `--new-pim` while changing `MAX_PIM`, and ignore the
explicit no-passphrase answer. Launcher controls change 16 copied rules/messages. The 22 library
faults cover every coin's roots, secondary roots, DIP17 runtime chains, evidence fields, retention
lists, replacement policy, target comparison, refusals and repeated confirmation. This substitutes
recorded keys and never repeats the memory-hard vectors.

The library driver refuses an existing `codex-known-answer-mutants-final/` directory instead of
overwriting earlier evidence. Keep that directory untouched; before another run, choose a fresh local output run name in the
probe and record that input/source change in the new command record. The other drivers write their small local result files under `tmp/aud024/`; preserve
needed earlier output before repeating them. No commit or push is performed.

Probe wrapping and whitespace were normalized with equal executable ASTs. The preformat source
bytes and `codex-probe-format-equivalence.json` remain in ignored local evidence; actual checked
Rust/source-file hashes remain those recorded by each mutation run. No original log was rewritten.
When rewriting an audited commit later, update this record and the case-name probe's pinned base
together, as the workspace's commit rules require.
