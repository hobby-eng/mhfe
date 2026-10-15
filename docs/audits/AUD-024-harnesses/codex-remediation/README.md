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

## Completion of the previously deferred changes

The owner's later authorization extends this remediation from `968424528984235635f187551126b2925d705297`
on `main`. Its source and artifact manifests and individual results are recorded separately in
the report's final remediation section. The original snapshot, failed checks and publication
checkpoint above remain historical. No additional checkout or audit number is involved.

The implementation now supplies these maintained controls, run in the existing checkout:

```sh
cargo test --locked --test error_contracts
node scripts/verify-error-contracts.mjs --self-test
node scripts/verify-error-contracts.mjs
node scripts/verify-module-boundaries.mjs --self-test
node scripts/verify-module-boundaries.mjs
node scripts/verify-browser-source.mjs
python3 docs/audits/AUD-024-harnesses/verify-error-text-sites/scan.py
python3 docs/audits/AUD-024-harnesses/verify-platform-hardening/platform_hardening.py
bash docs/audits/AUD-024-harnesses/verify-web-file-sizes/check-web-file-sizes.sh
python3 scripts/third-party-licenses.py --self-test
bash scripts/verify-archive-packing.sh
```

Expected: zero exit codes. Error contracts independently name all 52 retained codes, check owned
causes, canonical cancellation and shared format/passphrase conversions. Structural controls
reject free-text errors, low-level dependencies on cipher execution, broken source joins and
missing inputs. Coin extension is checked by a synthetic declaration in the wallet's own unit
tests; the older `new-coin-touches.sh` is not used because it extracts a second working tree.
Packing controls cover the GNU and Python tar packers and ZIP under four umasks. MinGW controls
reject missing or changed notices; a retained public Windows binary can additionally be supplied
through the documented archive/binary verifier options. These controls do not rebuild a release.

After rebuilding with `scripts/build-wasm.sh`, run `node scripts/verify-browser-package.mjs`,
`node scripts/verify-single-modules.mjs`, and `node scripts/verify-cli-browser-parity.mjs` with
the current CLI path. Real browser checks use `node scripts/verify-browsers.mjs`, one browser
and mode at a time through its `--browser` and `--mode` options. These checks keep their specified
Argon2 known answers and use the documented reduced cost for ordinary operations. Startup
privacy controls cover synchronous throws, rejected promises, unreadable exception messages and
fatal package mismatches without fallback. No `--full` option or full-cost vector replay is part
of this continuation. Bound jobs and serialize them with other sessions as the workspace rules
require; the report distinguishes execution from source inspection and cross-compilation.

For a focused retry of the standalone launcher's startup check, add
`--browser chromium --mode fast --launcher python` (or `firefox`). The default still executes
the complete native route and the Python startup route. Clients expose `cancel()` for ongoing
core/wallet operations; the smoke check does not invent a `close()` method on module classes.

Linux tests and a Windows cross-compiler cannot establish actual Windows console, page-lock,
process-access or crash-report behavior, or macOS debugger policy and signed archive behavior.
Those native-platform checks remain explicit verification limitations until executed there.

## Implementation commit binding — 2026-10-15 (UTC)

The current remediation source is recorded in SSH-signed implementation commit
`12f12032cca2215d11237e4e717690a1ccd75f29`, source fingerprint `9d485ddc61c3edfe51a864160a712e96945f7cf8108d00f1728fcd4ec384e403` (454 non-audit files).
This identity supplements the historical discovery/continuation snapshots above. The retained
checks were performed before committing on those exact source bytes; committing did not rerun
them. The associated report preserves the remaining platform and release acceptance limits.
