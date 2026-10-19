# AUD-026 audit harnesses

These read-only baseline probes belong to [AUD-026](../AUD-026-2026-10-15.md), reviewed commit
`575cbd1b7634646f6e19a2501ed9ea164a6a7acd`, source fingerprint
`9d485ddc61c3edfe51a864160a712e96945f7cf8108d00f1728fcd4ec384e403`.
Use public fixtures and synthetic markers only. No probe computes full-cost Argon2 or changes a
project source, vector, dependency or workflow. Generated output belongs in the ignored workspace
`tmp/` directory. Original command logs and exact artifact hashes are local-only in
`docs/audits/AUD-026-evidence/`.

Python probes with assertion controls refuse optimization (`-O`/`PYTHONOPTIMIZE`), so those controls
cannot silently disappear. The kept data inspector uses the current repository root and writes its
report to standard output; it has no machine-specific source path.

Run commands from the MHFE repository root with the toolchain environment from `AGENTS.md`:
Rust 1.99.0, Node.js 26.10.0 and Python 3.14.4. The workspace supplies `CARGO_HOME` and `RUSTUP_HOME`;
do not install another toolchain or use a second checkout. The baseline witnesses intentionally
exit nonzero on confirmed defects. They are historical reproductions, not automatically a future
fix-acceptance suite when an API or the live checker changes.

## File inventory

```sh
python3 docs/audits/AUD-026-harnesses/inventory.py > ../tmp/mhfe-aud026-inventory.json
```

Exit 0 prints every present tracked/nonignored file hash, the non-audit source fingerprint and
lexical public Rust declaration candidates. Ignored build/evidence files are excluded. The baseline
has 454 non-audit files and the fingerprint above. A rerun after adding this audit includes the new
audit files in its total; it does not recreate the original 1,211-file baseline inventory.
Lexical declarations are not a semantic Rust public-API count or execution coverage.

## Direct Rust boundaries

Build the actual library and CLI, then compile a separate small executable against that library:

```sh
cargo build --locked --lib --bin mhfe
rustc --edition=2021 docs/audits/AUD-026-harnesses/public-boundaries.rs \
  --extern mhfe=target/debug/libmhfe.rlib -L dependency=target/debug/deps \
  -o ../tmp/mhfe-aud026-public-boundaries
../tmp/mhfe-aud026-public-boundaries
```

At the reviewed debug snapshot, exit 1 reports four failing cases: word/character millibit overflow,
a foreign `Repair` panic, and ignored cancellation for an explicit BIP84 address path. Literal
normal-strength controls and ordinary address-search cancellation must pass. Public BIP39 zero-12
data and a published receiving address are embedded. Debug arithmetic panics are caught; the probe
does not establish optimized overflow behavior or validate every foreign-review association.

## CLI refusal privacy

```sh
python3 docs/audits/AUD-026-harnesses/cli-refusal.py target/debug/mhfe
python3 docs/audits/AUD-026-harnesses/cli-selection.py target/debug/mhfe \
  ../tmp/mhfe-aud026-selection-unused
```

The selection output path must not already exist. The baseline exits 1: LF/CRLF refused values
echo synthetic marker components; single-line, lone CR, NEL and U+2028 controls are redacted.
The selector witness exits 1 because stderr repeats `AUD026-NOT-A-VECTOR`; the command itself
exits 2, and its output directory remains absent. No vector generation or Argon2 occurs.

## Raw WASM rekey preflight

```sh
node docs/audits/AUD-026-harnesses/raw-rekey.mjs .
```

Requires the existing source-bound browser package at `dist/` and its own wasm-bindgen glue at
`target/wasm-bindgen/mhfe.js`. Exact hashes are in the audit JSON. The baseline exits 1 because
`setNew` accepts repair count 3. Recovery reaches one external engine call for the 1 MiB startup
known answer, where the fake throws; it never derives Argon2 or reserves its work area. Counts
0, 2, 4, 6 and 8 are acceptance controls. The ordinary JS class validates this option correctly.
An earlier local harness attempt used a separate VM realm and failed before initialization; that
audit-harness error is retained separately and is not a product defect.

## Audit-record checker negative controls

```sh
python3 docs/audits/AUD-026-harnesses/record-controls.py . ../tmp
```

Requires the sibling workspace audit schema and the existing Python `jsonschema` package.
The probe imports the historical checker actually used by the live wrapper and creates only
temporary synthetic AUD-999 records under the supplied scratch directory; those records are
removed on exit. A valid pair passes. At baseline a wrong JSON date, a conflicting audit ID/number
and an invalid JSON orphan
all evade the checks, so the probe exits 1. The real repository records remain unchanged.
Future remediation belongs in the live wrapper; preserving the frozen helper means this historical
direct-helper witness can continue failing after an effective live-wrapper fix. Verify that fix
with equivalent controls against the live interface.

## Fixtures and literal tables

```sh
python3 docs/audits/AUD-026-harnesses/spec-bindings.py
python3 docs/audits/AUD-026-harnesses/inspect-known-answer-data.py
```

Exit 0 checks exact bytes/JSON/checksum consistency for 31 suite-corpus files in sibling `mhfe_spec`,
and parses all published-round literals and terminal-width intervals against local fixtures.
These checks read every listed value; they do not independently derive Argon2, regenerate Unicode
data, rerun historical verification, or prove the cryptographic construction. The sibling repository
is read only. No network service or real wallet material is needed.

The literal parser compares protocol fields and recovery order. Startup-selection flags are read
and counted (10), with no independent per-vector startup-set comparison in this parser; source
review of that selection is separate.

The audit also ran the repository's existing fast/package/browser/table/notice/audit gates and a
current advisory query. Their exact commands, exits, limits and local log hashes are in the report;
they are not duplicated here as new test implementations. Cargo-mutants ran only a read-only
candidate preview. A compiled campaign remains unexecuted and must satisfy the MHFE mutation
profile, exclusive in-place access and the resource/restoration controls before use.
