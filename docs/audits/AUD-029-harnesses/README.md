# AUD-029 regression harnesses

These public-input probes belong to the frozen AUD-029 baseline: commit
`575cbd1b7634646f6e19a2501ed9ea164a6a7acd` plus the authorized dirty473-file source
manifest `dfaaa11bd9bc5a149a035ec9e204d2b29eb78e1d49bfb8e4e51bb9046fb80a90`.
The accompanying report distinguishes baseline reproduction, helper mistakes,
later remediation and runtime acceptance. A base commit alone does not identify
the dirty reviewed source. No real wallet data is used.

## Inputs and prerequisites

Run from the existing repository root, using its pinned Rust/Cargo and Node
toolchains. Set `CARGO_HOME` and `RUSTUP_HOME` to the workspace toolchain locations
as described in the workspace instructions. Keep one Cargo build worker and one
heavy check at a time. The Rust probes use the literal published zero-entropy
BIP39 phrase and synthetic `artw` prefix. They do not run Argon2.

The browser probe additionally needs the actual package built with
`scripts/build-wasm.sh`, the installed pinned development dependencies and the
repository's `scripts/package-check/package.mjs` adapter. It uses the real compiled
WASM bindings and the real Argon2 engine. Only production2GiB/12-pass calls are
reduced to256KiB/1pass. The operation's1MiB pre/post known answers remain unchanged.
The adapter also forwards64/256MiB full-check costs unchanged if requested;
this probe does not itself request those full checks. This is not a full-cost
vector replay or physical erasure proof.

## Commands and expected results

```sh
node docs/audits/AUD-029-harnesses/native-probe.mjs phrase-raw-boundary
node docs/audits/AUD-029-harnesses/native-probe.mjs hint-debug-boundary
node docs/audits/AUD-029-harnesses/sealed-json-owners.mjs
python3 docs/audits/AUD-029-harnesses/nondumpable-reader.py
python3 docs/audits/AUD-029-harnesses/structured-data.py docs/audits/AUD-029-2026-10-15.json
```

- `phrase-raw-boundary.rs` compares actual public readers against the common8192-byte domain, with leading and internal whitespace. Baseline: exits101 because all three readers accept8193bytes. Fixed: exits0;8192-byte positives still pass.
- `hint-debug-boundary.rs` first confirms intentional getters return `artwork` and `ork`, then rejects those selected values in `Debug`. Baseline: exits101 with2disclosures. Fixed: exits0; getters retain their values.
- `sealed-json-owners.mjs` checks exact reduced encryption output and24production engine calls, then searches for the complete453-byte returned JSON containing newly generated repair words above the known1MiB stack boundary. Baseline: exits1 with a retained heap match. Fixed: exits0 with no complete-result match in the inspected live linear-memory image. This finite probe does not prove universal erasure of registers, stacks or host/browser copies.
- `nondumpable-reader.py` is a Linux-only regular-user OS control using Python's standard-library `ctypes` FFI. It hardens only its own disposable interpreter process, never its caller or system policy. On the audited Linux host it exits0 after proving `/proc/self/mem` opens before non-dumpability and returns EACCES13 afterward. A different kernel/identity policy can fail this host-specific control; that does not prove missing product cleanup. It is not a final regression acceptance test and does not read private memory.
- `structured-data.py` is a Linux checker using Python3.11 or later, Unix `resource` for a64MiB address-space limit and standard-library `tomllib` for independent fixture/lock parsing. Its paths are portable within the repository; Windows execution is unsupported. Supply the published JSON companion. It pins only37 structured input files, then checks34 strict JSON files,27 positive-vector round shapes, exact18/11 checksum sets and109 Cargo packages with205 dependency references. Success prints JSON and exits0; mismatched bytes, malformed data or failed negative controls exit nonzero. It refuses Python optimization. Changes to other source files are outside this data-only check. The original private sweep additionally bound all473 source hashes; the report keeps its separate execution record and two initial fixture-schema mistakes.

The native runner uses actual Cargo JSON artifact metadata and refuses ambiguous,
foreign-manifest or test artifacts. Its outputs go to ignored
`target/aud029-probes/`; no source checkout is copied. Original exact executed
private helper bytes, command/log hashes and failed attempts remain local evidence.
These portable versions preserve the asserted public contracts; their own
execution is recorded separately from earlier private helper execution.
