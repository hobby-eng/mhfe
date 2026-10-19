# AUD-032 public controls

These controls inspect the existing dirty MHFE source at base commit
`575cbd1b7634646f6e19a2501ed9ea164a6a7acd`, current-source fingerprint
`d42ee90e77eee7578d86351d406e673709f93f2d12968adc93b3f4598ea53600`.
The base commit alone does not identify the reviewed source. Use only the included public vectors
and synthetic input. Run from the repository root with its pinned toolchains and dependencies.

The browser controls need the exact-source package in `dist/`, built by `scripts/build-wasm.sh`.
They run the actual bindings/classes with the existing stand-in worker, not a real browser or a
full-cost cryptographic operation. The CLI controls require a current binary built with
`cargo build --locked --bin mhfe` and Python's standard-library Unix PTY support. Do not run
multiple heavy checks together; these probes themselves do not request Argon2 recovery/drawing.

```sh
node docs/audits/AUD-031-harnesses/word-hints.mjs
node docs/audits/AUD-032-harnesses/wish-bytes.mjs
node docs/audits/AUD-032-harnesses/incomplete-startup.mjs
python3 docs/audits/AUD-032-harnesses/cli-refusal.py target/debug/mhfe invalid-utf8
python3 docs/audits/AUD-032-harnesses/cli-refusal.py target/debug/mhfe long-passphrase
python3 docs/audits/AUD-032-harnesses/pty-cancel-group.py target/debug/mhfe
node docs/audits/AUD-032-harnesses/inventory-runtime-names.mjs ../tmp/mhfe-aud032-names.json
```

- The unchanged AUD-031 word-hint probe exits zero when both raw/class paths accept 8,193 bytes,
  retaining exact 8,192-byte positives and literal dictionary/completion controls. Zero reproduces
  the missing admission; it is not passing product acceptance.
- `wish-bytes.mjs` exits zero when one padded chosen/excluded word at 8,192 and 8,193 UTF-8 bytes
  reaches both raw semantics and the complete class transport. ASCII/U+2003 padding is used;
  the wire has one additional framing newline. This reproduces original AUD-028-API005's remaining
  single-entry variant, separately from the corrected array-count guard. No exhaustion is attempted.
- `incomplete-startup.mjs` first passes the real complete startup report, then uses three incomplete
  synthetic final reports on fresh module identities with no previously passed component cache.
  It exits nonzero if an actual inspection operation is allowed. This is a malformed-protocol
  resilience control; the normal producer is not shown to emit such reports. Future fixes must
  preserve legitimate tier exclusions, shared cached passes and explicit failed trap reports.
- `cli-refusal.py` is the AUD-031 probe with only its output evidence directory changed. Zero means
  a premature exit 2 was reproduced after a valid earlier retry. It checks no recovery started,
  reaps its owned child, and writes synthetic transcripts only into ignored AUD-032 evidence.
- `pty-cancel-group.py` calls the existing ordinary terminal test without modifying it. The baseline
  exits nonzero after earlier password/refusal controls pass: one-write text plus Ctrl+C can be
  flushed by the terminal before display, while the oracle requires displayed text. The proper
  control must establish visibility before cancelling; dropping the oracle is not a fix.
- Run Python without `-O`: the terminal wrapper refuses optimization before starting the program,
  because optimization disables the underlying terminal assertions.
- `inventory-runtime-names.mjs` writes a new JSON file with the actual class, runtime and raw-binding
  namespaces and prototype member names. It exits zero after checking three expected exports and
  refuses to overwrite an existing output file. This is a named inventory, not execution of every
  feature or a compiler-expanded native trait API inventory.

The companion report retains binary/package/source hashes and separates failed product/control
assertions from successful reproductions. These probes do not prove all memory erasure, global
optimality, native Windows/macOS acceptance, canonical reproducibility or defect absence.
