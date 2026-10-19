# AUD-031 public refusal controls

These audit-only controls review the dirty source at base commit
`575cbd1b7634646f6e19a2501ed9ea164a6a7acd`, source manifest
`d42ee90e77eee7578d86351d406e673709f93f2d12968adc93b3f4598ea53600`.
The base commit alone does not identify the reviewed tree. No real wallet data is used.

Build the current CLI with the pinned workspace Rust toolchain and one Cargo worker, then run
from the existing repository root:

```sh
cargo build --locked --bin mhfe
python3 docs/audits/AUD-031-harnesses/cli-refusal.py target/debug/mhfe invalid-utf8
python3 docs/audits/AUD-031-harnesses/cli-refusal.py target/debug/mhfe long-passphrase
```

To retain an actual command receipt without overwriting earlier evidence:

```sh
python3 docs/audits/AUD-031-harnesses/record.py cli-build cargo build --locked --bin mhfe
```

The recorder requires Linux `/proc`, keeps one Cargo/test/Emscripten worker, samples descendant
RSS against a 2 GiB budget with a 3 GiB machine-available reserve, and stops after 15 minutes.
Its before/after source maps, UTC timestamps, log hash, exit and resource outcomes remain in
ignored `AUD-031-evidence/`. Sampling is not a hard sandbox or an exact peak guarantee.

Python's standard-library PTY support is required on Linux or macOS. The script waits for real
prompts, first proves a malformed ordinary fingerprint is asked again, then submits invalid
UTF-8 or an excessive synthetic passphrase. It refuses to count any run that reaches recovery.
Each process has a 15-second deadline and owned-process cleanup.
Cleanup does not re-enter the recovery tripwire; a synthetic child that ignores termination
must still be killed, reaped and have its PTY closed:

```sh
python3 docs/audits/AUD-031-harnesses/cleanup-control.py
```

Exit zero proves that finite cleanup control. It never starts the production binary or Argon2.

Exit zero means the baseline's proposed premature exit was reproduced: the actual process ended
with code 2 after the refusal rather than asking again. It does not mean the product passed
acceptance. Other exits indicate a harness/prerequisite mismatch or an unestablished finding.
The printed JSON carries binary/transcript hashes, not wallet material. No full-size Argon2,
release acceptance, cryptographic proof or cross-platform runtime claim follows.

## Word-hint byte admission

With the existing exact-source browser package in `dist/`:

```sh
node docs/audits/AUD-031-harnesses/word-hints.mjs
```

This uses actual raw bindings, literal dictionary positives and the existing page-class stand-in
worker. It tests both lists at 8,192 and 8,193 raw UTF-8 bytes, with ASCII and multibyte whitespace,
and confirms the complete byte payload is transferred and accepted. Exit zero establishes the
baseline's missing admission, not passing product acceptance. No Argon2 or random drawing is run;
this is not a resource-exhaustion or real-browser-scheduling campaign.
