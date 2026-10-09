# AUD-016 harnesses

These scripts belong to the 2026-10-09 UTC baseline audit of MHFE 0.5.1, HEAD
`3c60594479302827fe40975b04fd07f9f6fd4b3b` plus its existing uncommitted changes.
The reviewed non-audit source-manifest SHA-256 is
`0c282ddd47edbe418644f19a5ae136fedd68fc13cb1e3b61972dc7f7e6d74f41`.
HEAD alone does not identify the reviewed bytes. No baseline production, test,
fixture, dependency or workflow changes were made by this audit.
Another actor began editing source after baseline closeout. The report records
that later snapshot separately; the original checks do not verify those edits.

Run from the existing MHFE checkout. Use public vectors and synthetic inputs only.
Do not run heavy checks concurrently with another audit or build. This audit did
not run full-cost vector replays or canonical Docker rebuilds.

## Inputs and toolchains

- Linux x86_64, Python 3.14.4 and the workspace Node 26.10.0/Rust 1.99.0 toolchains.
- Set `CARGO_HOME=/home/user/Documents/bip_tools/workingspace/cargo` and
  `RUSTUP_HOME=/home/user/Documents/bip_tools/workingspace/rustup`, replacing the
  anonymized home prefix with the local workspace path. Set `CARGO_BUILD_JOBS=1`.
- Existing pinned Cargo archives/dependencies, installed Prettier/Playwright,
  wasm-bindgen 0.2.129, the workspace Emscripten 6.0.10, current specification
  vectors and the retained AUD-015 independent oracle/harness files.
- Specialized probe prerequisites are in [core](core/README.md),
  [native](native/README.md) and [browser](browser/README.md). They use the current
  release/library/WASM artifacts; bind those artifacts before comparing results.
- Report assembly requires the original local `AUD-016-evidence` directory.
  Validation additionally requires the shared audit schema and Python `jsonschema`.

## Capturing evidence

```sh
python3 docs/audits/AUD-016-harnesses/run.py snapshot new-snapshot-label
python3 docs/audits/AUD-016-harnesses/run.py new-command-label node scripts/verify-no-copies.mjs
```

`run.py` retains the original merged log and exact command record with UTC timing,
exit status, environment and log SHA-256 in ignored local evidence. Labels cannot
be reused, so failed attempts remain intact. Snapshots write full and non-audit
manifests for MHFE and its specification. Audit-owned files are excluded from the
full snapshot; all audit files are excluded from the non-audit source fingerprint.

The runner samples aggregate RSS within the launched Linux process group every
250 ms and kills that group above 3 GiB or 1,200 seconds. This is a sampled guard,
not a hard cgroup cap. Independent browser process groups are outside that sum;
the reported peak is not a whole-machine or complete browser-tree memory peak.
Serialize heavy commands and do not reduce cryptographic parameters to claim a
production-cost result. Browser regression suites already use their documented
reduced-cost test wrapper.

## Baseline helpers

- `baseline.py small` runs formatting, copy detection/self-test, published-round
  generation checks, license checks and selected historical documentation checks.
- `baseline.py rust` runs Rust formatting, native/WASM clippy, independent module
  feature compilation and rustdoc. Compilation is not runtime coverage.
- `baseline.py browser` is a convenience sequence, not a sequence executed as a
  whole in this audit. The actual separate build/runtime commands and all attempts
  are retained in the report JSON.
- `environment.py` records tool versions, procedure hashes and pre-build artifact
  hashes. `artifact-bindings.py` binds fresh native/browser artifacts and local
  release tag mapping; a Git signature header is not signer verification.
- `provenance.py` compares exact dependency pins, vendored files, cached Cargo
  archive SHA-256 values and unpacked source bytes. It needs existing caches and
  reports missing caches as gaps; it does not install dependencies.
- `assemble.py` assembles the Markdown/JSON report from preserved evidence without
  rerunning tests. It verifies log hashes and unchanged source fingerprints and
  anonymizes published metadata while leaving local original logs untouched.
- `validate.py` checks the schema, paired findings, 32-item coverage, source/log/
  harness bindings, links, privacy and ignored evidence. It writes validation
  results and a local evidence checksum manifest without circular self-hashing.

```sh
python3 docs/audits/AUD-016-harnesses/assemble.py
./node_modules/.bin/prettier --ignore-path /dev/null --write docs/audits/audit-16-2026-10-09.md docs/audits/audit-16-2026-10-09.json
python3 docs/audits/AUD-016-harnesses/validate.py
```

## Expected results and limitations

The recorded baseline has eight confirmed findings (three Medium, five Low), with
two mandatory gates failing: three duplicated test blocks and stale real-browser
acceptance assertions. Four browser/mode pages produce 17 distinct failures each,
68 failed assertions total; duplicate diagnostic printouts are not additional
tests. One copy-gate finding overlaps concurrent AUD-017. Runtime boundary probes
can exit nonzero when they reproduce a finding; that is not a passing acceptance
check. Report assembly and validation should exit zero.

Library/CLI/metadata/doctest counts and passing smaller suites are recorded
separately. Original sandbox errors, harness mistakes, corrected attempts and
unsupported hypotheses remain visible. The scripts do not prove absence of
defects, production-cost KDF correctness, canonical reproducibility, full host UI
acceptance or historical external release asset binding. Harnesses are intended
to be retained with the audit; original evidence is ignored and remains local.
