# AUD-018 core release review

These checks belong to the pre-release review of the modified MHFE 0.5.1 tree based on commit
`3c60594479302827fe40975b04fd07f9f6fd4b3b`, initial non-audit fingerprint
`3ef3c5720216af0ed5dc7328c07d910bb82f99a90b28683ef88310af1a31c2b3`.

`source_identity.py` compares twelve crypto, parameter, engine and dependency files with the exact
SHA-256 values retained by AUD-016. It reads only repository files, needs Python 3 and no private
inputs, and executes neither Argon2 nor a test vector. Byte identity supports the claim that these
particular inputs did not change; it does not establish cryptographic correctness or unchanged
application behavior. Other source files changed and are reviewed separately.

Run from the MHFE repository root:

```sh
python3 docs/audits/AUD-018-harnesses/run.py core-source-identity \
  python3 docs/audits/AUD-018-harnesses/core/source_identity.py
```

Expect twelve `PASS` lines, zero failures and exit 0. A changed file causes exit 1 and shows its
actual digest. Logs and command records are local-only under `docs/audits/AUD-018-evidence/`.

The review also reuses the earlier read-only document scanners without copying them:

```sh
python3 docs/audits/AUD-018-harnesses/run.py core-record-fields \
  python3 docs/audits/AUD-015-harnesses/r5-build-docs/record_commit_fields.py
python3 docs/audits/AUD-018-harnesses/run.py core-record-prose \
  python3 docs/audits/AUD-017-harnesses/r4-build-docs/record_commit_prose.py
python3 docs/audits/AUD-018-harnesses/run.py core-doc-symbols \
  python3 docs/audits/AUD-015-harnesses/r5-build-docs/documented_symbols.py
python3 docs/audits/AUD-018-harnesses/run.py core-doc-links \
  python3 docs/audits/AUD-015-harnesses/r5-build-docs/markdown_links_lists.py
```

The historical commit scans can report third-party RustSec, Rust and Argon2 commits that are
correctly absent from the project checkouts, and intentionally retained original historical hashes.
Their nonzero exit codes require classification; they are not counts of confirmed findings.

The native cancellation regression reuses AUD-016's `core/public_probe.rs` and
`core/cancel_watchdog.py`, compiled by the coordinator against its freshly checked debug library.
Its public zero-entropy phrase and example Bitcoin address exercise a large native address scope,
with one CPU and a two-second deadline after cancellation is requested. No Argon2 or vector replay
is involved. The coordinator owns compilation and scheduling; the exact binary and command are
bound in the retained command record.

Full vector replay was expressly excluded by the owner, who stated that it had just been checked.
This is owner attestation, not a fresh AUD-018 execution result.
