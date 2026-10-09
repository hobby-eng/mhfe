# AUD-014 chosen-word audit harnesses

This targeted review covers MHFE bit insertion, checksum boundaries, constrained
sampling, statistical/unit tests and startup/full self-check wiring. The reviewed
base commit and dirty source hashes are recorded in the paired report. Only public
fixtures and synthetic inputs are used; no card generation or full-cost Argon2.

Run from the MHFE root with the existing pinned toolchain:

```sh
python3 docs/audits/AUD-014-harnesses/run.py initial snapshot
python3 docs/audits/AUD-014-harnesses/run.py LABEL COMMAND ARGUMENTS...
```

The recorder retains exact command, UTC times, exit and log SHA-256 in ignored
local `AUD-014-evidence/`. It samples its own process group's RSS and system
available memory every quarter second; 3 GiB RSS/2 GiB available reserve stops its
own group, and less than 3 GiB available refuses startup. Sampling is not a hard
allocation cap, may double-count shared pages and does not diagnose prior freezes.
Exit 75 means a memory-budget stop/refusal, not an application defect.

The snapshot hashes tracked/nonignored source files outside audit records, with
deletion markers, plus existing artifacts and the common procedure files. Test
additions authorized during the audit have a separate later snapshot. No production
generator changes or publication are authorized by this harness.

The `bits/`, `tests/` and `integration/` folders describe the independent public API
oracle, statistical counterexamples and worker/browser probes. The two race probes
are deliberately failing regressions on the reviewed runtime, not healthy gates.

After every recorded command is complete, capture `final snapshot`, then run
`python3 docs/audits/AUD-014-harnesses/assemble.py`. It requires the local evidence,
the existing Python `jsonschema` package and the authoritative common audit guide.
It assembles the paired report, validates its schema and IDs, checks all 32 ledger
items, rejects source changes outside the three authorized files, verifies source,
procedure and log hashes, and checks that evidence is ignored and not staged. It
writes local `report-validation.json` and `SHA256SUMS`; success exits zero, while a
failed assertion or schema check exits nonzero. Format the newly generated report
pair with the pinned Prettier; never reformat earlier reports.
Run the same assembler with `--validate-only` after formatting to validate without
rewriting either report. The index points to the generated pair.
