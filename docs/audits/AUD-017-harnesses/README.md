# AUD-017 harnesses

These are the scripts of audit AUD-017 ([report](../audit-17-2026-10-09.md)), a compact audit of mhfe.

- The reviewed source is commit `3c60594479302827fe40975b04fd07f9f6fd4b3b` plus the uncommitted 0.5.1 working tree, with source fingerprint `b2addb366a3bda36ed23bb84f68a2c92550b0c0f7c533d366894a8664963cbc7`.
- No script builds anything or runs full-size Argon2.
- Run every command from the repository root.
- Evidence goes to `docs/audits/AUD-017-evidence/`, which git ignores.

The scripts:

- `run.py` runs one command and keeps its log and record: the argv, the UTC start and end, the exit code and the log's SHA-256.
  - Usage: `python3 docs/audits/AUD-017-harnesses/run.py <label> <command...>`.
  - It exits with the command's exit code.
  - `run.py snapshot <label>` writes the source manifest and its fingerprint.
- `assemble.py` writes the report pair from its findings and the command records, with home paths anonymized.
  - Expected output: "wrote audit-17-2026-10-09.md and .json: 12 findings, N commands".
- `r1-crypto/`, `r2-cli/`, `r3-browser/` and `r4-build-docs/` hold each reviewer's probes.
  - Each folder has its own README that says what each probe checks, what it needs and which exit code to expect.
  - A probe exits 1 when it reproduces a defect named in the report.
