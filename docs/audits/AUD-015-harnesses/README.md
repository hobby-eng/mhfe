# AUD-015 harnesses

Scripts of audit AUD-015 ([report](../audit-15-2026-10-09.md)), a full audit of mhfe with a compact
team. The reviewed source is commit `ca0086acf545d07bfe008ae340554124a48442bf` (before the privacy
rewrite during the review `4c3a6909bced0f0907f61ae291b11bb6bb419689`, with the same source files;
after the second privacy rewrite of the same day `abb16671b641378c0fc3c4d855f8d126498e754b`)
plus the uncommitted 0.5.1 working tree, source fingerprint
`f79444dc9884d11a54c2c0b316ce31bf3a3a734e5bb604e9667df09cf0482a93` (see the report). Run every
command from the repository root. Evidence goes to `docs/audits/AUD-015-evidence/`, which git
ignores.

- `run.py`: runs one command and keeps its log and record (argv, UTC start and end, exit code, log
  SHA-256): `python3 docs/audits/AUD-015-harnesses/run.py <label> <command...>`; exits with the
  command's code. `run.py snapshot <label>` writes the source manifest and its fingerprint.
- `baseline.sh`: the coordinator's baseline, the offline steps of `scripts/check.sh` under the
  owner's hold on long runs; needs the workspace toolchains (`workingspace/cargo`, `rustup`,
  `emsdk`) next to the repository, Node.js and Python 3. Expected: exit 0, about five minutes.
  The privacy redaction later replaced its absolute toolchain paths with the same paths derived
  from the workspace root.
- `assemble.py`: writes the report pair from its findings and the command records; anonymizes home
  paths. Expected: "wrote audit-15-2026-10-09.md and .json: 28 findings, 85 commands".
- `r1-crypto/`, `r2-cli/`, `r3-browser/`, `r4-wallet/`, `r5-build-docs/`: each reviewer's probes,
  with a README of their own that says what each checks, its inputs and its expected exit code. A
  probe exits 1 where it reproduces a defect named in the report.
