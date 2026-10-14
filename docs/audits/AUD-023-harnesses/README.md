# AUD-023 harnesses

Scripts of audit [AUD-023](../AUD-023-2026-10-13.md), a full audit of mhfe at commit
`e8dca53a5d17cb80f1f5ac1f5a40b351f939e7e7` plus the uncommitted changes the report names (source
fingerprint in the report). Run them from the repository root.

## baseline.sh

Runs the repository's own gates once, one after another:

- `check`: `scripts/check.sh`;
- `browsers`: `scripts/verify-browsers.mjs`;
- `canonical`: an uncached `scripts/build-reproducible.sh` into `canonical-output-aud023/`.

Each step holds a shared lock file, so that no other heavy job of the audit runs beside it. It
also runs under a kernel memory limit (`systemd-run --user --scope`, 6 GiB by default). Each step
writes `docs/audits/AUD-023-evidence/baseline-<step>.log` and a `.command.json` record with the
command, the UTC start and end, the exit code and the log's SHA-256. Full-cost vector replays are
not part of it.

Inputs:

- the toolchains of the workspace: Rust 1.99.0 with `CARGO_HOME` and `RUSTUP_HOME` under
  `../workingspace`, Emscripten 6.0.12 in `../workingspace/emsdk`, Node.js 26.10.0, Playwright
  1.64.0 with its Chromium and Firefox, and Docker;
- about 6 GiB of free memory.

```sh
docs/audits/AUD-023-harnesses/baseline.sh            # all three steps
docs/audits/AUD-023-harnesses/baseline.sh canonical  # one step
```

`AUD023_LOCK` names another lock file and `AUD023_MEMORY_MAX` another limit. Expected output:
`<step> exit 0` for each step and exit code 0; any failing step gives exit code 1.

## assemble.py

Writes the report pair `docs/audits/AUD-023-<date>.md` and `.json`. It reads the audit's retained
material in `docs/audits/AUD-023-evidence/`:

- the workflow result (`workflow-result.json`);
- the normalized finding records and the informational observations;
- the baseline records;
- the procedure hashes, the environment and the snapshot manifests;
- `canonical-output-aud023/release/SHA256SUMS`.

Every home directory is written as `/home/user`; every time is UTC.

```sh
python3 docs/audits/AUD-023-harnesses/assemble.py 2026-10-13
```

Expected output: one line naming the two files with the counts of findings and observations, and
exit code 0. The evidence folder is local and not committed, so a reader without it can rerun
`baseline.sh` but not reproduce the agents' review material.
