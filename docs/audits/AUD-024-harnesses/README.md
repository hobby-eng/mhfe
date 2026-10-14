# AUD-024 harnesses

Scripts of audit AUD-024, the expanded full-scope audit of mhfe at commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1`. Run them from the repository root on that commit. They
read the repository and write evidence only to the folder they are given, which for the audit was
`docs/audits/AUD-024-evidence/` (local and git-ignored).

## `run-logged.sh`

Runs one command and keeps its evidence: `<name>.log` with the output and `<name>.command.json`
with the exact command, the UTC start and end, the exit code and the SHA-256 of the log. It exits
with the command's exit code.

```sh
docs/audits/AUD-024-harnesses/run-logged.sh <evidence folder> <name> <command> [arguments...]
```

## `baseline.sh`

The audit's baseline checks, one after another through `run-logged.sh` (names `b01-…` to
`b26-…`): `scripts/check-fast.sh`, the vendored Argon2 gate, the licence and generated-table
checks, `cargo doc` with warnings as errors, the release build and the terminal suite's fast cases,
a fresh browser package with `verify-argon2-wasm.mjs`, `verify-browser-package.mjs`,
`verify-single-modules.mjs`, the CLI/browser parity, the fast-mode launcher check, the
release-artifact and archive-packing checks, the browser suite in Chromium and Firefox, the
independent checkers' fast modes, `cargo audit` and `pnpm audit`. It also writes
`dist-SHA256SUMS`, the hashes of the browser package it built.

```sh
PYTHONPATH=<folder with the packages of scripts/independent-suite3-requirements.txt> \
  docs/audits/AUD-024-harnesses/baseline.sh docs/audits/AUD-024-evidence
```

It needs the toolchains of `AGENTS.md`, Emscripten 6.0.12 in `../workingspace/emsdk`, the
browsers of `pnpm exec playwright install chromium firefox`, and network access for `cargo audit`
and `pnpm audit`. Full-size Argon2 work (the vector replays, the terminal suite's `--full` cases,
the independent checkers' full runs) and the canonical Docker build are not part of it. A failed
check does not stop the others; the script prints one line per check and exits 1 if any failed,
0 otherwise.

Subfolders, where present, hold the probes a reviewer of the audit kept; each has its own README.
