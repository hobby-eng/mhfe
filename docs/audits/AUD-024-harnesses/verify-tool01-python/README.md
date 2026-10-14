# TOOL-01 language-choice check (AUD-024 verifier)

Audit AUD-024, at commit b6fca69 (`b6fca69238344dd2525b06270ee6ff3b055e68c1`). This harness checks
TOOL-01 of `.github/instructions/code-tooling.instructions.md`: scripts are Node.js `.mjs`, Python
is kept for independent reimplementations or for a library only Python has, and shell is a thin
wrapper that calls other tools.

`check-tool01.mjs` makes three checks and prints PASS or FAIL for each:

1. `generator-imports`: `scripts/generate-published-rounds.py` imports only `json`, `sys` and
   `pathlib`, which Node.js's standard library covers, and names no Python-only library. FAIL
   means the generator has no reason that TOOL-01 accepts for Python. The check passes when the
   file no longer exists, for example after a port to `.mjs`.
2. `node-port`: the generator's job, rewritten with Node.js's standard library alone, renders
   `src/mhfe/published_rounds.rs` byte for byte. PASS shows that the job needs nothing that only
   Python has.
3. `shell-python`: no tracked shell script outside `docs/audits/` carries a Python program, either
   a heredoc fed to `python3` or a multi-line `python3 -c`. FAIL lists each program with its
   lines.

## Inputs

These are read from the checkout: `scripts/generate-published-rounds.py`,
`tests/fixtures/suite3-vectors/*.json`, `tests/fixtures/suite4-vectors/*.json`,
`src/mhfe/published_rounds.rs` and every `*.sh` that `git ls-files` lists. It needs Node.js and
git. It writes nothing and uses no network.

## Command (from the repository root)

```sh
node docs/audits/AUD-024-harnesses/verify-tool01-python/check-tool01.mjs
```

## Expected output at b6fca69 (exit code 1)

```text
FAIL generator-imports: scripts/generate-published-rounds.py imports import json (:15), import sys (:16), from pathlib import Path (:17); modules outside json/sys/pathlib: none; names unicodedata: false; docstring says "it computes nothing": true
PASS node-port: a Node.js standard-library port (node:fs, node:path, JSON.parse, Buffer) renders 27 vectors, 89422 bytes; committed src/mhfe/published_rounds.rs has 89422 bytes; identical: true
FAIL shell-python:
  scripts/build-reproducible.sh:8-12 heredoc, 3 lines of Python
  scripts/check-release-artifacts.sh:78-110 heredoc, 31 lines of Python
  scripts/check-release-artifacts.sh:125-132 python3 -c, 7 lines of Python
  scripts/verify-archive-packing.sh:52-73 heredoc, 20 lines of Python
```

Once TOOL-01 holds, all three lines read PASS and the exit code is 0.

## Remediation continuation

The current harness also accepts the generator filename changing from `.py` to `.mjs` in its
header comment. It normalizes that one label before the independent renderer compares every
other byte. The retained baseline log above is unchanged. The continuation separately compares
the pre-port table bytes and executes the new generator's `--check`, including a drift control.
