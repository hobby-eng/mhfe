# AUD-044 harnesses

Probes of audit AUD-044 of mhfe. The report is [`../AUD-044-2026-11-01.md`](../AUD-044-2026-11-01.md).
They ran against the tree `37a0d4fe6d0819bc654d69c69afbe693bd72d450`, public test data only.

- `run-logged.sh <evidence folder> <name> <command...>` runs one command and keeps its output, exact
  command, UTC times, exit code and the SHA-256 of its log. It exits with the command's code.
- `fun/`: scripts for each functional finding, with its own README. `fun/reduced-cli` and `fun/probes`
  build the command-line tool over a reduced-cost core, so that a whole run takes seconds.
- `sec/`: `scenario.sh` runs the release program in a pseudo-terminal and scans its memory at a prompt
  through the preloaded `memscan.c`; `raw-facts.py` reads the terminal's raw stream.
- `bld/`, `arc-doc/`: searches of the tree behind their findings.

Run them from the repository root. Each exits non-zero when its check fails, and against the fixed
tree a probe of a fixed finding reports the fixed behaviour. A harness that needs a program takes its
path as an argument.

One probe of the first run, `failed-part-lost`, ran under Node.js and is not kept: the repository has
no Node.js. Its result stands in the report, and the failure it showed is covered by the fix's code.
