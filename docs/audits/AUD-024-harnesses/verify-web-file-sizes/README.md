# verify-web-file-sizes

Audit AUD-024, reviewed commit b6fca69 (b6fca69238344dd2525b06270ee6ff3b055e68c1).

What it checks: the size of the browser package's JavaScript files and classes against CORE-15
(800 lines per file) and WEB-02 (small classes per operation) of the workspace coding guide.

- `check-web-file-sizes.sh` fails (exit 1) when a `web/*.js` file has more than 800 lines, whatever
  `oxlint-disable max-lines` exception it carries, or when one of its exported classes spans more
  than 800 lines. It prints each file's size, its exception reason and its classes' spans.
- `facts.sh` prints the facts the finding cites from git objects of b6fca69: the sizes at 253ca3c^
  and b6fca69, the commits that changed the two files, every length exception of the tracked files,
  the exception texts, the span and public methods of MhfeClient, the top-level declarations of
  web/runtime.js, and the build lines that join seven source files into runtime/worker.js. It exits
  0; it is evidence, not a check.

Inputs: a checkout of the repository (git objects of b6fca69 and 253ca3c^ for `facts.sh`). No
build, network or secrets.

Commands, from the repository root:

    docs/audits/AUD-024-harnesses/verify-web-file-sizes/check-web-file-sizes.sh
    docs/audits/AUD-024-harnesses/verify-web-file-sizes/facts.sh

Expected output at b6fca69: `check-web-file-sizes.sh` exits 1 with `web/client.js 1541 lines`
(class MhfeClient: lines 188-1138, 951 lines, FAIL) and `web/runtime.js 1347 lines` (FAIL, its
largest class WorkerJob 267 lines), every other file under 800 lines. After a fix that splits both
files it exits 0. `facts.sh` lists 18 public methods of MhfeClient and the two exceptions as the
only length exceptions of the tracked files.
