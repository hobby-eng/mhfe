# verify-fastmode-tamper-doc

Audit AUD-024, commit b6fca69. Checks that `docs/BROWSER-PACKAGE.md` (shipped as the browser
package's `README.md`) does not list the page's `mhfe-fast-mode.sha256` as protection against
deliberate tampering. SECURITY.md says the checksum file catches a damaged, swapped or partly
updated page only, because whoever can change the page can change the checksum file too.

The harness first shows that precondition: it writes a replaced page and a checksum file made from
it, and both launchers (`mhfe serve` and `packaging/mhfe-fast-mode.py`) verify and serve it.

Inputs: an mhfe binary built from the commit (no Argon2 runs; `serve` stops after 3 s) and an
empty scratch folder. Python 3 and coreutils `sha256sum` and `timeout`.

Command, from the repository root:

    docs/audits/AUD-024-harnesses/verify-fastmode-tamper-doc/check.sh <mhfe binary> <work folder>

Expected output at b6fca69: both launchers report "verified and served", the bullet is printed,
then `FAIL: the guide lists mhfe-fast-mode.sha256 as tamper protection; ...`, exit 1. After a fix,
`PASS` and exit 0. Exit 2 means a precondition changed.
