# AUD-024 harness: tooling conformance (guide-tooling-other)

Audit AUD-024, role guide-tooling-other, reviewed commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1`. It re-checks six tooling defects of that review; each
check prints `PASS` when the repository behaves as the cited rule wants and `DEFECT` otherwise:

1. **blame-revs gate**: the `.git-blame-ignore-revs` loop of `scripts/check.sh`, run on a scratch
   file, must refuse what `git blame --ignore-revs-file` refuses (an abbreviated hash, a ref name).
2. **empty or mistyped command lines**: `scripts/generate-cell-widths.py --chek`, run from a scratch
   copy whose table lies in a temporary folder, must not rewrite the table and must exit non-zero;
   `independent-suite3.py vector`, `independent-suite3.py passwords`,
   `independent-suite4.py validation` and `independent-suite4.py vector` without a file must exit
   non-zero.
3. **checks under PYTHONOPTIMIZE**: `independent-suite3.py vector --trust-argon2-keys` must refuse a
   copy of the public vector `zero-12.json` with one changed round mask also when
   `PYTHONOPTIMIZE=1` removes `assert` statements.
4. **checksum file with a lone CR**: `packaging/mhfe-fast-mode.py` must refuse a checksum file
   `"\r<digest>  tool.html\n"`, as `mhfe serve` does; with a program path, `mhfe serve
   --no-browser` is run on the same folder for comparison (stopped after 3 seconds if it serves).
5. **unreadable file in --builder-paths**: `scripts/check-release-artifacts.sh --builder-paths` must
   fail on a scratch file that names the repository's directory and cannot be read (skipped as
   root).
6. **archive reader copy**: the Python embedded in `scripts/check-release-artifacts.sh` must hold no
   function whose body is the same as one of `scripts/third-party-licenses.py` without a
   "deliberate copy" comment.

Inputs: public test data only (`tests/fixtures/suite3-vectors/zero-12.json`, a public test page).
Needs Python 3.11 or later with the packages of `scripts/independent-suite3-requirements.txt` on
`PYTHONPATH` (for check 3), git with the full history (check 1), and optionally a built `mhfe`.
It writes only to temporary folders and runs no Argon2 at full cost.

## Running

From the repository root:

```sh
PYTHONPATH=<folder with cryptography and unicodedata2> \
  docs/audits/AUD-024-harnesses/guide-tooling-other/run.sh [path/to/mhfe]
```

## Expected output at b6fca69

Exit code 1 and:

```text
DEFECT  blame-revs gate: lines the gate accepts and git blame refuses: ['f6067310e5ac', 'HEAD~3']
DEFECT  empty or mistyped command lines: generate-cell-widths.py --chek rewrote its table and exited 0; independent-suite3.py vector with no file exited 0; independent-suite3.py passwords with no file exited 0; independent-suite4.py validation with no file exited 0; independent-suite4.py vector with no file exited 0
DEFECT  checks under PYTHONOPTIMIZE: a vector with a changed mask was reported reproduced
DEFECT  checksum file with a lone CR: Python launcher serves; mhfe serve refuses with exit 2
DEFECT  unreadable file in --builder-paths: exit 0: No file names a directory of this builder: 1 checked.
DEFECT  archive reader copy: check-release-artifacts.sh members() = third-party-licenses.py archive_files()
6 of 6 checks found their defect
```

After the fixes every line reads `PASS` and the script exits 0.
