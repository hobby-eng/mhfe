# PEP 8 line lengths of the Python tooling (AUD-024, TOOL-04)

Audit AUD-024, reviewed commit b6fca69238344dd2525b06270ee6ff3b055e68c1.

What it checks: TOOL-04 ("Python follows PEP 8") against PEP 8's "Maximum Line Length" section.
For every tracked `.py` file outside `docs/audits/` at the given commit (read with `git show`, so
the working tree does not matter) it counts, in characters: lines over 79, over 99 and over 100;
comment-only lines and docstring lines over 72; inline comments on lines over 79; and lines over 79
that contain a URL. PEP 8 allows 79 characters, or up to 99 where a team agrees, with comments and
docstrings still wrapped at 72.

Inputs: the commit to read (first argument). Needs only `git` and Python 3 (standard library).

Command, from the repository root:

    python3 docs/audits/AUD-024-harnesses/verifier-pep8-lines/pep8-line-lengths.py b6fca69238344dd2525b06270ee6ff3b055e68c1

Expected output at b6fca69: a per-file table and the line
`TOTAL | 5898 | 1528 | 58 | 27 | 273 | 537 | 1 | 4`
(5,898 lines in 20 files; 1,528 over 79; 58 over 99; 27 over 100; 273 comment-only lines and 537
docstring lines over 72), and exit status 1. It exits 0 only when no line is over 99 and no
comment-only or docstring line is over 72.
