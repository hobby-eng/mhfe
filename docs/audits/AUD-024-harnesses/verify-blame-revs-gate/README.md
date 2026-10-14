# .git-blame-ignore-revs check against git blame

Audit AUD-024, at commit b6fca69 (branch aud023-remediation). This is the verifier's harness for
the finding about the check that `scripts/check.sh` runs on `.git-blame-ignore-revs`, added for
AUD-023-ARC012.

## What it checks

The check should refuse exactly the lists that git blame refuses. The harness takes the check's
loop from `scripts/check.sh`, from `while read -r hash; do` to
`done < <(grep -Ev '^(#|$)' .git-blame-ignore-revs)`, and replaces only the file name. It runs that
loop under `set -euo pipefail` on scratch lists. It runs
`git blame --ignore-revs-file <list> -- README.md` and
`git -c blame.ignoreRevsFile=<list> blame -- README.md` on the same lists. Each case reads PASS
when the check and git blame agree, and DEFECT when they do not.

The cases:

- the full hash of the reformat;
- the same hash shortened to 12 and to 7 digits;
- `HEAD~3`;
- the tag `v0.6.0`;
- the full hash followed by `# comment`;
- the full hash with a CRLF line ending;
- an indented `#` comment;
- a missing file.

## Inputs

- A full clone of the repository, since the check refuses a shallow one.
- Git. The run used git 2.53.0.
- `AUD024_SCRATCH`: a folder for the scratch lists. It is optional; by default the harness uses a
  new `mktemp -d` folder. The harness writes nothing in the repository.

## Command

From the repository root:

```sh
docs/audits/AUD-024-harnesses/verify-blame-revs-gate/run.sh
```

## Expected output

At b6fca69 the harness exits 1. The full hash reads PASS. Every other case reads DEFECT:

- The check accepts the abbreviated hashes, `HEAD~3` and `v0.6.0`, and git blame stops with
  `fatal: invalid object name`.
- The check refuses the trailing comment, the CRLF line and the indented comment, and git blame
  accepts them.
- The check accepts a missing file, and git blame stops with `could not open object name list`.

After a fix every line reads PASS and the harness exits 0. It exits 2 when it cannot find the loop
in `scripts/check.sh`.
