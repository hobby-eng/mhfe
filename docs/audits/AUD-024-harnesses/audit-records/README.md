# AUD-024 audit-records harness

Checks of the audit records in `docs/audits/` for audit AUD-024 (CHECK-DOC-003), the expanded
full-scope audit of mhfe at commit `b6fca69238344dd2525b06270ee6ff3b055e68c1`. It reads the
records, git objects and the workspace audit procedure files and writes nothing.

## `check_records.py`

Inputs:

- the repository at commit `b6fca69`, with its git history (the fix commits AUD-023 names);
- the workspace procedure files in `../multi-chain-wallet-tools/` beside the repository
  (`docs/FULL_AUDIT_GUIDE.md`, `docs/audits/AUDIT_STANDARD.md`, `docs/audits/AUDIT_TEMPLATE.md`,
  `docs/audit-report.schema.json`), or another schema path given with `--schema`;
- Python 3 with `jsonschema` (only the `schema` check needs it) and git.

Run from the repository root, all checks or the ones named:

```sh
python3 -B docs/audits/AUD-024-harnesses/audit-records/check_records.py
python3 -B docs/audits/AUD-024-harnesses/audit-records/check_records.py pairs procedure
```

Each check prints one indented line per problem and then `<check>: ok` or `<check>: FAIL (<n>
problem(s))`. The script exits 1 when any selected check finds a problem and 0 otherwise; an
unknown check name exits 2 with the usage.

The checks:

- `schema`: every `AUD-NNN-*.json` validates against the schema.
- `pairs`: Markdown and JSON agree on the record's own finding and observation IDs and on the
  register's severities and statuses; where the Markdown says each row stays open until a commit
  records it, no JSON remediation entry is `fixed` or `verified` without a fix commit.
- `dates`: the date in the file name and in the JSON is the stated UTC completion date.
- `procedure`: each procedure SHA-256 a record pins is the current file's, or
  `docs/audits/procedure-changes.json` gives the reverse edit that recovers it.
- `links`: every relative Markdown link under `docs/audits/` reaches a file tracked in git; links
  into a record's own `AUD-NNN-evidence/` folder are skipped when the record labels them
  local-only.
- `harnesses`: every `AUD-NNN-harnesses/README.md` names its record's reviewed commit.
- `fixed-in`: the files that AUD-023's remediation rows call "Fixed in" exist at the row's fix
  commit.
- `refuted`: no candidate in a record's `refutedCandidates` has a verdict that kept a defect, an
  adjusted severity above `info`.

Expected output on commit `b6fca69`: `schema: ok`, and FAIL for the other seven checks, with 13,
1, 2, 22, 2, 22 and 2 problems (AUD-001 and AUD-017 pairs, the AUD-019 date, the AUDIT_STANDARD.md
and schema edits missing from `procedure-changes.json`, the six harness READMEs that link to
`audit-NN` report names and the links to the AUD-018 archives and the workspace procedure files,
the AUD-012 and AUD-014 READMEs, 22 AUD-023 "Fixed in" rows, and two AUD-023 refuted candidates);
exit code 1. After the records are corrected each check prints `ok` and the exit code is 0.
