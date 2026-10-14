# regression-aud023

Harness of audit AUD-024, role `regression-aud023` (the regression check of the 58 AUD-023
findings), reviewed commit b6fca69 (`b6fca69238344dd2525b06270ee6ff3b055e68c1`, branch
aud023-remediation).

## What it checks

`remediation_fix_sites.py` checks the AUD-023 remediation register
(`docs/audits/AUD-023-2026-10-13.json`, `remediation[].evidence`, whose text the Markdown table
repeats) against the fix commit `253ca3c38aef04f0f68c1cdb1130c14bfd2e7789`.

For 14 fix sites of 9 findings (API001, API002, UI001, UI005, BLD010, ARC005, ARC006, ARC016,
DOC001), each a line that the fix commit added to a file, it checks that:

1. the line was added by the fix commit (read in its diff; `src/wasm_api/core/search.rs` was
   `src/wasm_api/core.rs` in that commit, before df07f21 split it);
2. the line is still in the file at the reviewed commit;
3. the register's "Fixed in ..." list of the finding names the file.

It also prints how many "Fixed in" lists equal exactly the set of files outside `docs/audits/`
that mention the finding's ID at the reviewed commit.

It exits 0 when every fix site is named by the register, 1 when one is not, and 2 on a usage error,
an unreadable record, or a fix site that is not found (the harness then needs updating).

## Inputs

The git repository itself: the record and the files at the reviewed commit, and the diff of the fix
commit, read with `git show` and `git grep`. Nothing is built or run; no network.

## Command, from the repository root

```
python3 docs/audits/AUD-024-harnesses/regression-aud023/remediation_fix_sites.py b6fca69
```

## Expected output

Exit 0 once the register names the files that hold each fix. At b6fca69 it exits 1:

```
Register entries whose 'Fixed in' list equals the files that mention the ID (b6fca69):
  45 of 45
AUD-023-API001: web/client.js: fix line added by 253ca3c: True; present at b6fca69: True; register: NOT NAMED (lists ['scripts/package-check/client-refusals.mjs', 'scripts/package-check/core-operations.mjs'])
...
AUD-023-DOC001: src/bin/mhfe/diceware.rs: fix line added by 253ca3c: True; present at b6fca69: True; register: NOT NAMED (lists ['scripts/terminal_suite/full_size.py', 'src/bin/mhfe/container_repair.rs', 'src/bin/mhfe/main.rs'])
FAIL: 14 fix sites of 14 are missing from the register's 'Fixed in' lists
```
