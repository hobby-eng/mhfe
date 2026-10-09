# AUD-017 R2 harnesses: the command line

- `static_cli_rules.py` reads `src/bin/mhfe` and runs four checks:
  - S1: one source for the "built-in check finds N words" message.
  - S2: the rekey front end does not decide owner eligibility itself.
  - S3: the decrypt passphrase question has an option.
  - S4: the repair-word count has an option.
- It builds and runs nothing.
- Run it from the repository root:

  ```sh
  python3 docs/audits/AUD-017-harnesses/run.py r2-static-cli-rules python3 docs/audits/AUD-017-harnesses/r2-cli/static_cli_rules.py
  ```

- Expected on the reviewed tree: exit 1, with S1 to S4 reporting AUD-017-ARC001, ARC002 and UI001.
- Expected after the fixes: exit 0.
