# Same-length container consequences (AUD-024, commit b6fca69)

Audit AUD-024, verifier of the candidate "the command-line tool shows the consequences of a
same-length container without the two that the specification makes mandatory", at commit
b6fca69238344dd2525b06270ee6ff3b055e68c1.

## What it checks

`probe.py` drives the `mhfe` binary in a pseudo-terminal (the helpers of
`scripts/terminal_suite/session.py`) and through pipes, and looks in what a person is shown for the
two statements that mhfe_spec/README.md:669-671 makes mandatory for suite 4: that a mistyped
password **or setting** is not detected and opens another valid wallet, and that the container
reveals the original phrase's word count. SECURITY.md:184-195 says the tool shows these
consequences, a wrong PIM or memory level included, before the choice.

Cases, each stopped before any Argon2 work (Ctrl+C at the repair-word question or the password
prompt, or a refused script input):

- A1: `mhfe encrypt --pim 0` at a terminal, the container-length list before any key.
- A2: the same, after key 2 (the same length), up to the repair-word question.
- B: the same list after `?`.
- C: `mhfe encrypt --pim 0 --same-length` at a terminal, up to the repair-word question.
- D: `mhfe rekey --pim 0` with the published same-length-zero-12 container, up to the password
  prompt.
- E: `mhfe encrypt --help`, the text of `--same-length`.
- F: `mhfe encrypt --stdin --same-length` with two different password lines (refused with exit 2).

## Inputs

Public test data only: the phrase of tests/fixtures/suite3-vectors/zero-12.json (the "abandon ...
about" phrase) and the container of tests/fixtures/suite4-vectors/same-length-zero-12.json. The
password lines are the public strings "public test password one" and "... two". The binary is a
release build of commit b6fca69 made with CARGO_TARGET_DIR=/home/user/Documents/bip_tools/tmp/aud024/target.

## Command (from the repository root)

```sh
python3 docs/audits/AUD-024-harnesses/verify-same-length-consequences/probe.py /home/user/Documents/bip_tools/tmp/aud024/target/release/mhfe
```

## Expected output

The checks state the specification's requirement. At b6fca69 the probe exits 1 with 12 failed
checks: the word count is said only after `?` (B) and in `--help` (E); the undetected wrong setting
is said nowhere (A2, B, C, D, E, F); only "A wrong password will not be detected: it opens another
12-word wallet." follows the choice (A2, C, F). A fixed tool exits 0 and prints "all checks hold"
(the A1 "before the choice" checks also need the consequences on the list itself, as SECURITY.md
says; a fix that keeps them behind `?` and after the choice must relax A1 and record why).

Evidence of the run at b6fca69: docs/audits/AUD-024-evidence/verify-same-length-consequences/probe.log
and probe.command.json.
