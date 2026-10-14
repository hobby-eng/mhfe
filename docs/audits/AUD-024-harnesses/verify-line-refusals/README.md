# line_refusals_after_answer.py (AUD-024, verifier)

Audit AUD-024 at commit b6fca69. Checks how the native `mhfe` refuses a typed line that cannot be
an answer: a line that is not UTF-8 or longer than the 8,192-byte line buffer.

What it runs, all with public data only (the 12-word "abandon ... about" test phrase); no password
is ever accepted, so no encryption round runs, only the startup checks:

- T1 to T4 in a pseudo-terminal, `mhfe encrypt --pim 0 --mem 0 --same-length no --new-password own
  --repair-words 0`: T1 the byte 0xff and Enter at the first prompt; T2 8,193 letters at the first
  prompt; T3 the accepted test phrase, then 0xff and Enter at the "Container password" prompt;
  T4 (control) the accepted test phrase, then an empty line at that prompt.
- S1 to S3 with `--stdin`: S1 a phrase line 0xff; S2 the test phrase, then a password line 0xff;
  S3 (control) a phrase line of 8,192 letters.

Input: the path of an `mhfe` release binary built from the commit.

Command, from the repository root:

    python3 -B docs/audits/AUD-024-harnesses/verify-line-refusals/line_refusals_after_answer.py <mhfe>

Expected output at b6fca69 (the defect): T1, T2 and T3 end the command with exit 2 and no second
prompt; T4 asks again ("The password is empty. Please choose another.") and is still running;
S1 and S2 exit 1 with "Input or output failed: stream did not contain valid UTF-8"; S3 exits 2.
The last line is "DEFECT REPRODUCED" and the exit status is 1. Once fixed (T1 to T3 ask again,
S1 and S2 exit 2), it prints "DEFECT NOT REPRODUCED" and exits 0.
