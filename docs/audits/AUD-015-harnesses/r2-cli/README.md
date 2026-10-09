# AUD-015 R2: native command-line tool probes

Probes of reviewer R2 of AUD-015 (the `mhfe` command-line tool, `src/bin/mhfe/`), against the
reviewed snapshot: HEAD `4c3a6909bced0f0907f61ae291b11bb6bb419689` plus the uncommitted tree whose
source fingerprint is recorded in the audit's snapshot. They drive the built tool in a Linux
pseudo-terminal with Python's standard library only.

Inputs: a built tool (default `target/release/mhfe`, or the path given as the only argument), the
public zero-12 vector `tests/fixtures/suite3-vectors/zero-12.json`, synthetic passwords and pages.
Nothing secret is used. Every run gets an address space of 1 GiB (`RLIMIT_AS`), so no probe can
reach the 2 GiB of full-cost Argon2; each stops the tool before any memory is reserved. Run them one
at a time from the repository root, through the audit's runner:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 docs/audits/AUD-015-harnesses/run.py r2-<label> \
  python3 docs/audits/AUD-015-harnesses/r2-cli/<probe>.py target/release/mhfe
```

Each probe checks the behaviour the documents promise and exits 1 when it does not hold, printing
`FAIL (defect reproduced)`; it exits 0 with `PASS` lines when it holds. So a probe of a reported
defect keeps failing until the defect is fixed.

| Probe                        | What it checks                                                                                                                                                                   | Expected now    |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
| `serve_checksum_name.py`     | `mhfe serve`: escape sequences in the page name of `mhfe-fast-mode.sha256` are not written raw to the terminal (in colour and with `NO_COLOR`)                                     | 1 (colour mode) |
| `public_answer_echo.py`      | `mhfe check --fingerprint`: a refused fingerprint with escape sequences is not echoed raw, as a script (`--stdin`) and at the terminal                                            | 1               |
| `search_reference_record.py` | the reference of a search for a missing word: neither typed escape sequences nor a mistyped seed phrase reach the main-screen summary                                             | 1               |
| `made_password_dumb.py`      | `mhfe encrypt --new-password words` with `TERM=dumb`: the made password appears only on an alternate screen                                                                      | 1               |
| `hint_rows_narrow.py`        | the word hint below a typed line keeps the cursor on the line, at 80 columns (control) and 32 columns                                                                           | 1 (32 columns)  |
| `quit_key_private_screen.py` | Ctrl+\\ (SIGQUIT) at a line-mode prompt of `mhfe new` while the chosen word is on the private screen; reported, SECURITY.md promises clearing only on acceptance and Ctrl+C       | 1               |
| `serve_live.py`              | `mhfe serve` over its real 127.0.0.1 socket: loopback bind, Host check, headers, 404/405/400, the 16-connection cap and the 10-second deadline, no request log                      | 0               |
| `menu_isolation.py`          | the Isolation line of a command started from the menu (seccomp and Landlock) and of one started directly (with the network namespace)                                            | 0               |

`pty_session.py` is the shared helper: the pseudo-terminal session and a small VT100 screen model
that replays the output (cursor up, column, erase, pending wrap) to see where characters land.
