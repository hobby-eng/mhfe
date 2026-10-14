# AUD-024 verify-reproduction harnesses

Harnesses of the reproduction verifier of audit AUD-024, written for commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1`. They back the finding that every message on standard
error is written with anstream 1.0.0's `eprint!`/`eprintln!`, which panic on a write error other
than a broken pipe, so that the release build (`panic = "abort"`) ends with SIGABRT (status 134)
and runs none of its cleanup. Each exits 1 while the defect is there and 0 once it is fixed. At
b6fca69 both exit 1. Public test data only: the BIP39 phrase "abandon" x 23 + "art", the words
"not a phrase" and the Down arrow key. No command runs Argon2 beyond the checks at start.

Inputs: `<mhfe>` is a release build of the tool at the commit under test
(`cargo build --locked --release`, with a target folder outside the repository), `<scratch>` a
folder for temporary files. Linux, Python 3 and gcc. Run from the repository root.

## stderr_shim_run.sh

Builds `stderr_shim.c`, an `LD_PRELOAD` shim that makes every write to standard error fail with
ENOSPC, as `/dev/full` does, and copies the bytes the tool tried to write to a log (mhfe's
`PR_SET_DUMPABLE 0` keeps strace from reading them). Runs `password`, `repair-words --stdin --count
4`, `encrypt --stdin --pim 0 --mem 0` with three words, and `encrypt --no-such-option`, and prints
each exit status and the panic text with its source location.

```sh
docs/audits/AUD-024-harnesses/verify-reproduction/stderr_shim_run.sh <mhfe> <scratch>
```

Expected at b6fca69: exit 134 for all four (documented: 0 for password and repair-words, 2 for
the other two); `panicked at src/bin/mhfe/style.rs:88:5: failed printing to stderr: No space left on
device (os error 28)` for the first three, `src/bin/mhfe/main.rs:291:5` for the usage error; then
`FAIL: 4 of 4 commands aborted (SIGABRT, 134) on a failing standard error` and exit 1.

## menu_list_pty.py

Starts `mhfe` without arguments in a pseudo-terminal: standard input is the terminal opened
blocking, standard output and error the same terminal opened again with `O_NONBLOCK`. At the start
menu, which reads keys with the terminal switched to single keys without echo, it stops reading and
sends the Down arrow until the terminal's output buffer is full and a write returns EAGAIN. Reports
the exit status and the terminal's echo and line mode afterwards.

```sh
python3 -B docs/audits/AUD-024-harnesses/verify-reproduction/menu_list_pty.py <mhfe>
```

Expected at b6fca69: `menu shown: True`, `exit status: -6 (SIGABRT)`, `terminal left with echo:
False, line mode: False`, then a `FAIL:` line and exit 1. With the watch mode of the shim
(`SHIM_MODE=watch`) the panic is at `src/bin/mhfe/style.rs:210:9` (`style::hint`, called by the
menu's `draw` inside `hidden_input::with_keys`).
