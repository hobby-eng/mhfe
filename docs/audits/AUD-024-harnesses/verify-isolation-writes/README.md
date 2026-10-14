# AUD-024 verifier: isolation-writes on the real binary

Audit AUD-024, commit `b6fca69238344dd2525b06270ee6ff3b055e68c1`. Confirms, on the real `mhfe`
release binary rather than on its modules compiled alone, that a secret command isolated by
`protect::isolate` (no_new_privs, user and network namespace, Landlock, seccomp) can still change
the file system through calls Landlock does not handle.

`hook.c` is preloaded (`LD_PRELOAD`) into `mhfe encrypt --stdin --pim 0 --mem 0`. On the first read
of standard input, which comes after the isolation, it prints `NoNewPrivs` and `Seccomp` from
`/proc/self/status`, then tries from inside the isolated process: opening `/dev/null` for writing
(the tool's own probe), a UDP socket, opening the scratch file for writing, `setxattr` by path and
`fsetxattr` on a descriptor opened read-only (both holding the public BIP39 test phrase "abandon ...
about"), `chmod 0644`, `utimensat` and `truncate`. The command is then fed three words, which it
refuses before any Argon2 round (exit status 2). `run.sh` reads back from outside what reached the
file.

Inputs: a release build of `mhfe` at b6fca69 (`cargo build --locked --release`), a scratch folder
on a file system with user extended attributes (ext4, btrfs, xfs; tmpfs from Linux 6.6), Linux with
Landlock, gcc and Python 3.

Command, from the repository root:

```sh
docs/audits/AUD-024-harnesses/verify-isolation-writes/run.sh <mhfe> <scratch>
```

Expected at b6fca69 (Linux 7.0, Landlock ABI 8): the summary line `Isolation  isolated network, no
new sockets or file writes (kernel-enforced)`, `NoNewPrivs: 1`, `Seccomp: 2`; the `/dev/null` open,
the socket, the open for writing and `truncate` refused with errno 13; `setxattr`, `fsetxattr`,
`chmod` and `utimensat` ALLOWED; afterwards mode 644, mtime 1000000000 and both attributes holding
the test phrase; then `FAIL: the isolated secret command changed the file system ...` and exit 1.
Exit 0 (`PASS`) once every change is refused.
