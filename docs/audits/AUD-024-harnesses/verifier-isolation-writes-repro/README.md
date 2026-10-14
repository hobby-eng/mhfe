# Isolation writes, reproduced on the real binary (AUD-024 verifier)

Audit AUD-024, commit b6fca69238344dd2525b06270ee6ff3b055e68c1. Linux only.

What it checks: whether a secret command of the real `mhfe` binary, once isolated
(PR_SET_NO_NEW_PRIVS, its own user and network namespace, Landlock, seccomp), refuses every change
to the file system, as SECURITY.md ("a Landlock ruleset that refuses every write to the file
system") and the summary ("no new sockets or file writes (kernel-enforced)") state.
`preload.c`, loaded with LD_PRELOAD, stands for code running inside the isolated command: on the
first `write`/`writev` after no_new_privs is set it tries a socket, opening /dev/null and the target
for writing, creating a file (all expected refused), then setxattr, chmod, utimensat, truncate,
and fsetxattr and fchmod through a read-only descriptor. The script then reads the target back from
outside. `abi2-truncate.c` applies the mask that `src/bin/mhfe/protect/landlock.rs:48-63` builds on a
kernel of Landlock ABI 1 or 2 (Linux 5.13 to 6.1) and tries `truncate`.

Inputs: the mhfe release binary built at b6fca69 and a scratch folder on a file system with user
extended attributes (ext4, btrfs, xfs, tmpfs from Linux 6.6); a C compiler and python3. Public data
only: the attribute value is the BIP39 test phrase "abandon ... about". No Argon2 above the
startup checks' few MiB runs: `self-test` without `--vectors`, and `decrypt` refused for want of a
terminal before any round.

Command, from the repository root:

    CARGO_TARGET_DIR=<target> cargo build --locked --release
    docs/audits/AUD-024-harnesses/verifier-isolation-writes-repro/check.sh <target>/release/mhfe <scratch>

Expected output at b6fca69 (the defect): for both commands the socket, the opens and the file
creation are "refused (EACCES)", while setxattr, chmod, utimensat, fsetxattr and fchmod are
"ALLOWED"; afterwards both attributes hold the test phrase, the mode is 640 and the mtime
1000000000; with the ABI 1-2 mask truncate is "ALLOWED" (size 0). The script prints
"FAIL: a file-system change got through the isolation of a secret command" and exits 1. After a
fix it prints "PASS: every file-system change tried was refused" and exits 0.
