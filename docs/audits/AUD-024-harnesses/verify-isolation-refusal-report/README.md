# verify-isolation-refusal-report

Audit AUD-024, commit b6fca69 (verifier of the candidate "an isolation restriction that the
kernel refuses is reported nowhere").

`refused_isolation.py` runs an mhfe binary four times (Linux x86-64 only): as it is, and under a
seccomp filter, installed in a forked child before exec, that makes one system call fail as a
kernel without the feature does:

- `landlock`: `landlock_create_ruleset` returns ENOSYS (a kernel without Landlock);
- `seccomp`: `prctl(PR_SET_SECCOMP, ...)` returns EINVAL (no seccomp filters);
- `unshare`: `unshare` returns EPERM (no user namespaces; documented as optional).

For each case it prints the "Isolation" row of `mhfe self-test` (standard input /dev/null) and the
output of `mhfe encrypt --pim 0 --mem 0 --same-length no --new-password own --repair-words 0` at
TERM=dumb in a pseudo-terminal, read up to the first secret prompt; that process is then killed.
Nothing is typed and no Argon2 round of the command runs. Public data only; no network.

Input: the path of a release mhfe binary built at b6fca69.

Command, from the repository root:

    python3 -B docs/audits/AUD-024-harnesses/verify-isolation-refusal-report/refused_isolation.py <path to mhfe>

Expected output at b6fca69 (defect present): exit 1, ending in `DEFECT REPRODUCED`; in the
`landlock` case the self-test row reads `Isolation ... enforced` and the encrypt summary reads
`Isolation  isolated network, no new sockets (kernel-enforced)` with no warning. After a fix it
exits 0 (`DEFECT NOT REPRODUCED`): the self-test row carries a "!" or the output names the
unrestricted file writes.
