# verify-cgroup-usage

Audit AUD-024, reviewed commit b6fca69 (branch aud023-remediation). Adversarial verification of the candidate finding "With a cgroup limit readable but its usage unreadable, the memory figure is 0 bytes instead of none".

## What it checks

`src/engine/cgroup.rs:28-29` documents `available_bytes` as giving `None` "without a limit or where the figures cannot be read". The check passes when a control group whose limit can be read but whose usage cannot gives no free-memory figure, so that MHFE does not refuse a memory level for lack of memory it never measured.

- `unit`: builds, with `rustc --test`, a copy of the reviewed `src/engine/cgroup.rs` with `probe.rs` appended as a child module, so the probe calls the module's private `available_with` with the module's own fake-file technique. The module's seven tests run too. Cases: a readable control (v2, `memory.max` 8 GiB, `memory.current` 1 GiB), v2 with `memory.max` 8 GiB and no `memory.current`, and v1 with `hierarchical_memory_limit` 8 GiB and no `memory.usage_in_bytes`.
- `e2e`: runs the real `mhfe` binary in a private user and mount namespace (`unshare -Urm`). The process's own cgroup v2 group shows a bind-mounted `memory.max` of 8 GiB and a `memory.current` of mode 000, and capabilities are dropped (`setpriv`), so reading it fails with "Permission denied". The command is `mhfe decrypt --stdin --pim 0 --mem 0 </dev/null`. It ends before any Argon2 round: refused for memory, or at the empty standard input. There are three runs: a readable `memory.current` (1 GiB) as the control, an unreadable `memory.current` with the real `memory.stat`, and both files unreadable. Nothing outside the private namespace changes.

## Inputs

- `CARGO_TARGET_DIR`: a folder outside the repository (required).
- `MHFE_BIN` (e2e only): the `mhfe` binary, by default `$CARGO_TARGET_DIR/debug/mhfe`, built from this commit with `cargo build --locked --bin mhfe`.
- `TMPDIR`: where the temporary work folder goes (removed at exit).
- e2e needs Linux with cgroup v2, the process in a non-root group, unprivileged user namespaces, `unshare` and `setpriv`.

## Commands, from the repository root

```sh
CARGO_TARGET_DIR=/home/user/.../tmp/aud024/target TMPDIR=/home/user/.../tmp/aud024/verify-cgroup-usage \
  docs/audits/AUD-024-harnesses/verify-cgroup-usage/run.sh unit
CARGO_TARGET_DIR=/home/user/.../tmp/aud024/target TMPDIR=/home/user/.../tmp/aud024/verify-cgroup-usage \
  docs/audits/AUD-024-harnesses/verify-cgroup-usage/run.sh e2e
```

## Expected output

When the defect is fixed, both checks exit 0. `unit` ends with `test result: ok. 10 passed`. In `e2e`, the two runs with an unreadable `memory.current` end like the control, with `Standard input ended before this answer` and `mhfe exit 2`, followed by `OK`.

At b6fca69:

- `unit` exits 101. It prints `v2, max 8 GiB, memory.current unreadable: Some(0)` and `v1, limit 8 GiB, memory.usage_in_bytes unreadable: Some(0)`, and 2 of its 10 tests fail.
- `e2e` exits 1. The control ends with `mhfe exit 2` at the empty standard input. With only `memory.current` unreadable, the refusal is `This memory level needs 2 GiB of memory, but only 0.6 GiB is available` and `mhfe exit 4`. That figure is the group's `inactive_file`, about 0.65 GiB on the audit machine. With `memory.stat` unreadable as well, it is `but only 0 GiB is available` and `mhfe exit 4`. The check then prints `FAIL: ...`.
- An exit code of 2 from `e2e` means the result is inconclusive: the control run was refused for memory too, or the environment does not fit.

Evidence logs: `docs/audits/AUD-024-evidence/verify-cgroup-usage/unit.log` and `e2e.log`.
