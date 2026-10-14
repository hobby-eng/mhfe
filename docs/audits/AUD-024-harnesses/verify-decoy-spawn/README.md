# AUD-024 verify-decoy-spawn harness

Audit AUD-024, verifier role verify-decoy-spawn, reviewed commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1`.

What it checks: the missing-word search with the container's own wallet
(`ContainerSearch::search_decoy`, which calls `compare_candidates` in `src/search.rs`) when the
system refuses a new thread. `compare_candidates` starts one worker per core, up to the candidate
count, with `std::thread::Scope::spawn`, which panics when the system refuses the thread. The
wallet-check draw (`src/wallet_check/threads.rs`) uses `Builder::spawn_scoped` and goes on with
the threads it got, and is the contrast.

`run.sh` runs four cases, each inside a systemd user scope with a pids limit (`TasksMax`):

1. `probe/` (library, public API, release profile with `panic = "abort"` as in the tool's own
   release profile): `search_decoy` on "abandon" x23 "art" with the last word typed as `?` and its
   fingerprint, under `TasksMax=4`. Expected after a fix: `decoy search: Ok(Some([(24, "art")]))`.
   `probe/ twelve` (not run by `run.sh`) does the same with the 12-word "abandon" x11 "about",
   whose last word leaves 128 candidates, so the search starts one worker per core.
2. `probe/ draw`: `PhraseDraw::draw_on_every_core` under the same limit (contrast; passes today).
3. The tool's start: `mhfe check --fingerprint --pim 0` with standard input from `/dev/null` under
   `TasksMax=8`. Expected after a fix: no "Self-test at start failed" (the command then refuses the
   missing terminal, exit 2).
4. `cli_decoy.py`: drives `mhfe check --fingerprint --pim 0` on a pseudo-terminal through the
   terminal suite's `Session`, as `check_container_search` in `scripts/terminal_suite/repair.py`
   does: zero-12's container phrase with word 24 typed as `?`, Enter at the repair words, "The
   container's own wallet", the published decoy fingerprint `487a156e`, no passphrase; under
   `TasksMax=9`. It never types a password: it ends the tool with Ctrl+C at the next question.
   Expected after a fix: `Found word 24: peace`.

Inputs: public test data only (the "abandon ... art" phrase, zero-12 from
`tests/fixtures/suite3-vectors`). Needs cargo with Rust 1.99.0 and the crates already fetched
(`--offline`), python3, and `systemd-run --user` with the pids controller. No network. No Argon2 at
suite cost: the start-up checks run at their reduced cost, and no password is ever typed.

The limits 8 and 9 assume a machine with at least 8 cores, so that the search starts 8 workers for
the 8 candidates (at start the self-check needs 1 + 8 tasks; in the command the Ctrl+C thread adds
one). On fewer cores the search starts fewer workers; lower the limits accordingly.

## Running

From the repository root (`CARGO_TARGET_DIR` is honoured; default
`${TMPDIR:-/tmp}/aud024-verify-decoy-spawn-target`):

```sh
docs/audits/AUD-024-harnesses/verify-decoy-spawn/run.sh
```

## Expected output at b6fca69

Exit 1, with these lines:

```text
FAIL library: the decoy search ended with exit 134 when a thread was refused
PASS contrast: the wallet-check draw goes on with the threads it got
FAIL CLI start: a thread limit is reported as a failed self-test (exit 1)
FAIL CLI search: the decoy search did not finish under TasksMax=9
```

Each FAIL shows `failed to spawn thread: Os { code: 11, kind: WouldBlock, ... }` from
`std/src/thread/scoped.rs`, or "Self-test at start failed: Search for missing words: the program
stopped." Once the search goes on with the threads it got, all four lines pass and it exits 0.
