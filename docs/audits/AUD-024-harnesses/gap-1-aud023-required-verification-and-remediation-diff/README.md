# gap-1-aud023-required-verification-and-remediation-diff

Harnesses of audit AUD-024, role `gap-1-aud023-required-verification-and-remediation-diff`, for
reviewed commit b6fca69 (`b6fca69238344dd2525b06270ee6ff3b055e68c1`, branch aud023-remediation).
The role compared the required verification of 45 AUD-023 findings with the regression tests the
remediation (253ca3c to 64a4b99) added, and walked that diff for side effects. Each harness checks
whether a test can fail for the behaviour an AUD-023 fix promised, or whether a fixed behaviour
holds. None runs Argon2 at full size, uses a secret, or needs the network; the test data is public.

Run every command from the repository root. Each prints `GUARDED`/`PASS` and exits 0 when the
check holds, prints `NOT GUARDED`/`FAIL` and exits 1 when it does not, and exits 2 on a setup error.

## doc002_budget_guard.sh

AUD-023-DOC002. Restores, in a copy of the commit, the wait loop of `compare_candidates`
(`src/search.rs`) from before 253ca3c, which sleeps one progress interval before it looks whether
its workers ended, and runs `self_check::sets::tests::the_startup_set_stays_within_its_budget`:
once in a debug build, as `cargo test --locked` in the gates runs it (budget 30 s), and ten times in
a release build (budget 250 ms). The test's doc comment says the release budget makes that wait
fail.

Inputs: a scratch folder and a Cargo target folder of the harness's own. Do not give it the
target folder of builds of the real tree: Cargo names the artifacts of two copies of the package
alike, so a mutant built there is later taken for the real build.

```
docs/audits/AUD-024-harnesses/gap-1-aud023-required-verification-and-remediation-diff/doc002_budget_guard.sh \
  /home/user/Documents/bip_tools/tmp/aud024/gap-1/scratch \
  /home/user/Documents/bip_tools/tmp/aud024/gap-1/target-mutants
```

Expected at b6fca69: the debug run passes ("the test PASSES with the restored wait"), some release
runs pass with a startup set of about 248 to 263 ms against the 250 ms budget, `NOT GUARDED`,
exit 1.

## fun002_empty_passphrase_evidence.sh

AUD-023-FUN002, required verification "the empty-passphrase 16-bit pass keeps its evidence".
Builds a copy whose `evidence_of` (`src/rehearsal.rs`) drops a pass of the 16-bit check made with
the empty passphrase, then runs `cargo test --locked --lib` and `cargo test --locked --bin mhfe`
(reduced Argon2 cost).

```
docs/audits/AUD-024-harnesses/gap-1-aud023-required-verification-and-remediation-diff/fun002_empty_passphrase_evidence.sh \
  /home/user/Documents/bip_tools/tmp/aud024/gap-1/scratch \
  /home/user/Documents/bip_tools/tmp/aud024/gap-1/target-mutants
```

Expected at b6fca69: `test result: ok. 360 passed` and `test result: ok. 141 passed`,
`NOT GUARDED`, exit 1.

## arc017_response_deadline_hang.sh

AUD-023-ARC017, required verification "a removed Python response timeout must fail at least one
test". Copies `packaging/`, `scripts/verify-fast-mode-script.py`, `src/bin/mhfe/` and `Cargo.lock`
into a scratch tree, makes `answer()` of the Python launcher set no timeout, and runs
`Server.test_a_client_that_does_not_read_is_dropped_at_the_response_deadline` alone for at most 60 s.

```
docs/audits/AUD-024-harnesses/gap-1-aud023-required-verification-and-remediation-diff/arc017_response_deadline_hang.sh \
  /home/user/Documents/bip_tools/tmp/aud024/gap-1/scratch 60
```

Expected at b6fca69: `exit 124 after 60 s`, `NOT GUARDED: the test is still running after 60 s`,
exit 1.

## fun003_serve_nofile.py

AUD-023-FUN003, the cheap check its required verification names: `mhfe serve --no-browser` under
`prlimit --nofile=4:1024` on 127.0.0.1. Three connections it cannot accept, then about 2 s: its
processor time must stay below 0.5 s. Then `prlimit --pid` raises the soft limit to 64, and a GET of
`/` must return 200 with the page. Needs Linux and `prlimit` (util-linux).

```
python3 docs/audits/AUD-024-harnesses/gap-1-aud023-required-verification-and-remediation-diff/fun003_serve_nofile.py \
  target/release/mhfe
```

Expected at b6fca69 (release build of the commit): `cpu ticks 0`, `phase 2 reply head:
b'HTTP/1.1 200 OK'`, `PASS: no spin, and it serves once descriptors are available`, exit 0.
