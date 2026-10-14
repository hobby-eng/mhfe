# AUD-024 verifier harness: facts the command-line tool works out again

Audit AUD-024, verifier of the candidate finding "The command-line tool works out again what
library types already say: the stage of a round, the Argon2 code the engine runs, and whether a
suite has a built-in check", reviewed commit `b6fca69238344dd2525b06270ee6ff3b055e68c1`.

What it checks, reading every file from the commit with `git show` (the working tree is not
used):

- Part 1. The progress bar's private `fn stage` (`src/bin/mhfe/terminal/progress.rs:131-137`) is
  copied verbatim into a small Rust program, with `ROUNDS` read from `src/suite.rs` and
  `ENCRYPTION_ROUNDS = 2 * ROUNDS` as `src/mhfe.rs:32` defines it. The program feeds it the rounds
  exactly as the library reports them with their `Stage`: `Encryption::run` (Encrypt 1-12, Check
  13-24 of 24), `SelfTest::replay` (Encrypt 1-12, Recover 13-24 of 24, as `src/self_test.rs:474-475`
  asserts) and `Rekey::seal` (Encrypt 13-24, Check 25-36 of 36), and counts the rounds whose bar
  name differs from the library's stage. It then checks the three caller lines that drop or
  renumber the library's rounds to fit the bar: `src/bin/mhfe/encrypt.rs:261`,
  `src/bin/mhfe/rekey.rs:422` and `src/bin/mhfe/self_test.rs:309`.
- Part 2. `src/bin/mhfe/test_tools.rs:350-361` (`argon2_engine`) runs its own
  `is_x86_feature_detected!("ssse3")`, has no "deliberate copy" marker, and types "4 threads"
  three times, while the engine's rule `processor_has_ssse3` (`src/engine/native.rs:34`) is
  `pub(super)` and so not reachable from the binary.
- Part 3. `src/bin/mhfe/terminal.rs:619` decides the "(no built-in check)" note from the `Suite`
  variant instead of `Suite::built_in_check_lengths` (`src/suite.rs:82-90`). This part records
  the code fact only: the verifier judged it an observation (a variant translated into display
  text), not a defect. Part 2 is a root cause of its own, separate from Part 1.

Inputs: none besides the repository at the commit. Needs `git` and `rustc` (1.99.0 was used). No
Argon2 runs, no cargo build, nothing is written outside the work directory.

## Running

From the repository root, with an optional commit (default b6fca69...) and work directory
(default `${TMPDIR:-/tmp}/aud024-verify-cli-derived-facts`):

```sh
docs/audits/AUD-024-harnesses/verify-cli-derived-facts/run.sh [commit] [work dir]
```

## Expected output at b6fca69

It exits 1 and ends with `9 of 9 checks show the defect` and `DEFECT REPRODUCED`. Part 1 prints

```
Encryption::run as reported: all 24 rounds named as the library's stage
SelfTest::replay as reported: 12 of 24 rounds named differently, first: library Recover round 13 of 24 -> bar "Checking"
Rekey::seal as reported: 24 of 24 rounds named differently, first: library Encrypt round 13 of 36 -> bar "Recovering"
rounds whose bar name differs from the library's stage: 36
```

that is, the bar names a stage correctly only for a 24-round encryption counted from 1, and the
self-test and the rekey get the right bars only because their callers renumber the rounds. Exit 0
(`DEFECT NOT REPRODUCED`) means none of the nine checks found the defect; exit 2 is a usage or
build error.
