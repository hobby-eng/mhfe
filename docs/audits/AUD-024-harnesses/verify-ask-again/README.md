# Ask again, keeping earlier answers (AUD-024, verifier)

Audit AUD-024, commit b6fca69238344dd2525b06270ee6ff3b055e68c1. This harness checks CORE-42 ("A wrong
or unusable answer is explained in one line and asked again, keeping earlier answers") for two
groups of questions of the native `mhfe` tool:

- the person's own settings (`settings::ask_own`, src/bin/mhfe/settings.rs:249-300), reached from
  every command when neither `--pim` nor `--mem` is given and "Other settings" or "My own PIM and
  memory level" is chosen;
- the chosen word and the word never to use of `mhfe new` (`chosen_words::ask`,
  src/bin/mhfe/chosen_words.rs:88-133).

`check_ask_again.py` drives the binary in a pseudo-terminal. Each case types one wrong answer
among valid ones and passes only when the refusal is shown and the same question is asked again,
with no earlier question asked again:

| Case | Answers typed | Passes when |
| --- | --- | --- |
| `a_refused_level_keeps_the_pim` | `decrypt`, Other settings, PIM 0, level 22 | the level is refused and asked again, the PIM is not |
| `a_level_above_this_computer_keeps_the_pim` | the same with a level one above the highest shown | the same (not applicable, counted as passed, where no highest level below 21 is shown) |
| `a_pim_out_of_range_is_refused_when_typed` | PIM 5000 | the PIM is refused and asked again before the level is asked |
| `a_refused_position_keeps_the_chosen_word` | `new ... --choose-word yes --never-use zoo`, chosen word abandon, position 0 | the position is refused and asked again, the chosen word is not |
| `a_refused_never_use_word_keeps_the_chosen_word` | `new ... --choose-word yes`, abandon, position 1, never-use word xyzzy | the never-use word is refused and asked again, the chosen word is not |

Every case stops the program with Ctrl+C before any Argon2 round; nothing is encrypted, recovered
or reserved. Public test data only.

## Inputs

One argument: the `mhfe` binary to test, built from the tree under review. Do not take it from a
target directory that other probes also build mutant copies of the repository into: cargo gives
every copy the same output names and may report the mutant build fresh for the clean tree.

## Command (from the repository root)

```
python3 docs/audits/AUD-024-harnesses/verify-ask-again/check_ask_again.py target/release/mhfe
```

## Expected output

At b6fca69 every case fails, and the harness exits 1:

```
FAIL a_refused_level_keeps_the_pim
FAIL a_level_above_this_computer_keeps_the_pim
FAIL a_pim_out_of_range_is_refused_when_typed
FAIL a_refused_position_keeps_the_chosen_word
FAIL a_refused_never_use_word_keeps_the_chosen_word
```

After a fix every line reads PASS and the harness exits 0. The evidence of the run at b6fca69 is
docs/audits/AUD-024-evidence/verify-ask-again/harness-baseline-release.log.
