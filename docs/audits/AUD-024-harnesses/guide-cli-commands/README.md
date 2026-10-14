# Command modules against the coding guide (AUD-024, commit b6fca69)

Audit AUD-024, role guide-cli-commands: conformance of the command modules of `src/bin/mhfe/` with
the coding guide (`code-core` CORE-10, CORE-14, CORE-39, CORE-41, CORE-42; `code-rust` RUST-13), at
commit b6fca69238344dd2525b06270ee6ff3b055e68c1. Every harness exits 0 when its check holds and 1
when it fails; at b6fca69 each of them fails, which is the evidence of a finding. None changes a
tracked file, and none runs Argon2 beyond the checks at start of the tool.

Inputs: public test data only, the "abandon ... about" phrase and the container of
`tests/fixtures/suite3-vectors/zero-12.json`, the words "zoo", "zooo" and the string "public test
password". The binary is a release build of commit b6fca69 made with
`CARGO_TARGET_DIR=/home/user/Documents/bip_tools/tmp/aud024/target cargo build --locked --release --bin mhfe`.
The pseudo-terminal harnesses use the helpers of `scripts/terminal_suite/session.py` (Linux or
macOS, Python 3).

## mutant.sh

Copies HEAD with `git archive` into `<scratch>/mutant` (the working tree is not touched), moves
library constants to other valid values (`MAX_PIM` 1023 to 1000, `MAX_MEMORY_LEVEL` 21 to 20,
`DEFAULT_WORDS` 5 to 6, `RECOMMENDED_REPAIR_WORDS` 4 to 6), renames the self-check ids
`random-source` and `memory-locking`, adds two tests that print the rendered helps and the
self-test verdict of every part's id, and runs the CLI's guard tests on the copy
(`every_help_states_the_limits_of_the_constants`, `each_outcome_reads_as_its_kind`,
`chars_alone_means_the_default`). It checks that no rendered help keeps a stale value and that the
renamed checks keep their verdict words.

```sh
CARGO_TARGET_DIR=/home/user/Documents/bip_tools/tmp/aud024/target \
  docs/audits/AUD-024-harnesses/guide-cli-commands/mutant.sh /home/user/Documents/bip_tools/tmp/aud024/guide-cli-commands
```

Expected output at b6fca69: the guard tests pass on the mutant ("GUARD PASSED ON THE MUTANT"), six
"STALE:" lines (`rekey --new-pim` keeps "0 to 1023", `--new-mem` keeps "0 to 21", the
`--new-password` help says "five dice words" beside the bits of six, the `repair-words` example
keeps "Four repair words, the recommended number", and the renamed checks read "as published /
NOT as published"), exit code 1.

## check_reference_options.py

Reads the answers of `mhfe check`'s reference question for the zero-12 container in a
pseudo-terminal (stopped with Ctrl+C after the password, before the recovery) and the options of
`mhfe check --help`, and requires an option for each answer (CORE-41).

```sh
python3 docs/audits/AUD-024-harnesses/guide-cli-commands/check_reference_options.py /home/user/Documents/bip_tools/tmp/aud024/target/release/mhfe
```

Expected output at b6fca69: four answers offered, "FAIL: the answer 'The phrase + passphrase check'
has no command-line option", the clap refusal of `check --stdin` without `--address`,
`--fingerprint` or `--words`, exit code 1.

## chosen_word_answers.py

Drives `mhfe new --pim 0 --mem 0 --wallet-check no --repair-words 0` in a pseudo-terminal: case A
types the chosen word "zoo" at position 25, case B at position 24 with "zooo" as the word never to
use. A refused answer must be asked again at once, keeping the earlier ones (CORE-42). Each session
ends with Ctrl+C before anything is drawn.

```sh
python3 docs/audits/AUD-024-harnesses/guide-cli-commands/chosen_word_answers.py /home/user/Documents/bip_tools/tmp/aud024/target/release/mhfe
```

Expected output at b6fca69: "FAIL A1" (position 25 accepted, the word never to use asked next),
"FAIL A2" (the refusal returns to "Do you want to choose a word of the new phrase?"), "FAIL A3"
(the chosen word is asked for again), "FAIL B", exit code 1.

## password_prompt_explained.py

Types the zero-12 phrase into `mhfe encrypt --pim 0 --mem 0 --same-length no --repair-words 0
--new-password own` at TERM=xterm-256color and at TERM=dumb, stopping with Ctrl+C at the container
password prompt, and requires the prompt to say what the password does (CORE-39).

```sh
python3 docs/audits/AUD-024-harnesses/guide-cli-commands/password_prompt_explained.py /home/user/Documents/bip_tools/tmp/aud024/target/release/mhfe
```

Expected output at b6fca69: the sentence "The container password encrypts your phrase; it is NOT a
BIP39 passphrase." at TERM=xterm-256color and not at TERM=dumb, "FAIL: at TERM=dumb ...", exit
code 1.

The logs of these runs are in `docs/audits/AUD-024-evidence/guide-cli-commands/`.
