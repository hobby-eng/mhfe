# Help texts against the library constants (AUD-024, commit b6fca69)

Audit AUD-024, adversarial verifier `verify-help-constants`, at commit
b6fca69238344dd2525b06270ee6ff3b055e68c1. It checks the candidate finding that help texts of the
command modules still type values the library defines as constants (CORE-10, CORE-18; the
incomplete fix of AUD-023-ARC007), and that the guard test
`every_help_states_the_limits_of_the_constants` (src/bin/mhfe/main.rs:471-529) passes when those
values drift.

## probe.sh

Copies HEAD with `git archive` into `<scratch>/mutant` (the working tree is not touched), moves
four library constants to other valid values (`MAX_PIM` 1023 to 1000, `MAX_MEMORY_LEVEL` 21 to 20,
`DEFAULT_WORDS` 5 to 6, `RECOMMENDED_REPAIR_WORDS` 4 to 6), adds one test that prints the rendered
`-h` and `--help` of `rekey`, `repair-words` and `encrypt`, and runs that test and the guard test
with `cargo test --locked --bin mhfe`. No Argon2 is run.

Inputs: none besides the repository at HEAD. The build goes to the shared audit target.

Command, from the repository root:

```sh
CARGO_TARGET_DIR=/home/user/Documents/bip_tools/tmp/aud024/target \
  docs/audits/AUD-024-harnesses/verify-help-constants/probe.sh /home/user/Documents/bip_tools/tmp/aud024/verify-help-constants
```

Exit codes: 0 when no rendered help keeps a stale value or the guard test fails on the drift; 1
when the guard test passes while a rendered help keeps a stale value; 2 on a setup or build error.

Expected output at b6fca69: "test result: ok. 2 passed", "guard test ... passed on the mutant:
True", the four controls True (the derived `--pim`, `--mem` and `--new-mem` long helps and the bits
follow the mutated constants), four `STALE:` lines (`rekey --new-pim` keeps "0 to 1023",
`--new-mem` keeps "0 to 21", the `--new-password` help says "five dice words" beside 77.6 bits,
the `repair-words` example keeps "Four repair words, the recommended number"), "4 stale help
texts", exit code 1.

## typed-values.sh

Renders `-h` and `--help` of a built mhfe (clap prints the help before any command starts, so no
Argon2 runs) and lists 20 help texts that state, as typed text, a value the library or the tool
defines as a constant: the rekey `--new-pim`, `--new-mem` and `--words` short helps, the
`--new-password` long help, the round counts of decrypt, encrypt, check and self-test, the 12- to
21-word lengths of encrypt, check and rekey `--confirm`, the memory sizes of the examples, the
self-test `--vectors` short help, the repair-words example, the EFF list size and two examples of
the top-level help. For each it prints the source line at HEAD (`git grep`) that types it.

Inputs: a release build of HEAD, made with
`CARGO_TARGET_DIR=/home/user/Documents/bip_tools/tmp/aud024/target cargo build --locked --release --bin mhfe`.

Command, from the repository root:

```sh
docs/audits/AUD-024-harnesses/verify-help-constants/typed-values.sh /home/user/Documents/bip_tools/tmp/aud024/target/release/mhfe
```

Exit codes: 0 when no listed text is found, 1 when at least one is, 2 on a setup error.

Expected output at b6fca69: 20 `TYPED:` lines, from the rekey `--new-pim` short help "PIM of the
new container, 0 to 1023 (default 0)" (src/bin/mhfe/rekey.rs:46) to the top-level example "Make a
strong password of five dice words" (src/bin/mhfe/main.rs:181), then "20 help texts type a value
that a library constant defines", exit code 1.
