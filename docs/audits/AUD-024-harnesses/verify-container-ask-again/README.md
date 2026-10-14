# AUD-024 verifier harness: a container or phrase the command cannot use

Audit AUD-024, verifier role `verify-container-ask-again`, at commit `b6fca69238344dd2525b06270ee6ff3b055e68c1`.

`check_container_ask_again.py` checks the coding guide's CORE-42 (a wrong or unusable answer is explained and asked again; a command ends only on Escape, Ctrl+C or a critical self-test failure) for a container or seed phrase that is valid but that the command cannot use, typed at a terminal. Each terminal case starts `mhfe` in a pseudo-terminal, types one answer and passes when the command is still running 10 seconds later (it asked again or went on to its next question); it fails when the command has ended by itself. A running command is then stopped with Ctrl+C, before any Argon2 round: no recovery, encryption or memory reservation is reached.

| Check | Command and answer |
| --- | --- |
| `control_wallets_with_a_24_word_container` | `wallets --pim 0 --mem 0`, the 24-word "abandon ... art" phrase as the container (passes at b6fca69: a control) |
| `wallets_with_a_12_word_container` | `wallets --pim 0 --mem 0`, the 12-word "abandon ... about" phrase as the container |
| `encrypt_same_length_with_a_24_word_phrase` | `encrypt --same-length --pim 0 --mem 0`, the 24-word phrase as the original |
| `decrypt_words_15_with_a_12_word_container` | `decrypt --words 15 --pim 0 --mem 0`, the 12-word phrase as the container |
| `check_words_15_with_a_12_word_container` | `check --words 15 --pim 0 --mem 0`, the 12-word phrase as the container |
| `rekey_words_15_with_a_12_word_container` | `rekey --words 15 --pim 0 --mem 0`, the 12-word phrase as the container |
| `script_encrypt_same_length_24_still_exits_2` | `encrypt --same-length --stdin`: a script, which cannot be asked again, still ends with exit code 2 and no output |

Inputs: a built `mhfe` binary (a debug build is enough); Python 3 on Linux or macOS (the `pty` module). Public test data only.

Command, from the repository root:

```bash
python3 docs/audits/AUD-024-harnesses/verify-container-ask-again/check_container_ask_again.py <path to mhfe>
```

Expected output at b6fca69: `PASS` for the control and the script case, `FAIL ... ended by itself with exit code 2` for the five terminal cases, then `2 of 7 checks pass` and exit code 1. After the finding is fixed: seven `PASS` lines, `7 of 7 checks pass`, exit code 0. The audit's run is kept in `docs/audits/AUD-024-evidence/verify-container-ask-again/harness-container-ask-again.log`.
