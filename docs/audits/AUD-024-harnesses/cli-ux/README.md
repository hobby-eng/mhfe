# AUD-024 cli-ux harness

Audit AUD-024, role cli-ux, at commit `b6fca69238344dd2525b06270ee6ff3b055e68c1`.

`verify_cli_ux.py` checks eight behaviours of the `mhfe` command-line tool that the cli-ux findings describe. Each check drives the binary in a pseudo-terminal, or with standard input closed, with public test data only (the BIP39 "abandon ... about" phrase and the 24-word "abandon ... art" phrase), and stops it with Ctrl+C before any Argon2 round: no recovery, encryption or memory reservation is reached.

| Check | What passes |
| --- | --- |
| `dumb_terminal_asks_the_container_length` | `encrypt` at `TERM=dumb` asks the container length of a 12-word phrase |
| `dumb_terminal_explains_the_password` | `check` at `TERM=dumb` says that the container password is not a BIP39 passphrase |
| `a_pim_out_of_range_is_asked_again_at_once` | a PIM of 5000 typed at the settings question is refused before the memory level is asked |
| `wallets_asks_again_for_a_short_container` | `wallets` asks for the container again after a 12-word container instead of ending |
| `confirm_show_is_refused_before_the_container` | `rekey --confirm show` at `TERM=dumb` is refused before the container is asked |
| `a_phrase_argument_is_not_repeated` | the usage error of `mhfe decrypt "<phrase>"` does not repeat the phrase |
| `an_unknown_coin_reads_as_a_sentence` | `check --address --coin dogecoinz` is not refused with "unknown coin the coins are …" |
| `dumb_terminal_has_no_colour_with_ci_or_clicolor` | `repair-words` at `TERM=dumb` writes no colour sequence with `CI=true` or with `CLICOLOR=1` set |

Inputs: a built `mhfe` binary (a debug build is enough); Python 3 on Linux or macOS (the `pty` module).

Command, from the repository root:

```bash
python3 docs/audits/AUD-024-harnesses/cli-ux/verify_cli_ux.py <path to mhfe>
```

Expected output at b6fca69: eight `FAIL` lines, then `0 of 8 checks pass`, exit code 1. After the cli-ux findings are fixed: eight `PASS` lines, `8 of 8 checks pass`, exit code 0. The run of the audit is kept in `docs/audits/AUD-024-evidence/cli-ux/verify-cli-ux.log`.
