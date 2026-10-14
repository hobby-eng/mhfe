# AUD-024 verifier harness: what the secret prompts say

Audit AUD-024, verifier of the finding "At TERM=dumb, and where a secret prompt opens inside
another private screen, the container password, new password and BIP39 passphrase prompts do not
say what the secret is" (guide rule CORE-39), at commit `b6fca69238344dd2525b06270ee6ff3b055e68c1`.

Two scripts drive the `mhfe` binary in a pseudo-terminal with public test data only (the 24-word
"abandon ... art" container, the 12-word "abandon ... about" phrase, the BIP39 test-vector
passphrase "TREZOR"). Every run ends with Ctrl+C at a secret prompt, before the memory reservation
and any Argon2 round.

| Script | What it checks |
| --- | --- |
| `dumb_terminal_prompts.py` | At `TERM=dumb`: the container password prompt and the BIP39 passphrase prompt of `mhfe check --words auto --passphrase-used yes --pim 0 --mem 0`, and the container password prompt of `mhfe encrypt --pim 0 --mem 0`, are preceded by their explanation ("it is NOT a BIP39 passphrase", "it is NOT the container password"). The same `check` run at `TERM=xterm-256color` is printed for comparison. |
| `nested_search_prompts.py` | At `TERM=xterm-256color`, `mhfe decrypt --pim 0 --mem 0` with a word typed as `?`, no repair words and "The original seed phrase's passphrase": the search's BIP39 passphrase prompt and container password prompt carry their explanations with standard output on the terminal and with standard output redirected to /dev/null. |

Inputs: a built `mhfe` binary (debug or release); Python 3 on Linux or macOS (the `pty` module).

Commands, from the repository root:

```bash
python3 -B docs/audits/AUD-024-harnesses/verify-secret-prompt-explanations/dumb_terminal_prompts.py <path to mhfe>
python3 -B docs/audits/AUD-024-harnesses/verify-secret-prompt-explanations/nested_search_prompts.py <path to mhfe>
```

Expected output at b6fca69: `dumb_terminal_prompts.py` prints `explained=False` for the three
`TERM=dumb` prompts and `explained=True` for the two `TERM=xterm-256color` prompts, then
`prompts without their explanation at TERM=dumb: 3`, exit code 1. `nested_search_prompts.py` prints
`explained=True` for both prompts with standard output on the terminal and `explained=False` for
both with standard output on /dev/null, exit code 1. After the fix: every line `explained=True`,
`prompts without their explanation at TERM=dumb: 0`, both exit code 0. The runs of the audit are
kept in `docs/audits/AUD-024-evidence/verify-dumb-secret-explanation/`.
