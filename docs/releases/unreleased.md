# Next release notes — draft

Record user-visible changes here as they are made. Before tagging, move them into
`docs/releases/v<version>.md`: the release workflow publishes that file as the release text and
stops at once if it is missing.

Planned as version 0.5.0.

- **Containers of the same length (suite 4, `MHFE-BIP39-LP-EXPERIMENTAL-4`).** For a phrase of 12,
  15, 18 or 21 words, `mhfe encrypt` now asks how long the container should be: 24 words, the
  recommended default, or the same length as the phrase. The question links to the README's
  section on the choice, `?` compares both, and `--same-length` chooses the same length without
  asking. Such a container keeps the backup's length but has no
  built-in check: a wrong password gives another valid phrase, the container shows the phrase's
  length, and a miscopied word passes its shorter checksum more often. `mhfe decrypt` and
  `mhfe check` recognise it by its word count; a recovered phrase from it is always shown as not
  verified, and `mhfe check` compares it with an address or the fingerprint. The browser package
  takes `sameLength: true` and reports `suiteId`; its API version is 7.
- A chosen original length now admits only a 24-word container or a same-length container of exactly
  that length, and a selected suite only its own containers; everything else is refused before any
  Argon2 work, as the specification's recovery table requires. New error codes:
  `SAME_LENGTH_NEEDS_SHORT_PHRASE`, `LENGTH_CHOICE_NOT_APPLICABLE` and `NO_BUILT_IN_CHECK`.
- The format of a container (its suite identifier) is shown after an encryption and when a container
  is read, instead of at the start.
- Questions are answered from lists, as in the menu: the arrow keys and Enter, or an answer's
  number at once; Escape cancels (q too, where the keyboard has it). This replaces the typed
  `y`/`n` answers of `mhfe encrypt` and the typed choice of `mhfe check`. Laid out as in MnemoCode,
  each question stands apart with a short explanation, and once answered it gives way to one line
  of a summary. Scripts (`--stdin`) answer as before.
- `mhfe rekey` puts the same seed phrase into a new container under a new password or new
  settings. It encrypts again only once the recovery is confirmed: by the built-in check at the
  length the owner states, or, for a 24-word phrase or a same-length container, by an address or
  the fingerprint of the wallet or by the owner, who sees the phrase on a private screen and
  compares it with their backup. The library offers this as
  `Mhfe::recover_confirmed`, with the new error codes `REFERENCE_REQUIRED` and
  `REFERENCE_MISMATCH`. It warns every time that wallets of other passwords on the old container
  change, and that the old container stays valid until it is destroyed. The start menu offers it.
- `mhfe password --chars N` makes N random characters (16 by default, about 93.3 bits) from 57
  letters and digits without look-alikes, instead of dice words.
- `mhfe encrypt` estimates the strength of a typed password and warns below about 50 bits, instead
  of warning whenever it is not four dice words. The estimate needs no dependency: it reads the
  password as words of the EFF and BIP39 lists, common passwords, years, repeats, runs and keyboard
  rows, with letter substitutions, and the README states what it can overrate.
- The start menu's password generator repeats on Enter and returns to the menu on Escape. Each
  password replaces the previous one on the private screen, which is cleared when leaving.
- Secrets are typed on a private screen, the terminal's alternate screen, which shows them as they
  are typed and is cleared as soon as they are accepted, with no question to confirm them: a
  mistyped word is refused by the word list or the checksum. This replaces the hidden prompts and
  the questions whether to show the words or the password. A container typed for a recovery or a
  check is read the same way. The new container and a recovered seed phrase are shown on a private
  screen too, which Enter or Escape clears once they are written down. Each answered step gives
  way to one line of a summary on the main screen, and warnings stand apart, so that the next
  question is always at the bottom.
- Screens keep to short lines while a command runs. Explanations moved to the README, whose
  commands now have sections of their own, and a grey "More:" line links to the section that
  explains a question, a warning or a result. After an encryption, two lines say what to keep and
  what to do next.
- The program and its documents say "seed phrase" where they said "recovery phrase", so that it
  is not confused with recovering one: `mhfe decrypt` is now "Recover a seed phrase".
- Secrets stay out of core dumps and swap: the tool forbids core dumps and, on Linux, other
  programs of the same user from reading its memory; it keeps the password, the phrases and a BIP39
  passphrase in locked memory, and marks Argon2's work area to be left out of a dump. On Linux it
  warns before any secret is typed when swap is not encrypted.
- On Linux the kernel enforces that `encrypt`, `decrypt`, `check`, `rekey` and `password` stay
  offline and write no file: seccomp refuses sockets and Landlock refuses file writes, for every
  thread the command starts. The summary shows it; the start menu runs each command in an isolated thread.
- `mhfe check` compares with a receiving address of twelve coins instead of Bitcoin alone: Bitcoin,
  Ethereum and every EVM network, XRP, Tron, Zcash (transparent), Dogecoin, Bitcoin Cash, Litecoin,
  Ethereum Classic, Cosmos, Injective and Dash, for Dash both Core `X…` and Platform payment
  `dash1k…` addresses (DIP17 and DIP18, checked against their official vectors). It asks for the
  coin, listed alphabetically, or takes `--coin`, and shows before the check the address type and
  the paths it searches. Shielded Zcash and Dash addresses are refused with that reason. The
  browser package takes `reference: { address, coin }`. One new dependency, `sha3`, gives
  Keccak-256.
- On a match with a receiving address, `mhfe check` shows where it was found, such as
  `m/49'/0'/0'/0/5`: which account and address of the wallet it is. The library's `check` returns a
  `CheckOutcome` with that path, and the browser package's `check` resolves to `{ matches, path }`.
- Without `--pim` or `--mem`, `mhfe encrypt`, `decrypt` and `check` ask at a terminal whether to
  keep the defaults, PIM 0 and memory level 0, which come first, or to type their own. The question
  links to the README's section on both settings instead of explaining them; the memory level is
  asked with the highest one this computer can use. The start menu's commands thereby reach every
  setting.
- Suite 4 test vectors in `tests/fixtures/suite4-vectors/` with fast refusal cases, an independent
  check with `scripts/independent-suite4.py`, and the replay `tests/suite4_vectors.rs`. The full
  replay of both vector sets runs for a release or on request, no longer on every push.
- Rust 1.99.0, Node.js 26.10.0 in the build container and CI, and current crates and actions.
- One program for every x86-64 computer instead of two. It uses SSSE3, 7 to 10% faster, where the
  processor has it and SSE2 otherwise, so the separate `ssse3` archives and the "processor not
  supported" refusal (`PROCESSOR_NOT_SUPPORTED`, exit code 4) are gone.
