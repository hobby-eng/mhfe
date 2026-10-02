# Next release notes — draft

Record user-visible changes here as they are made. Before tagging, move them into
`docs/releases/v<version>.md`: the release workflow publishes that file as the release text and
stops at once if it is missing.

Planned as version 0.5.0.

- **Containers of the same length (suite 4, `MHFE-BIP39-LP-EXPERIMENTAL-4`).** For a phrase of 12,
  15, 18 or 21 words, `mhfe encrypt` now asks how long the container should be: 24 words, the
  recommended default, or the same length as the phrase. `?` explains both; `--same-length`
  chooses the same length without asking. Such a container keeps the backup's length but has no
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
- Without `--pim` or `--mem`, `mhfe encrypt`, `decrypt` and `check` ask at a terminal whether to
  keep the defaults, PIM 0 and memory level 0, which come first, or to type their own. The question
  explains what the two settings change and that recovery needs them again; the memory level is
  asked with the highest one this computer can use. The start menu's commands thereby reach every
  setting.
- Suite 4 test vectors in `tests/fixtures/suite4-vectors/` with fast refusal cases, an independent
  check with `scripts/independent-suite4.py`, and the replay `tests/suite4_vectors.rs`. The full
  replay of both vector sets runs for a release or on request, no longer on every push.
- Rust 1.99.0, Node.js 26.10.0 in the build container and CI, and current crates and actions.
- One program for every x86-64 computer instead of two. It uses SSSE3, 7 to 10% faster, where the
  processor has it and SSE2 otherwise, so the separate `ssse3` archives and the "processor not
  supported" refusal (`PROCESSOR_NOT_SUPPORTED`, exit code 4) are gone.
