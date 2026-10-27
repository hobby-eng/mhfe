# Next release notes — draft

Record user-visible changes here as they are made. Before tagging, move them into
`docs/releases/v<version>.md`: the release workflow attaches that file as the text of the draft
release. Without it the canonical job fails before its build and no draft is made, while the macOS
builds and the CI checks of the same run, and `vectors.yml` for the tag, go on until they end or
are cancelled.

## Changed

- **Standard input and output without the standard library's buffers.** Secrets typed at the
  terminal, a script's answers on standard input and everything printed on standard output pass
  straight between the operating system and the program's own buffers, which are locked and wiped,
  instead of through the standard library's buffers, which keep their last contents for as long as
  the tool runs. What was typed at the terminal and not read when a hidden prompt or a list ends is
  discarded, so the rest of a paste never reaches the next answer or the shell. A script's answer
  that is not UTF-8 is now refused with exit code 2, as one typed at the terminal is. On Windows,
  Ctrl+Z is now kept as a character at every prompt, as on Linux and macOS; the standard library
  ended a typed answer at it or dropped it. A result that cannot be written, for example to a full
  disk, now ends the tool with exit code 1 and the reason, instead of a panic.
