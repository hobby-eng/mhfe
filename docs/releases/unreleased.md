# Next release notes — draft

Record user-visible changes here as they are made. Before tagging, move them into
`docs/releases/v<version>.md`: the release workflow attaches that file as the text of the draft
release. Without it the canonical job fails before its build and no draft is made, while the macOS
builds and the CI checks of the same run, and `vectors.yml` for the tag, go on until they end or
are cancelled.

## Changed

- The rehearsal check reports one of the specification's three results: "matches", "does not
  match" or "not verified". "Not verified" is a 24-word reading without an address or fingerprint,
  which a wrong password gives too, or several lengths that pass their built-in checks with none of
  them stated; MHFE lists those lengths. A pass of the 16-bit phrase + passphrase check is reported
  beside the result and no longer counts as a match. `mhfe check --stdin` prints "not verified"
  with the new exit code 5. In the browser package `check()` resolves to `outcome` ("matches",
  "notVerified" or "doesNotMatch") in place of `matches`, `evidence.matchingLengths` lists the
  lengths, and `onNoLength` receives the evidence.
- MHFE is licensed under the MIT license or the Apache License 2.0, at your option
  (`LICENSE-MIT`, `LICENSE-APACHE`); releases up to 0.6.0 remain available under the MIT license.
  Every release archive carries both licence files.
- Every question that is not a secret has an option, so that a script can give every answer:
  `mhfe new --wallet-check yes|no` and `--choose-word yes|no`,
  `mhfe check --passphrase-used yes|no`, and `mhfe encrypt --same-length no` for a 24-word
  container.
- A command that reads a secret refuses at its start, with the advice to run it in a terminal or
  pass `--stdin`, when its standard input is not a terminal and `--stdin` is not given, instead of
  reading that input as answers.
- `mhfe rekey` refuses an invalid `--new-pim` or `--new-mem`, and a `--confirm` that the stated
  length does not allow, before the old container's recovery instead of after it.
- The start menu offers the fast mode only when the page beside the program is there and matches
  its checksum file; otherwise it says why the fast mode is not offered.
- `mhfe serve` starts with its title line and wraps its lines at 78 columns, and both fast-mode
  launchers always print the page's address, also when a browser was opened. The Python launcher
  writes as the program does: ✓ and "✗ Error:", colours only at a terminal, `NO_COLOR` honoured.
- When a phrase also reads as another length, the note of its word count is to be kept apart from
  the container phrase, like the password.

## Fixed

- Warn when the Linux swap inventory cannot be read, instead of treating it as confirmed empty.
- Refuse generated container-password output when a private screen cannot be established, including
  failed Windows VT activation; check the acquired screen again immediately before display.
- A zram swap device with a writeback device is judged by that device, so that an unencrypted one
  gives the swap warning.
- The word hints of a phrase or password no longer copy the matching words into strings that are
  not wiped.
- A result that cannot be written to standard output, on a closed pipe or a full disk, ends with
  "Input or output failed" and exit code 1, never as a success or a panic.
- Keys typed during the start or during long work no longer answer the next question or close a
  screen that shows a secret once.
- At `TERM=dumb` the word prompts write no cursor-control sequences and no hint rows.
- The `--stdin` help of encrypt, decrypt and check names the second line of standard output that
  `--repair-words` or `--repair` adds, and `mhfe serve` shows the checksum file's format with its
  two spaces.
- The startup self-checks no longer wait a fixed 0.2 s; they take about 0.08 s.
- The Python fast-mode launcher keeps serving after a connection fails, as `mhfe serve` does.

## Browser package

- A BIP39 passphrase given where an operation does not use it, inside the reference of `check()`,
  `searchDecoy()` or an address or fingerprint `rekey()`, or beside `{ builtInCheck: true }`, is
  refused with a `TypeError` instead of being dropped.
- The early refusals of the PIM, the memory level, the word count and the repair-word count use
  the library's sentences.
- A WebAssembly trap inside a hidden-wallet session, a rekey recovery or a check session rejects
  with `INTERNAL_ERROR`, "The WebAssembly stopped", instead of a wasm-bindgen ownership error.
- `MhfeRepair`'s startup self-check covers the master key fingerprint that every repair computes,
  and `MhfePasswords` built alone carries only the password cases of its self-check.
- The documentation says which copies of keys and seeds the WebAssembly cannot wipe, and the host
  page's duties include every application rule of the specification.

## Build, tests and release

- The Windows zip's permission bits no longer depend on the umask of the checkout, and
  `THIRD_PARTY_NOTICES.md` covers the Rust standard library and the crates it is built from.
- The vendored Argon2 gate refuses an added file, and the no-network gates share one list of
  patterns.
