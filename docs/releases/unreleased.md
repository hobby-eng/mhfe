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

## Fixed

- Warn when the Linux swap inventory cannot be read, instead of treating it as confirmed empty.
- Refuse generated container-password output when a private screen cannot be established, including
  failed Windows VT activation; check the acquired screen again immediately before display.
