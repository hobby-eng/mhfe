# Next release notes — draft

Record user-visible changes here as they are made. Before tagging, move them into
`docs/releases/v<version>.md`: the release workflow attaches that file as the text of the draft
release. Without it the canonical job fails before its build and no draft is made, while the macOS
builds and the CI checks of the same run, and `vectors.yml` for the tag, go on until they end or
are cancelled.

## Changed

- MHFE is licensed under the MIT license or the Apache License 2.0, at your option
  (`LICENSE-MIT`, `LICENSE-APACHE`); releases up to 0.6.0 remain available under the MIT license.
  Every release archive carries both licence files.
