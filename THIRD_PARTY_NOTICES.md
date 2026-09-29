# Third-party notices

The `mhfe` command-line tool and browser package include the following third-party material in
addition to the Rust crates listed in `Cargo.lock`, each under its own licence.

## Argon2 reference implementation

- Source: https://github.com/P-H-C/phc-winner-argon2, commit
  `f57e61e19229e23c4445b85494dbf7c07de721cb`, vendored unchanged in `vendor/phc-winner-argon2/`.
- Copyright 2015 Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson and Samuel Neves.
- Offered under CC0 1.0 or the Apache License 2.0, at the user's option. MHFE uses it under the
  **Apache License 2.0**. The licence text is in `vendor/phc-winner-argon2/LICENSE` and ships with
  every release. No file has been changed; any future change would be recorded as a separate patch
  file next to `vendor/phc-winner-argon2.md`.

## EFF large wordlist

- Source: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt, included unchanged in
  `vendor/eff-large-wordlist/` and used by `mhfe password`.
- "EFF large wordlist" by the Electronic Frontier Foundation (Joseph Bonneau), licensed under the
  Creative Commons Attribution 4.0 International licence (CC BY 4.0):
  https://creativecommons.org/licenses/by/4.0/. See `vendor/eff-large-wordlist.md`.
