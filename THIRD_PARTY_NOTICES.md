# Third-party notices

The `mhfe` command-line tool and browser package include the following third-party material,
each under its own licence. The other Rust crates compiled into them are listed in `Cargo.lock`.

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

## bech32

- Source: the `bech32` crate, version 0.12.0 (https://github.com/rust-bitcoin/rust-bech32),
  compiled into the command-line tool and the browser package for SegWit and Taproot addresses.
- Licensed under the MIT licence only. Its notice, unchanged from the `LICENSE-MIT` file of the
  published crate:

```text
Copyright (c) 2017 Clark Moody

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```
