# AUD-024 core-crypto harness

Audit AUD-024, role core-crypto, reviewed commit `b6fca69238344dd2525b06270ee6ff3b055e68c1`
(branch `aud023-remediation`). Public test data only: the published vectors in `tests/fixtures`,
the specification's profile vectors, the "abandon ... about" phrase and fixed public byte streams.
Nothing runs Argon2 above 256 MiB.

## What it checks

`run.sh conformance`, which passes at b6fca69:

- `oracles/argon2_tags.py`: the engine's Argon2id known answers (1, 64 and 256 MiB, and RFC 9106
  section 5.3) recomputed with OpenSSL through Python `cryptography`.
- `oracles/profiles_oracle.py`: MHFE-REPAIR-1 (generator polynomials g_2 to g_8 and every published
  card), MHFE-PASSWORD-CHECK-1 (the four published rows) and MHFE-WALLET-CHECK-SEED-1 (both passing
  digests and the three failing prefixes), written from the specification alone.
- `oracles/reduced_cost_oracle.py`: suites 3 and 4 written from the specification, with Argon2id at
  the unit tests' reduced cost (256 KiB, one pass, four lanes), against the reduced-cost containers
  of `src/mhfe.rs`.
- `oracles/bip39_reading_oracle.py`: BIP39 encoding of 1,029 entropies of every width and the
  specification's "Reading words" rule for 2,059 typed phrases, against `read_phrase` and
  `phrase_from_entropy` through the probe.
- `oracles/repair_bound_oracle.py`: 4,000 damaged containers of every length and card size: within
  `2e + s <= k` the original comes back; beyond it the repair is refused or stays within the bound.
- `oracles/password_scan.py` against the probe's `password-scan`: the password rule
  (`Password::new`) for every Unicode scalar value equals the Unicode 17.0.0 rule of the
  specification (`unicodedata2`), compared through a SHA-256 of every result.

`run.sh findings`, which fails at b6fca69 and passes once the core-crypto findings are fixed:

- `uniform-below-refuses-a-bad-bound`: `random::uniform_below` with a bound of 1 returns an error.
- `stuck-source-is-refused`: a random source that passes the start probe and then gives only 0xff
  ends `PasswordRecipe::make` with `RANDOM_FAILED` within 10 seconds.
- `half-filling-source-is-refused`: a source that fills half of every buffer gives no phrase.
- `chosen-word-read-as-a-phrase-word`: `WordWishes::new` refuses "\u{212A}ite" (KELVIN SIGN), as
  `check_phrase` does.
- `dice-group-count-is-named`: dice rolls with one group too many are not refused as malformed
  digits of a word the password does not have.
- `check-word-adds-no-strength`: `Strength::of` rates a check-word password at the recipe's 64.6
  bits, not as six random dice words.
- `doc-comments-describe-their-own-item`: the three doc blocks that start with another item's
  sentence (`src/feistel.rs`, `src/bin/mhfe/style.rs`, `src/bin/mhfe/hidden_input.rs`).

## Inputs

The repository at the reviewed commit, the offline Cargo registry with `bip39-3.0.0` (its English
list is the oracles' word list), Rust 1.99.0, Python 3 with the hash-pinned packages of
`scripts/independent-suite3-requirements.txt` (`cryptography`, `unicodedata2`) on `PYTHONPATH`.
`run.sh` copies `probe/` to a temporary folder, writes its `Cargo.toml` from `probe/Cargo.toml.in`
and builds it there, into `CARGO_TARGET_DIR` if set; it writes nothing into the repository.

## Commands, from the repository root

```text
CARGO_TARGET_DIR=<a folder outside the repository> PYTHONPATH=<the pinned packages> \
  docs/audits/AUD-024-harnesses/core-crypto/run.sh conformance
CARGO_TARGET_DIR=<a folder outside the repository> PYTHONPATH=<the pinned packages> \
  docs/audits/AUD-024-harnesses/core-crypto/run.sh findings
```

## Expected output at b6fca69

`conformance` exits 0. Every oracle line starts with `OK`, and it ends with
`encoding: 1029 entropies, 0 differences`, `reading: 2059 typed phrases, 0 differences`,
`within bound: 2411 repaired; beyond: 1579 refused, 10 given as another valid container within the
bound; 0 violations`, `accepted 297267 control 67 unassigned 814730 other 0`,
`sha256 d84788f1ab4dd942a25783f12ea80a65ea5d89d34da0314fad0f010f05b7d8dd` and
`password rule: the Rust encoding equals the Unicode 17.0.0 oracle for every scalar value`.

`findings` exits 1, with seven `FAIL` lines: `uniform-below-refuses-a-bad-bound` (a panic),
`stuck-source-is-refused` (`Err(Timeout)`), `half-filling-source-is-refused` (a phrase ending in
eleven "abandon" words and "biology"), `chosen-word-read-as-a-phrase-word` (accepted: true),
`dice-group-count-is-named` ("the dice digits for word 3 must be exactly five digits, each from 1
to 6"), `check-word-adds-no-strength` (77.55 bits against 64.625) and
`doc-comments-describe-their-own-item`. After the fixes it exits 0 with seven `PASS` lines.

The logs of both runs at b6fca69 are `docs/audits/AUD-024-evidence/core-crypto/c12-harness-conformance.log`
and `c13-harness-findings.log`.
