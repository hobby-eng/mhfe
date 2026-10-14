# verify-check-reference-options

Audit AUD-024, commit b6fca69. Adversarial reproduction of the docs-claims candidate
"mhfe check accepts --coin and --path beside --fingerprint or --words N and ignores them".

## What it checks

`mhfe check` documents `--coin` and `--path` as "With --address" and declares
`requires = "address"` for both (src/bin/mhfe/check.rs:54-56, :71-73). clap waives a `requires`
whose target conflicts with an argument that is present, and the `reference` group
(check.rs:42) makes `--address` conflict with `--fingerprint` and `--words`. The probe runs:

1. `check --stdin --fingerprint --coin ethereum --path m/84'/0'/0'/0/5` with a valid 12-word
   container, a password and a malformed fingerprint: the command asks the fingerprint and
   stops at it.
2. `check --stdin --words 12 --coin ethereum --path m/0/1` with a valid 24-word container and a
   password: no reference is asked; the command stops at the 2 GiB reservation.
3. `check --stdin --words auto --coin ethereum --path m/0/1`: the passphrase line is read; the
   command stops at the 2 GiB reservation.
4. Controls: `--coin` alone and `--address --fingerprint` are refused by clap;
   `--address --coin ethereum --path ...` uses the coin.

No Argon2 round runs: `ulimit -v 1000000` makes the 2 GiB work-area reservation fail, and the
fingerprint and address cases stop before it. Inputs are public test data only (the "abandon ...
about" and "abandon ... art" phrases).

## Command, from the repository root

    docs/audits/AUD-024-harnesses/verify-check-reference-options/probe.sh <path to a debug mhfe>

## Expected output

At b6fca69 the three cases print `ACCEPTED (defect)` and the probe exits 1. After a fix each of
them prints `refused before anything is asked` (exit 2 before the title) and the probe exits 0.
