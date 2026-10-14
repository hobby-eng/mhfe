# verify-error-text-sites

Audit AUD-024, commit b6fca69238344dd2525b06270ee6ff3b055e68c1 (branch aud023-remediation).

Checks RUST-04 ("its `Display` is the one place its messages are written (CORE-23)") and CORE-23
("the text a person reads is built in one place per front end from that code") against
`MhfeError` in `src/error.rs`, which itself says at lines 9-10 and 211-214 that its `Display` is
"the one place the messages are written".

## What it checks

1. No `Display` arm of `src/error.rs` writes nothing but the caller's text
   (`write!(f, "{reason}")`).
2. No non-test code outside `src/error.rs` builds an `MhfeError` variant that carries free text
   (`InvalidPhrase`, `InvalidContainer`, `InvalidRepairWords`, `InvalidWordWish`,
   `InvalidAddress`, `InvalidDerivationPath`, `InvalidFingerprint`, `Argon2`, `InvalidRequest`,
   `InvalidPasswordSize`, `RandomFailed`, `InvalidCoin`, `Internal`, `SelfCheckFailed`).
   Test code (`#[cfg(test)]` and `#[cfg(all(test, ...))]` items and modules, and files declared
   as test-only modules) and match patterns are left out.
3. No browser binding (`src/wasm_api*`) writes the message of a library error code itself, or
   constructs an error only to read its `code()`.

## Inputs

The Rust sources under `src/` of the checkout. Nothing is built or run; no network.

## Command (from the repository root)

```sh
python3 docs/audits/AUD-024-harnesses/verify-error-text-sites/scan.py
```

## Expected output at b6fca69

Exit status 1 and the last line `result: FAIL (Display is not the one place the messages are
written)`. Check 1 lists `src/error.rs:413` (`InvalidPasswordSize`); check 2 counts 102 sites in
37 files (77 in 28 library files outside `src/wasm_api*` and `src/bin`); check 3 lists 11 places,
among them `src/wasm_api.rs:273` (`"{code}: {name} must be a whole number, not {value}"`).

A fixed tree prints `result: PASS` and exits 0. A documented exception (for example the
reference implementation's own Argon2 message) has to be removed from the variant list in
`scan.py` with its reason.
