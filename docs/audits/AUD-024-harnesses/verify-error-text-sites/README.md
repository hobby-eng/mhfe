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

The Rust sources under `src/` of the checkout. No wallet operation is built or run; no network.
The remediated tree also needs Node.js for the current structural gate and its synthetic controls.

## Command (from the repository root)

```sh
python3 docs/audits/AUD-024-harnesses/verify-error-text-sites/scan.py
```

## Expected output at b6fca69

Exit status 1 and the last line `result: FAIL (Display is not the one place the messages are
written)`. Check 1 lists `src/error.rs:413` (`InvalidPasswordSize`); check 2 counts 102 sites in
37 files (77 in 28 library files outside `src/wasm_api*` and `src/bin`); check 3 lists 11 places,
among them `src/wasm_api.rs:273` (`"{code}: {name} must be a whole number, not {value}"`).

## The module-owned error model

The historical flat-variant trace above remains available for the original source layout.
When `src/error_code.rs` is present, the command runs `scripts/verify-error-contracts.mjs` and
its negative controls instead. A list of old names cannot assess nested typed causes: the new
gate reads every library error declaration, rejects free-text payloads even in renamed
variants, checks independent leaves for dependencies on the aggregate `MhfeError`, and rejects
binding-owned library code prefixes. A failed control or check propagates its failure status.

The only static text field allowed is `SelfCheckError::Failed.component`, a program-defined
component label. `FailureDetail` retains typed causes, public case metadata and codes. Its
synthetic `TestMessage(String)` is compiled only for tests; a negative gate control makes sure
such a test-only enum variant cannot hide a production field after it. Argon2 reference
messages are validated against a closed table generated from the pinned C source, with a
private numeric index rather than an arbitrary string payload. Runtime redaction and
conversion tests complement these structural checks; the gate is not a Rust type checker.

A remediated tree prints `result: PASS (module-owned typed errors and binding messages)` and
exits 0. Baseline evidence and its checker/source hashes are historical; changing this harness
does not claim that those checks ran on the later tree.
