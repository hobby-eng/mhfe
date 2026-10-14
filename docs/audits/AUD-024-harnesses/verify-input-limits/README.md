# verify-input-limits

Harness of audit AUD-024 at commit b6fca69 (adversarial verification of the candidate finding on
input size limits of address texts and BIP39 passphrases).

What it checks: the built browser package refuses an address text of 32,000 characters within
50 ms (`describeAddress`, coin `bitcoin`) and refuses a BIP39 passphrase of 8 MiB
(`walletFingerprint` with the public "abandon ... about" phrase), as CORE-48 and CORE-50 require.
It loads `dist/runtime/mhfe.wasm` with the wasm-bindgen glue of `dist/runtime/worker.js` in
Node.js, read only, and calls the functions as `web/wallet-worker.js` does. No Argon2 runs.

Inputs: a built package in `dist/` (the baseline's browser package build of the same commit) and
Node.js 22 or later. Public test data only.

Command, from the repository root:

    node docs/audits/AUD-024-harnesses/verify-input-limits/check-input-limits.mjs .

Expected output at b6fca69 (the defect is present), exit code 1:

    FAIL address text of 32000 characters refused within 50 ms: refused after ~190 ms (INVALID_ADDRESS: ...)
    FAIL BIP39 passphrase of 8 MiB refused: accepted after ~140 ms (27f79526)

Expected output after a fix, exit code 0: both lines start with PASS.
