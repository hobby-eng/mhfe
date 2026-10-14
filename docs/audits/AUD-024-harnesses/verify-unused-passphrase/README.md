# verify-unused-passphrase

Audit AUD-024, commit `b6fca69238344dd2525b06270ee6ff3b055e68c1`. This is the reproduction harness
for the finding that the browser package's core takes a BIP39 passphrase where the comparison uses
none and drops it without a refusal. The library's own rule `rehearsal::refuse_unused_passphrase`
(src/rehearsal.rs:272-288) says such a passphrase must be refused.

## What it checks

`probe.mjs` loads the built core WebAssembly (`dist/runtime/mhfe.wasm`) with its wasm-bindgen glue
(`target/wasm-bindgen/mhfe.js`). It passes in a stand-in Argon2 object: it computes the 1 MiB known
answer exactly with Node's Argon2id, and every larger call at 1 MiB with one pass. No full-cost
Argon2 runs. Because encryption and recovery use the same stand-in, they agree with each other. The
only test data is public: the `abandon … about` 12-word phrase, `abandon ×23 art`, and public test
passwords.

The probe covers these cases:

1. `CheckSession` with reference kind `"words"`, reference `"12"` and then `"21"`, and the passphrase
   `"x"`. The case expects `INVALID_REQUEST` before any round.
2. `CheckSession.compare("words", "12", …, "x")` on a session that detected the length. This is the
   path the worker takes for an `onNoLength` answer. The case expects `INVALID_REQUEST`.
3. Two contrasts that refuse today: `searchWallet` with `"builtInCheck"` and `"x"`, and
   `RekeySession.recover` with `"builtInCheck"` and `"x"`.
4. A rekey of a 12-word original with 15 words stated and `walletHasPassphrase` set to false. The
   owner is shown the verified 12-word reading. The owner's answer is
   `ownerAnswer(true, "x")`, and the case expects `INVALID_REQUEST`.
5. A contrast for case 4: the same answer for a 24-word original, whose rehearsal is the
   fingerprint. The library refuses it there.

## Inputs

You need `dist/runtime/mhfe.wasm` and `target/wasm-bindgen/mhfe.js` as the baseline built them at
b6fca69 (`scripts/build-wasm.sh`; the hashes are in
`docs/audits/AUD-024-evidence/dist-SHA256SUMS`). You also need Node 24 or later, for
`crypto.argon2Sync`.

## Command

From the repository root:

```sh
node docs/audits/AUD-024-harnesses/verify-unused-passphrase/probe.mjs .
```

## Expected output

The script exits 1 while the defect is present. It prints one line per case:

- `FAIL` for cases 1, 2 and 4, each with the accepted result. Case 1 reports
  `"outcome":"matches"`, with output identical for the passphrases `"x"`, `""` and another one.
  Case 4 reports `accepted; sealed; rehearsal {"kind":"builtInCheck"}`.
- `PASS` for the three contrasts.
- `4 case(s) failed` as the last line.

Once the fix is in, every line is `PASS` and the script exits 0.

The log of the audit run is `docs/audits/AUD-024-evidence/verify-unused-passphrase/wasm-unused-passphrase.log`.
