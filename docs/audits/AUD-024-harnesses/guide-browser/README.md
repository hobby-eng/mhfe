# AUD-024 guide-browser harness

Audit AUD-024, role guide-browser, at commit b6fca69 (branch aud023-remediation, clean tree).
Review only: the harness reads the repository and runs the built browser package; it writes
nothing.

## What it checks

`check-browser-guide.mjs` runs the browser package of `dist/` in Node: the page classes as they
are, and every worker they start as the real `runtime/worker.js` evaluated in the same process
(`in-process-package.mjs`). Argon2 rounds run at a reduced cost (256 KiB, one pass); only the
known answers of the Argon2 build (1 MiB, 64 MiB and 256 MiB) reach the real single-threaded build
unchanged, so no suite-cost Argon2 runs. Public test data only: the "abandon ... about" phrase, the
password "public test password" and its reduced-cost container from
`scripts/public-test-data.mjs`, and the BIP-0084 address of that phrase.

Each check is the behaviour a guide-browser finding expects:

1. A `scanGap` of 2^32 is refused in the library's words, not as "not a whole number" and not with
   the parameter name capitalized into "ScanGap" (`whole_number` in `src/wasm_api.rs`).
2. `searchDecoy({ scanGap: 0 })`, a number, rejects with an `MhfeError` code, as the documented
   error contract says (docs/API.md, "A wrongly typed argument rejects with a TypeError ...").
3. An `onNoLength` answer that asks for detection again is a `TypeError`, as
   docs/BROWSER-PACKAGE.md says, not `CALLBACK_FAILED`.
4. A failing `onUnverified` callback is named `onUnverified` in its `CALLBACK_FAILED` message.
5. An error code returned by the page's Argon2 build gives an `ARGON2_FAILED` message that does
   not repeat the code.
6. One chosen word with a space in it is refused with `INVALID_WORD_WISH`, and an empty word never
   to use is refused rather than dropped.
7. `MhfeWallet.fingerprint()` takes a seed phrase as UTF-8 bytes, as passwords and passphrases are
   taken.
8. No worker operation table serves `packageVersion`, which no class sends.
9. The doc comment right above `searchCandidates` in `web/client.js` holds its description.

## Inputs

`dist/` built from the reviewed commit by `scripts/build-wasm.sh` (the audit's baseline build
de06b919b42eae2f, log `docs/audits/AUD-024-evidence/b12-build-wasm.log`), and `web/` of the same
commit. Node.js 22 or later.

## Command

From the repository root:

```sh
node docs/audits/AUD-024-harnesses/guide-browser/check-browser-guide.mjs
```

## Expected output

At b6fca69 every check fails and the harness exits 1:

```text
FAILS scanGap 2^32 is refused in the library's words: MhfeError INVALID_REQUEST: ScanGap must be a whole number, not 4294967296
FAILS searchDecoy scanGap 0, a number, rejects with an MhfeError code (docs/API.md:975-980): TypeError (no code): scanGap must be a whole number of addresses, at least 1.
FAILS onNoLength answering detection again is a TypeError: MhfeError CALLBACK_FAILED: The page's noLength callback failed.
FAILS a failing onUnverified is named onUnverified: MhfeError CALLBACK_FAILED: The page's unverified callback failed.
FAILS ARGON2_FAILED's message does not repeat the code: MhfeError ARGON2_FAILED: Argon2 failed: ARGON2_FAILED: the reference code returned error -33
FAILS a chosen word with a space is INVALID_WORD_WISH: MhfeError INVALID_REQUEST: Invalid request: give one place for every chosen word
FAILS an empty word never to use is refused, not dropped: resolved {...}
FAILS wallet.fingerprint takes a phrase as bytes: TypeError (no code): phrase must be a string.
FAILS no worker table serves the unused packageVersion operation: core-worker.js, repair-worker.js, passwords-worker.js, wallet-worker.js
FAILS searchCandidates' doc comment holds its description: the comment above it is "/** @param {OptionsOf<\"searchCandidates\">} [options] */"
10 checks fail.
```

After the findings are fixed, every line reads `ok`, the last line is "Every check passes." and the
harness exits 0.
