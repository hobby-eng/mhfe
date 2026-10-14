# AUD-024 api-contracts harness

The harness of the api-contracts review of audit AUD-024, at commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1`. It checks the public contracts of the browser
package's classes (`web/*.js` as built into `dist/`) and of the WebAssembly bindings
(`src/wasm_api*`) that the review found broken. Each check states the expected behaviour and its
source in a comment and prints `PASS` or `FAIL` with what it saw.

## Files

- `harness.mjs`: runs the built classes of `dist/` in Node.js with the package's real worker
  script, `dist/runtime/worker.js`, in the same process in place of a browser's `Worker`. Argon2 is
  the single-threaded Emscripten build `dist/core/argon2-st.js`. It reads `dist/` and writes
  nothing.
- `check-contracts.mjs`: the checks. The self-checks and the modules without Argon2 run in the real
  worker; the core's long operations (`encrypt`, `decrypt`, `check`, `searchWallet`, `rekey`,
  `openHiddenWallets`) run against a scripted stand-in worker that records what the page sends and
  answers as the real worker would at that step, so that no Argon2 round runs. Check 8 calls the
  WebAssembly bindings directly through the glue in `dist/runtime/worker.js`; check 10 reads
  `docs/API.md`; check 11 reads `src/hidden.rs`.

## Inputs

- The browser package built from this commit: `scripts/build-wasm.sh`, which writes `dist/`. The
  audit's build was `de06b919b42eae2f` (`dist/modules.json`); `docs/audits/AUD-024-evidence/dist-SHA256SUMS`
  holds the hashes of its files.
- Node.js 26 (the audit used v26.10.0). No network, no browser, no secret: the only phrase is the
  public test phrase ("abandon" eleven times, then "about") and the only address its first BIP84
  address.

## Command

From the repository root:

```sh
node docs/audits/AUD-024-harnesses/api-contracts/check-contracts.mjs
```

## Expected output

At `b6fca69` all eleven checks fail, and the script exits with status 1, ending with
`11 check(s) failed`. The first lines read:

```text
FAIL owner-answer-extra-keys: owner answered { confirmed: false, passphrase }; the page sent {"confirmed":true,"passphrase":"bytes(12)"}
FAIL misspelled-option: encrypt({ PIM: 7 }) reached the worker with pim 0
FAIL out-of-range-numbers: make count 2**32: "The size must be a whole number, not 4294967296"; ...
```

Once the findings are fixed, each line reads `PASS`, the last line `every check passed`, and the
exit status is 0. It takes about a second.
