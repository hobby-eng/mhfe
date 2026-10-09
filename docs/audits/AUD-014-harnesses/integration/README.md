# AUD-014 integration harness

`worker-lifecycle.mjs` checks the current `web/runtime.js` and `web/wallet.js` from this checkout against a controlled Worker. It belongs to AUD-014, whose reviewed dirty source snapshot is recorded by the coordinator in the audit evidence; the script prints the SHA-256 of both source files it actually imports. It needs Node.js 26.10.0 and no installed package, generated browser artifact, network access, or private input.

Run from the MHFE repository root:

```sh
node docs/audits/AUD-014-harnesses/integration/worker-lifecycle.mjs
```

Each passing state check prints `PASS`, followed by a JSON summary. The cases cover deferred termination after cancellation while loading, first ready/result/error/progress replies, native worker errors, the loading deadline, first-winner and first-error settlement, slot reuse, late-result suppression, transferred request ownership, and WordWishes startup/full failure gates. Assertions exit nonzero if these checks fail. The synthetic worker reports never claim that the Rust WordWishes known answers ran.

One separately labelled diagnostic reports whether an operation already awaiting startup is allowed after a concurrent full check fails. It isolates the shared `PackageCheck` policy; it is not counted as a passing WordWishes check and does not claim new phrase-generation behavior. Subsequent requests must still be refused.

This harness does not run MHFE WASM, Argon2, actual phrase generation, a real browser, or memory-erasure tests. The empty eight-byte WASM module exercises only the host compilation step. Test inputs are synthetic public words and a public audit passphrase. The existing browser regression's Firefox-specific crash test requires its own real-browser execution and is not established by this harness.

`gate-race.mjs` is a separate regression for an operation waiting on startup when a concurrent full check fails. It calls the actual `MhfeWallet.drawPhrase()` and `fullCheck()` methods and observes the actual module worker dispatch. It exits nonzero if the failed full check permits a new draw worker to start, then refuses the observed dispatch before any phrase is generated.

```sh
node docs/audits/AUD-014-harnesses/integration/gate-race.mjs --controlled
node docs/audits/AUD-014-harnesses/integration/gate-race.mjs --wasm
```

The controlled mode uses labelled synthetic reports and no MHFE WASM. The WASM mode requires the existing `dist/runtime/mhfe.wasm` and `target/wasm-bindgen/mhfe.js`, prints both hashes, and runs the actual `selfCheckWallet` binding in each controlled worker. Startup runs its scripted cases and passes; the full wallet self-check uses a stuck live random source and fails `random-source`. Its bounded wallet known answers use a few BIP39 seed computations and no Argon2, full-size cipher vectors, or cards. The artifact is not built or refreshed here, so its source relationship must be recorded separately by the coordinator. Both modes deliberately deliver the passing startup report only after the failed full report has reached the same class, which is an allowed ordering for separate workers. A correct gate refuses the pending request with `SELF_CHECK_FAILED` before dispatch. The baseline runtime is expected to fail this assertion; this failure is retained separately from the healthy lifecycle checks.

`startup-browser.mjs` exercises the current built wallet package in installed Chromium and Firefox through actual Blob workers, one browser at a time, on a local file page with the normal offline policy. It validates the package's WASM and worker hashes against `dist/modules.json`, derives the version and build from the current manifest, records the build and engine versions, requires the startup WordWishes component to pass within two seconds, runs only the bounded wallet full self-check (including the real host RNG), draws an unchecked last-word `zoo` and an unchecked first-word `happy` with `abandon` excluded, compares both complete phrases with the independent KATs in `src/word_wishes/known_answers.rs`, validates the returned BIP39 phrases through fingerprinting, and refuses an invalid chosen word. A narrow fixture reader extracts those ASCII golden phrases directly from that source rather than maintaining a second list, and its hash is reported. The fixtures name the independent implementation that originally computed them. A public scripted source is injected into `drawPhrase` only; self-checks keep real `crypto.getRandomValues`. `PhraseDraw::draw` calls `random::check_source` first, which consumes two 32-byte probe blocks; the script supplies bytes 1 through 64 for these guards, then starts the fixture's xorshift32 stream from its original seed. Thus the entropy stream after the guards exactly matches the KAT's direct `try_draws` stream. It creates only the ignored local page `docs/audits/AUD-014-evidence/integration-startup-browser.html`. It does not build, install, run Argon2, draw checked phrases, or inspect the Deriver. Browser phases share a twenty-five-second deadline; memory usage is bounded by one ordinary browser and the wallet's small worker at a time.

```sh
node docs/audits/AUD-014-harnesses/integration/startup-browser.mjs
```

Each browser prints its actual report and draw properties as JSON; a final JSON record includes the artifact hashes. Any failed report, missing component, draw mismatch, invalid-word acceptance, unexpected egress, uncaught page error, or timeout exits nonzero. This smoke is targeted runtime evidence, not the full browser or release suite.
