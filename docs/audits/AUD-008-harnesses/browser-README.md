# AUD-008 browser state probes

This contribution reviews MHFE HEAD `b6993bb1c11834a01847d1812b31a24145ab1f18` and the current dirty source bytes recorded in the local-only `AUD-008-evidence/browser-source-manifest.json`. Owner changes remain in place. It is a second scoped contribution from reviewer2, not an additional independent reviewer.

From the authoritative MHFE repository root, run:

```sh
/home/user/.local/bin/node docs/audits/AUD-008-harnesses/browser-state.mjs
```

The harness needs Node 26.10.0 and the current `web/client.js`, `web/mhfe-worker.js` and `web/argon2-engine.js`. It imports or evaluates those production files directly. Only synthetic public byte arrays and short text are used. No WASM or Argon2 computation runs, and no dependency installation or Cargo build is needed.

A passing run prints JSON with `outcome: "passed"` and `groups: 10`, and exits 0. Assertion failure exits nonzero. The groups cover worker cancellation/caller ownership; late result/error/callback isolation during a newer operation; rejected settings and references; pre-transfer failure cleanup; worker success/error cleanup; and Argon2 bridge success/error/allocation-error cleanup when the C heap view changes.

Worker, Rust core and C allocator stand-ins establish control-path behavior only. They do not establish browser CSP, browser scheduling, WASM FFI, actual Argon2 output, fresh distribution assets or physical memory erasure. The coordinator owns those applicable checks. The first harness run failed because its Argon2 stub used the wrong key-pointer argument; the original failure and corrected rerun are preserved in local evidence and are not counted as product failures.
