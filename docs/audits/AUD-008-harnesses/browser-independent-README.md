# AUD-008 independent browser seam probe

The two `browser-independent-wasm-*.mjs` harnesses supplement the earlier ten production-JavaScript stand-in groups with the real shipped WASM glue and Rust callbacks. They belong to AUD-008 at reviewed commit `b6993bb1c11834a01847d1812b31a24145ab1f18`, including the dirty source bytes captured by the coordinator in `AUD-008-evidence/snapshot.json`. The initial seams probe compares each source hash with that snapshot and verifies that the assembled worker contains the current glue, Argon2 bridge and worker sources byte for byte.

The inputs are the public `abandon … about` BIP39 phrase, an explicitly public password marker and a synthetic constant key marker. It does not compute Argon2, build an artifact or start a browser. The synthetic engine exists only in this audit harness, so its container is not an MHFE vector. Fresh `dist/` and `target/wasm-bindgen/` output from the reviewed source are prerequisites; the coordinator owns their build.

Run from the MHFE repository root with the workspace Node toolchain:

```sh
/home/user/.local/bin/node docs/audits/AUD-008-harnesses/browser-independent-wasm-seams.mjs
/home/user/.local/bin/node docs/audits/AUD-008-harnesses/browser-independent-wasm-residual.mjs
```

The initial seams probe is retained as a failed diagnostic. It exits non-zero at its assertion that no key marker survives after `on_unverified` throws; consequently its final JSON and direct numeric cases never ran. That absence assumption was stronger than the compiler-copy limitation already stated in `SECURITY.md` and `docs/API.md`. Its original failure is preserved, rather than relaxing that assertion.

The residual probe starts a fresh real WASM core for each of four cases: an engine throws before returning, cancellation before the second round, cancellation after the twelve encryption rounds, and successful encryption plus verification. It records callback-view pointers, restored stack pointers, a sampled heap allocation, and remaining marker offsets. It exits zero only if the documented residual is reproduced alongside password cleanup and the expected errors/results. Its JSON explicitly records `outcome: "observed documented compiler-copy limitation"`, rather than claiming total erasure. The key view wipes when the engine throws, but after successful return the original view can remain below the restored stack pointer, consistent with compiled `RoundValues` moves. The normal client ends the entire worker on result, error or cancel. These observations do not establish a missed final source-owner drop or a practical disclosure path.

Marker presence or absence is bounded runtime evidence rather than a general zeroization proof. Browser scheduling, CSP, worker transfer and actual Argon2 outputs use the coordinator's separately recorded checks.
