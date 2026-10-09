# AUD-009 reproduction harness

This harness checks four confirmed browser API and cleanup defects in the dirty MHFE refactor on
HEAD `d7af4b1035355a69779f8ad70a9dc50ba5b9ffd0`. The report records the source hashes.
It uses only synthetic values, reads the real JavaScript sources, rewrites the runtime import to an
in-memory data URL and uses a stand-in worker. It does not build WASM, write generated output or
exercise a real browser.

Run from the MHFE repository root with Node 26.10.0:

```sh
node docs/audits/AUD-009-harnesses/browser-boundaries.mjs
```

Expected baseline output: four `REPRODUCED` lines for API002, API001, SEC001 and API003, exit 0.
The assertions intentionally demonstrate defects; a successful run is not acceptance of the API.
After remediation the corresponding assertions should fail, and positive regressions should replace
them. The harness cleans up its own synthetic arrays and restores replaced globals.
Native API004/API005 were established by source trace; this harness does not verify them.

Owner-authorized documentation-only amendment of 2026-10-09: commit references of the history replaced by the second privacy rewrite of 2026-10-09 now name the commits that replaced them: f4f7b017d21cbda51283f9eaa973a0cc161b95d6 -> d7af4b1035355a69779f8ad70a9dc50ba5b9ffd0.
