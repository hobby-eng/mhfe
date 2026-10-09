# Browser Lifecycle Probe

This AUD-012 probe independently checks the AUD-011-SEC001 repair against current source. The audit report binds the reviewed commit and dirty-source fingerprint. It uses only synthetic byte arrays, synthetic text and an unpaired surrogate, and prints no wallet material.

From the MHFE repository root, with its pinned Node.js, run:

```sh
node docs/audits/AUD-012-harnesses/browser/lifecycle.mjs
```

The actual runtime and client are imported in memory. Startup checking is stubbed and a fake worker exchanges protocol messages, because the probe checks request cleanup and caller ownership independently of cryptography. It tests refusal of a surrogate, failure allocating the second encoding, postMessage failure, and preservation during refusal and successful transfers from ordinary Uint8Array and pooled Buffer inputs. It uses structuredClone with actual transfer lists to detach package buffers.

Expected output is seven case PASS lines and one summary PASS line, with exit zero. Any failed assertion exits nonzero. No file is exported and no source or artifact is built. Actual worker/browser security and real Rust-session cleanup require separate coordinator evidence.

The separate drawing-setup refusal probe runs with:

```sh
node docs/audits/AUD-012-harnesses/browser/draw-refusal.mjs
```

It passes `workers: 2 ** 32`, which is a safe integer accepted by the API but cannot be an Array length. The resulting RangeError is immediate and allocates no enormous array or workers. The actual public draw method runs with startup checking stubbed, and its synthetic passphrase copies are observed through TextEncoder. The reviewed snapshot exits nonzero because both copies remain unwiped; after remediation it should reject the count while leaving no unwiped copy and exit zero. Cleanup wipes its synthetic observations in either case.
