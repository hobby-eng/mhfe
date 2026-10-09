# AUD-016 browser review harnesses

These read-only production probes support the browser portion of AUD-016. The reviewed mhfe
checkout is based on `3c60594479302827fe40975b04fd07f9f6fd4b3b` with uncommitted changes and code
fingerprint `0c282ddd47edbe418644f19a5ae136fedd68fc13cb1e3b61972dc7f7e6d74f41`.
The complete audit records the coordinator's snapshot and build evidence. Use only the documented
workspace checkout and Node.js 26.10.0. These probes do not install anything or modify production
files, fixtures, dependencies, or other project checkouts.

- `page-protocol.mjs` imports the current `web/` runtime and classes in memory and supplies a
  synthetic Worker. It challenges malformed response envelopes, inherited message names,
  argument types, caller byte ownership, cancellation during initialization, and independent
  repair-module operation. Its synthetic passing startup report tests the page transport only;
  it is not evidence that the WASM self-checks passed. It completes 26 assertions, including the
  six baseline failures associated with API002/API003, and exits 1 while those failures remain.
- `worker-cleanup.mjs` executes the current worker runtime and operation tables in a VM with
  synthetic binding objects. It checks byte overwriting and binding disposal after exceptions,
  a hidden-wallet refusal and close, and inherited operation-name rejection. No cryptographic
  operation runs. Seven assertions pass at the reviewed snapshot; failures exit nonzero.
- `real-wasm-api.mjs` imports the freshly built `dist/` classes and executes the unmodified
  production worker and real WASM with a VM implementing the Worker transport. It runs startup
  checks, exact public fingerprint/repair-card/EFF-dice answers, scalar overflow refusals,
  invalid-UTF-8 refusal, caller ownership, and the explicit-null TypeError cases. It completes
  22 assertions, including three baseline API003 failures, and exits 1 while those failures
  remain. No Argon2 source or Argon2 operation runs. The VM transport is not real-browser evidence.

The real-WASM probe requires `scripts/build-wasm.sh` to have completed in this checkout. Its
baseline build ID is `0ead1c7b89fe6106`; it prints the actual build ID and artifact hashes so
future runs identify their own package bytes. All fixtures are public: BIP39's all-zero phrase,
the suite-3 public `zero-12` container, its independently calculated repair card, and EFF dice
`11111`. No network service is contacted. The fingerprint is the published BIP39/BIP32 answer;
the repair-card answer is also retained in `src/repair.rs` and `scripts/verify-browser-package.mjs`.

Run from the mhfe repository root:

```sh
node docs/audits/AUD-016-harnesses/browser/page-protocol.mjs
node docs/audits/AUD-016-harnesses/browser/worker-cleanup.mjs
node docs/audits/AUD-016-harnesses/browser/real-wasm-api.mjs
```

The coordinator's evidence runner captures a command's UTC times, exit code and log SHA-256:

```sh
python3 docs/audits/AUD-016-harnesses/run.py browser-page-protocol node docs/audits/AUD-016-harnesses/browser/page-protocol.mjs
python3 docs/audits/AUD-016-harnesses/run.py browser-worker-cleanup node docs/audits/AUD-016-harnesses/browser/worker-cleanup.mjs
python3 docs/audits/AUD-016-harnesses/run.py browser-real-wasm-api node docs/audits/AUD-016-harnesses/browser/real-wasm-api.mjs
```

Use a fresh label for any rerun. Evidence labels are never overwritten. The baseline also reused
the read-only `AUD-015-harnesses/r3-browser/static-scan.mjs` under label
`browser-static-surface`: 14 assertions passed against the rebuilt package. It checks declaration
codes, documented exports, operation tables, secret-field inventories, package stamps and hashes,
and absence of network/storage calls. Static lexical scanning complements source inspection; it
does not prove that arbitrary host code is offline.

The separate assertion counts overlap in purpose and must not be combined into a claim of
independent cryptographic coverage. The coordinator owns the full package, Argon2, CLI parity,
and real-browser suites. These harnesses add bounded fault injection and contract evidence.

The coordinator's separate native-browser run also reproduces BLD002: the required verifier
retains earlier length-selection, rekey field, refusal-timing and error-message expectations.
This folder does not patch that verifier. The audit records the original native failures and
source diagnosis; final browser versions, matrix counts, exit status and log hash belong to the
coordinator's evidence. Immediate failure lines and repeated per-page failure lists must not be
counted twice.
