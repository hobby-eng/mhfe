# AUD-017 R3 harnesses: WASM bindings and the browser package

Audit-only probes of reviewer R3 of AUD-017, for the reviewed tree HEAD `3c60594` with its
uncommitted 0.5.1 changes (source fingerprint
`b2addb366a3bda36ed23bb84f68a2c92550b0c0f7c533d366894a8664963cbc7`) and the browser package in
`dist/` of build `0ead1c7b89fe6106`. They read `web/`, `src/`, `docs/`, `target/wasm-bindgen/` and
`dist/` and change nothing on disk. Public test data only. No cargo, no browser, no full-size
Argon2: every round runs at 256 KiB and one pass.

Run from the repository root through the audit's runner, which keeps the log in
`docs/audits/AUD-017-evidence/`:

```sh
timeout 60 python3 docs/audits/AUD-017-harnesses/run.py r3-static-scan-aud015 node --max-old-space-size=1024 docs/audits/AUD-017-harnesses/r3-browser/static-scan.mjs
timeout 60 python3 docs/audits/AUD-017-harnesses/run.py r3-api-probes node --max-old-space-size=1024 docs/audits/AUD-017-harnesses/r3-browser/api-probes.mjs
timeout 60 python3 docs/audits/AUD-017-harnesses/run.py r3-rekey-parity node --max-old-space-size=1024 docs/audits/AUD-017-harnesses/r3-browser/rekey-parity.mjs
```

- `static-scan.mjs`: AUD-015's R3 static scan, unchanged but for its paths: error codes against
  `MhfeErrorCode`, network, storage, DOM and dynamic code in `dist/`, the export list of
  `docs/API.md`, `SECRET_FIELDS`, worker operation tables, build stamps and `modules.json`.
  Expected: exit 0.
- `api-probes.mjs`: AUD-015's R3 page-side probes P1 to P6 with a stand-in worker (secret
  transfer, `drawPhrase` types, `Object.prototype` names, the self-check gate, cancel of a loading
  worker), plus P7, `decrypt()`'s new `passphrase` (transfer, cancel, type refusal), and P8,
  replies out of protocol order. Expected: exit 0.
- `rekey-parity.mjs`: the built core at reduced cost: `decrypt` candidates' `walletCheck`,
  `statedWords` and `otherLengths` (D), a rekey with the length detected and the built-in check
  alone, which the command-line tool never offers (A), `LENGTH_DIFFERS` (C), the owner's check
  without the stated length the command-line tool warns of (B), and the passphrase's encoding (E).
  Expected on this tree: exit 1, A and B fail (AUD-017 R3 findings).
