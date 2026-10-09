# AUD-015 R3 harnesses: WASM bindings and the browser package

Audit-only probes of reviewer R3 of AUD-015, for the reviewed tree HEAD
`4c3a6909bced0f0907f61ae291b11bb6bb419689` with its uncommitted changes (source fingerprint
`f79444dc9884d11a54c2c0b316ce31bf3a3a734e5bb604e9667df09cf0482a93`) and the browser package in
`dist/` of build `6a91d106c1b87634`, built from that tree by `scripts/build-wasm.sh`. They read
`web/`, `src/`, `docs/` and `dist/` and change nothing on disk.

Inputs: a built `dist/` (and, for `csp-page.mjs`, `node_modules` with Playwright and its Chromium
and Firefox). Run each from the repository root through the audit's runner, which keeps the log
in `docs/audits/AUD-015-evidence/`:

```sh
python3 docs/audits/AUD-015-harnesses/run.py r3-static-scan node docs/audits/AUD-015-harnesses/r3-browser/static-scan.mjs
python3 docs/audits/AUD-015-harnesses/run.py r3-api-probes node docs/audits/AUD-015-harnesses/r3-browser/api-probes.mjs
python3 docs/audits/AUD-015-harnesses/run.py r3-csp-chromium node docs/audits/AUD-015-harnesses/r3-browser/csp-page.mjs chromium
python3 docs/audits/AUD-015-harnesses/run.py r3-csp-firefox node docs/audits/AUD-015-harnesses/r3-browser/csp-page.mjs firefox
```

- `static-scan.mjs`: the error codes the bindings, the library and the classes give against
  `MhfeErrorCode`; network, storage, DOM and dynamic-code references in every `dist/` script; the
  WebAssembly exports named in `docs/API.md` against the glue's; the two `SECRET_FIELDS` lists and
  the fields the classes encode as secrets; the worker's operation tables; the build stamps and
  `modules.json`. Each check prints PASS or FAIL; a FAIL exits 1.
- `api-probes.mjs`: the page-side classes of `dist/` with a stand-in worker in Node.js: every
  secret field of every request and answer is transferred (P1); runtime types outside
  `wallet.d.ts` for `drawPhrase` (P2); replies and questions named after `Object.prototype`
  members (P3); the self-check gate when a full check fails first, AUD-014-SEC001 (P4); what a
  failed `fullCheck()` leaves (P5, recorded only); `cancel()` of a worker that still loads (P6).
  "CHECK" lines count towards the exit code, "INFO" lines record behaviour.
- `csp-page.mjs`: one browser, closed at the end: the four classes on a page under the strict
  policy of the wallet tools (standard mode), their startup checks and a few quick operations on
  the public BIP39 test phrase, then the same page without `'wasm-unsafe-eval'`, with every request
  that leaves the page and every uncaught error. It runs Argon2's 1 MiB known answer once and no
  Argon2 operation.

Expected output at this snapshot: `static-scan.mjs` exits 1 (S1c: a doc comment without its code
in `MhfeErrorCode`; S3a/S3b: the export list of `docs/API.md`), `api-probes.mjs` exits 1 (P2 and
P3), and `csp-page.mjs` exits 0 in both browsers. The AUD-014 regression
`docs/audits/AUD-014-harnesses/integration/gate-race.mjs` was also rerun (`--controlled` and
`--wasm`) and passes.
