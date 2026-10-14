# AUD-024 verifier harness: type assertions that stand in for checks in the browser package

Audit AUD-024, commit b6fca69 (branch aud023-remediation). Review only; not part of the package.
Rule TS-04 (`.github/instructions/code-typescript.instructions.md`): a type assertion is `as const`,
or sits in a function that parses outside input after it has checked the shape, with a comment
that names the check. These scripts show what some of the JSDoc casts of `web/` let through.

## What each script checks

- `check-unchecked-casts.mjs` loads the package's classes as `scripts/verify-browser-package.mjs`
  does (from `dist/`, with its stand-in `Worker` from `scripts/package-check/`) and drives:
  1. control: a rekey confirmed by the owner, whose worker asks `ownerCheck`;
  2. and 3. a rekey confirmed by a fingerprint or by the built-in check, whose worker asks
     `ownerCheck`. `web/client.js:769` casts `owner` (`PageOwner | undefined`) to `PageOwner`.
     Expected `PACKAGE_MISMATCH` (docs/API.md: a message of the worker the page does not know);
  4. a core self-check report without `parameters` (cast at `web/client.js:1086`) and 5. a null
     module self-check result (cast at `web/runtime.js:1150`). Expected an `MhfeError`, which
     docs/API.md says every error other than a wrongly typed argument is.
- `check-shared-bytes-compile.mjs` asks Node.js and the Playwright Chromium and Firefox whether
  `WebAssembly.compile` rejects bytes over a `SharedArrayBuffer`, the check that the comment of the
  cast at `web/runtime.js:98-100` names.
- `uncast-tsc.sh` copies `web/` to a scratch folder (default `../tmp/aud024/verifier-type-assertions/
  web-uncast`, or `$AUD024_SCRATCH/web-uncast`), removes five casts there and runs the page-side
  type check on the copy. It never writes to `web/`.

## Inputs

`dist/` and `target/wasm-bindgen/` as the AUD-024 baseline built them at b6fca69 (read only),
`web/` of the working tree, `node_modules` (TypeScript 7.0.2, Playwright with its Chromium and
Firefox). No real worker, no Argon2 rounds, no network, only the package check's own test strings.

## Commands, from the repository root

```sh
node --no-warnings docs/audits/AUD-024-harnesses/verifier-type-assertions/check-unchecked-casts.mjs
node --no-warnings docs/audits/AUD-024-harnesses/verifier-type-assertions/check-shared-bytes-compile.mjs
bash docs/audits/AUD-024-harnesses/verifier-type-assertions/uncast-tsc.sh
```

## Expected output

- `check-unchecked-casts.mjs`: exit 0 and four `ok` lines once the casts are replaced by checks.
  At b6fca69 it exits 1: the control resolves; cases 2 and 3 reject with `CALLBACK_FAILED` "The
  page's ownerCheck callback failed." and the cause "TypeError: owner is not a function"; cases 4
  and 5 reject with a plain `TypeError` ("Cannot read properties of undefined (reading 'maxPim')",
  "Cannot read properties of null (reading 'version')"). Exit 2 means the control failed, so the
  harness no longer fits the package.
- `check-shared-bytes-compile.mjs`: exit 0 when every engine rejects the shared bytes. At b6fca69
  it exits 1: Node.js 26.10.0, Chromium 156 and Firefox 157 all compile them.
- `uncast-tsc.sh`: exit 1 at b6fca69, with tsc errors at `client.js:769`, `client.js:1086`,
  `runtime.js:1158-1159` and `wallet.js:304` of the copy (the casts are what keep tsc quiet there)
  and none at `runtime.js:100` (that cast is not needed by tsc 7.0.2). Exit 0 would mean none of
  the five casts is needed any more.

Evidence logs: `docs/audits/AUD-024-evidence/verifier-type-assertions/vta01-*.log` to `vta04-*.log`.
