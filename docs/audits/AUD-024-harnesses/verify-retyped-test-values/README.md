# verify-retyped-test-values (AUD-024)

Audit AUD-024, verifier role verify-retyped-test-values, at commit
b6fca69238344dd2525b06270ee6ff3b055e68c1 (branch aud023-remediation). It checks the candidate
finding that the JavaScript tooling types its shared test data and helpers again in several
scripts instead of importing them from the modules that hold them (CORE-10):

- P1: `ZERO_24` defined in `scripts/browser-check/page-values.mjs` with the value that
  `scripts/public-test-data.mjs` exports.
- P2: the known-answer cost list `["1024/1", "65536/3", "262144/2"]` typed in more than one file.
- P3a-d: `scripts/verify-cli-browser-parity.mjs` keeps its own copies of `pageMessageOf`
  (`packageError`, same body but its assertion message), of the package loader of
  `package-check/package.mjs`, of the known-answers-only Argon2 stand-in, and of `encode`/`noBytes`.
- P4: `scripts/build-browser-check.mjs` types the public phrase, the full-size container and the
  BIP84 address, and imports nothing of `public-test-data.mjs`.
- P5: the list of bundled class files in more than one file.
- P6: values that `page-values.mjs` and `package-check/test-values.mjs` both define.
- P7: `package-check/class-self-checks.mjs` defines `pagePart` with its own label table although it
  imports `part()` of `self-checks.mjs`, whose labels (from `public-test-data.mjs`) are the same.
- P8: no "deliberate copy" marker in the tooling's `.mjs` files (the copy gate itself aside).

Inputs: the working tree's `scripts/` (clean at b6fca69 apart from the untracked audit folders).
Needs Node.js. It imports only `public-test-data.mjs`, `browser-check/page-values.mjs` (which
computes public BIP32 fingerprints with node:crypto) and `package-check/test-values.mjs`, which
have no side effects; the other scripts are read as text. No build output, no secret, no Argon2.

Command, from the repository root:

    node docs/audits/AUD-024-harnesses/verify-retyped-test-values/retyped_test_values.mjs

Expected at b6fca69: `PRESENT` for P1 to P8 (11 parts), `11 of 11 parts present`,
`DEFECT REPRODUCED` and exit 1. Once each value and helper has one source, it prints
`DEFECT NOT REPRODUCED` and exits 0.

Log: `docs/audits/AUD-024-evidence/verify-retyped-test-values/v01-retyped-test-values.log`,
written by `docs/audits/AUD-024-harnesses/run-logged.sh`.
