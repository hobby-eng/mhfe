# AUD-024 verifier harness: a page callback that fails after its job has ended

Audit AUD-024, commit b6fca69 (branch aud023-remediation). Review only; not part of the package.

## What it checks

`check-workerjob-late-callback-failure.mjs` imports `web/runtime.js` from the repository root and
drives one `WorkerJob` per case with a stand-in `Worker` that answers "ready" and then sends either
news (`progress`) or a question (`ask`). The page handler ends the job, as `cancel()` does through
`WorkerJob.stop`, and then fails. A failure that comes after the job has ended must stay the page's
own unhandled rejection or uncaught exception, as the comment of `WorkerJob.callPage` says
(web/runtime.js:420-422) and rule CORE-22 requires ("none is swallowed").

Cases:

1. control: an async news handler rejects after the end (`callPage`, web/runtime.js:419-424);
2. a synchronous news handler throws after the end (`callPage`, web/runtime.js:426-428);
3. an async `ask` handler (`ownerCheck`) rejects after the end (`#answer`, web/runtime.js:443-452);
4. a synchronous `ask` handler (`noLength`) throws after the end (`#answer`);
5. informational: an `ask` handler (`confirmAgain`) that fails while the job runs ends it with
   `CALLBACK_FAILED`.

## Inputs

`web/runtime.js` of the working tree. No WebAssembly, no Argon2, no secrets, no network.

## Command, from the repository root

```sh
node --no-warnings docs/audits/AUD-024-harnesses/verify-late-answer-callback/check-workerjob-late-callback-failure.mjs
```

## Expected output

Exit 0 and four `ok` lines once every late failure is reported. At b6fca69 it exits 1: case 1 is
`ok`, cases 2 to 4 are `FAIL` with empty unhandled-rejection and uncaught-exception lists. Exit 2
means the control failed, so the harness itself no longer fits the runtime.
