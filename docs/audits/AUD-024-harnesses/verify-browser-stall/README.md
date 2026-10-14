# verify-browser-stall (audit AUD-024, commit b6fca69)

What it checks: that the wait loop of `scripts/verify-browsers.mjs` (`pageOutcome`, `partialOutcome`
and `ask`, read verbatim from the file at run time) calls a page stopped within twice its stall
limit when the page's script never starts. The comment at `scripts/verify-browsers.mjs:73-77` says
a page that goes `STALL_MS` without a result or drawing report has stopped and fails.

The loop runs with scaled constants (`STALL_MS` 6 s, `PAGE_LIMIT_MS` 30 s, `POLL_MS` 1 s) in
Chromium and Firefox (the browsers Playwright installed for the repository) against four small
`file://` pages:

- `csp-refused`: an inline module whose hash is not the page policy's, so the browser refuses it;
- `parse-error`: an inline module with two `const` declarations of one name;
- `unbundled-import`: an inline module with an `import` that the policy (`script-src` hash only)
  refuses;
- `record-then-silent` (control): sets `window.mhfeProgress` as `pageRecord` does, then stops.

Inputs: none besides the repository's `scripts/verify-browsers.mjs` and its installed
`node_modules/playwright` with Chromium and Firefox. No package build, no Argon2, no network; the
generated loop module and pages go to a new folder under the system's temporary directory.

Command, from the repository root:

```sh
node docs/audits/AUD-024-harnesses/verify-browser-stall/probe.mjs
```

Expected output at b6fca69 (the defect present), exit status 1:

```text
chromium ... csp-refused: stopped after 30 s: ["the page did not end within 0.5 minutes, in \"starting\""]; page errors 0; ...
chromium ... parse-error: stopped after 0 s: ["an uncaught error stopped the page's script, in \"starting\""]; page errors 1; ...
chromium ... unbundled-import: stopped after 30 s: ["the page did not end within 0.5 minutes, in \"starting\""]; page errors 0; ...
chromium ... record-then-silent: stopped after 6 s: ["no result or drawing report for 6 s, in \"checkA\""]; ...
(the same four lines for firefox)
FAIL: a page whose script never started was not reported within 2 * STALL_MS
```

With the defect fixed, `csp-refused` and `unbundled-import` stop after about 6 s in both browsers,
the last line is `ok` and the exit status is 0.
