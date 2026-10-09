# Browser Refusal Probe

This AUD-011 harness checks the live browser class's hidden-session request encoding. The audit report records the reviewed dirty-source fingerprint. Inputs are synthetic text and one unpaired surrogate; no real wallet data or secret bytes are printed.

Run from the MHFE repository root using the configured Node.js:

```sh
node docs/audits/AUD-011-harnesses/browser/secret-refusals.mjs
```

The harness imports production JavaScript as in-memory modules. It replaces workers with a message stub and makes the startup gate resolve to isolate encoding: this is not evidence of browser execution or startup cryptography. It instruments TextEncoder to observe the package-owned first password buffer, then supplies a repetition that encoding must refuse. The buffer must be wiped on that refusal.

On the reviewed snapshot the assertion fails and exits nonzero because the buffer remains nonzero. After remediation the check prints one PASS line and exits zero. The harness writes no files and builds no artifacts. Its synthetic buffer is wiped during cleanup regardless of the result.
