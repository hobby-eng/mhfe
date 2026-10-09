# AUD-012 quality probes

`clone-checker.mjs` executes the unchanged `scripts/verify-no-copies.mjs` in a Node VM with in-memory synthetic source files. Only the imports and `import.meta.url` are adapted to inject file-system functions. No project directory or production file is copied, edited or created by the probe.

The reviewed checkout is the uncommitted MHFE AUD-012 source snapshot rooted at commit `abb16671b641378c0fc3c4d855f8d126498e754b`; the coordinator's source fingerprint identifies the exact reviewed bytes. Inputs are generated public arithmetic functions. No dependencies beyond the pinned Node runtime are needed.

Run from the MHFE repository root:

```sh
/home/user/.local/bin/node docs/audits/AUD-012-harnesses/quality/clone-checker.mjs
```

The positive control must exit 1 inside the checker for ordinary duplicated code. The probe then reports results for a duplicated exported function with a `from` parameter, an invalid token threshold and a one-sided deliberate-copy marker. On the reviewed baseline the first two incorrectly pass the checker, so the harness exits nonzero at its assertion. After corrections both acceptance assertions must pass and the harness exits zero. The one-sided marker result is informational: it records the exemption's current breadth without assigning a contract failure by itself.

This tests the checker's parsing and argument validation, not the absence of semantic duplication or the whole-program correctness of MHFE.

Owner-authorized documentation-only amendment of 2026-10-09: commit references of the history replaced by the second privacy rewrite of 2026-10-09 now name the commits that replaced them: ca0086acf545d07bfe008ae340554124a48442bf -> abb16671b641378c0fc3c4d855f8d126498e754b.
