# Documented browser check() shape (AUD-024, verifier role verify-doc-check-shape)

Audit AUD-024 at commit b6fca69. `check-doc-check-shape.py` compares the browser package's
documentation with what the package declares and exports:

- `web/client.d.ts` declares `check()` as `{ outcome, path, evidence }` with `matchingLengths` and
  `passed` in the evidence, the rekey result's `rehearsal`, and `MhfeClient.keepOldContainer()`;
  `src/wasm_api/core.rs` exports `keepOldContainer`.
- `docs/API.md`, `docs/BROWSER-PACKAGE.md` and, when present, `dist/README.md` (written from
  BROWSER-PACKAGE.md by `scripts/write-package-manifest.mjs`) document no `matches` field and no
  two-field evidence `{ builtInCheck, walletCheck }`.
- The MhfeClient listing of docs/API.md (from `// core/client.js` to `// repair/repair.js`) names
  `keepOldContainer` and `rehearsal`, its WebAssembly exports paragraph names `keepOldContainer`,
  and it does not state that `{ words: n }` matches when any short length passes.

Inputs: the working tree (read only); `dist/README.md` from the coordinator's baseline build, if
present (skipped otherwise).

Command, from the mhfe repository root:

```sh
python3 docs/audits/AUD-024-harnesses/verify-doc-check-shape/check-doc-check-shape.py
```

Expected output once the documents are fixed: only `ok` lines (or `skip` for an absent
dist/README.md), then `0 check(s) failed`, exit 0. At b6fca69 it prints 7 FAIL lines (API.md:775,
BROWSER-PACKAGE.md and dist/README.md:117/122/124, the listing without keepOldContainer and
rehearsal, the exports list without keepOldContainer, API.md:784) and exits 1.
