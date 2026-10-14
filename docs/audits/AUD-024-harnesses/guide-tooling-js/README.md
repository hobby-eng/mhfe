# AUD-024 guide-tooling-js harnesses

Audit AUD-024, role guide-tooling-js (coding-guide conformance and test fidelity of the
JavaScript tooling), reviewed commit `b6fca69238344dd2525b06270ee6ff3b055e68c1` of `mhfe`.

Each script checks one claim of the repository's tooling and exits non-zero when the check fails.
Run them from the repository root. They need Node.js 26.10.0; `tsc-declarations.mjs` also needs
the tools of `pnpm install --frozen-lockfile` (`node_modules/.bin/tsc`). None runs Docker,
Emscripten, Argon2 at suite cost or the network. The scripts that take a scratch folder write only
into it.

## `argon2-wasm-stage.mjs`

Does the `argon2-wasm` stage of `packaging/Dockerfile.reproducible` copy every script its Node
steps need? It reads the stage's `COPY` instructions, rebuilds the stage's `/workspace` from the
working tree in the scratch folder, checks every relative import of the copied scripts, and runs
`node scripts/verify-vendored-argon2.mjs` there as `scripts/build-argon2-wasm.sh` does in the
stage. A control then adds the missing imports and runs the gate again.

```sh
node docs/audits/AUD-024-harnesses/guide-tooling-js/argon2-wasm-stage.mjs <scratch folder>
```

Expected at `b6fca69`: exit 1, with
`FAIL scripts/verify-vendored-argon2.mjs imports ./gate-command-line.mjs`, the gate's
`ERR_MODULE_NOT_FOUND` for `<stage>/scripts/gate-command-line.mjs`, and the control line
`control: with the missing imports added, the gate exits 0`.

## `pinned-copies.mjs`

Does `scripts/verify-pinned-versions.mjs` see every copy of the vendored Argon2 commit and of the
wasm-bindgen version? It extracts `git archive HEAD` into the scratch folder, runs the gate there
unchanged, then once for each changed copy: three copies in `THIRD_PARTY_NOTICES.md` that the
gate's list leaves out, and two listed copies as controls.

```sh
node docs/audits/AUD-024-harnesses/guide-tooling-js/pinned-copies.mjs <scratch folder>
```

Expected at `b6fca69`: exit 1; the unchanged tree passes, the three `THIRD_PARTY_NOTICES.md`
changes print `FAIL ... gate exit 0`, and the two controls print `ok ... gate exit 1`.

## `single-module-owners.mjs`

Does `scripts/verify-single-modules.mjs` look for the vectors of every part outside a module's
set? It reads the gate's `OWNERS` table from its source, lists every `known_answers` file under
`src/`, `src/mhfe/published_rounds.rs` and the fixtures `src/validation_fixtures.rs` builds in, and
names each file the gate does not read with the vector texts (the gate's own `isVectorText`) that no
file it reads holds. Reads only.

```sh
node docs/audits/AUD-024-harnesses/guide-tooling-js/single-module-owners.mjs
```

Expected at `b6fca69`: exit 1, with `FAIL` lines for `src/engine/known_answers.rs` (8 texts),
`src/mhfe/published_rounds.rs` (677 texts) and `tests/fixtures/suite4-vectors/validation-cases.json`
(89 texts), and `ok` for the 19 files of `OWNERS` and the suite 3 fixture.

## `tsc-declarations.mjs`

Does the browser package's type check (`pnpm run check:types`) check the classes against their
declarations, as TS-13, `AGENTS.md` and `scripts/check-fast.sh` say? It copies `web/` into the
scratch folder and runs the repository's `tsc` on the copy: unchanged, then with one difference at
a time between `client.js` and `client.d.ts`, and a control type error inside `client.js`.

```sh
node docs/audits/AUD-024-harnesses/guide-tooling-js/tsc-declarations.mjs <scratch folder>
```

Expected at `b6fca69`: exit 1; the unchanged copy passes; `client.js loses its keepOldContainer()
method` and `client.d.ts declares a method that client.js does not have` print `FAIL ... tsc exit 0`;
the return type of `mode()` and the control print `ok ... tsc exit 1`.

## `browser-suite-methods.mjs`

Does the real-browser suite (`scripts/verify-browsers.mjs`, page code in `scripts/browser-check/`)
call every method that `MhfeClient`, `MhfeRepair`, `MhfePasswords`, `MhfeWallet` and their base
`MhfeModuleClass` declare in `web/*.d.ts` (CORE-33)? It counts `.<method>(` in the page code, which
calls the classes only, and, for information, in `scripts/package-check/`. Reads only.

```sh
node docs/audits/AUD-024-harnesses/guide-tooling-js/browser-suite-methods.mjs
```

Expected at `b6fca69`: exit 1; 34 `ok` lines and one
`FAIL MhfeClient.keepOldContainer() (web/client.d.ts): 0 calls in the browser suite, 1 calls of that
name in the package check` (that one call is the raw binding `core.keepOldContainer` in
`scripts/package-check/core-rekey.mjs`).
