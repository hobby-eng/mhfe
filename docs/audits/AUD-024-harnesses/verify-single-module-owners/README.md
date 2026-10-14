# AUD-024 verifier harness: vectors the single-module gate never looks for

Audit AUD-024, verifier of the candidate finding "scripts/verify-single-modules.mjs never looks
for the vectors of the argon2 and cipher-rounds parts or of the suite 4 fixture", reviewed commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1`.

What it checks: whether `scripts/verify-single-modules.mjs` looks, in each browser module built
alone, for the vector texts of every source that a `browser-core` or `browser-repair` build
compiles in. The harness evaluates the gate's own `OWNERS`, `COINCIDENCES`, `formatsVectors` and
`foreignVectors`, sliced unchanged from the gate's source, so it tests the gate's code and not a
copy. For each source that `OWNERS` does not name, and each module outside that source's owners,
it counts the vector texts (the gate's `isVectorText`, runs of 3 or more distinct characters, no
coincidence) that:

- the gate never looks for in that module;
- the owner's WebAssembly carries as text;
- that module's WebAssembly does not carry today.

The sources checked are `src/engine/known_answers.rs`, `src/mhfe/published_rounds.rs`,
`tests/fixtures/suite4-vectors/validation-cases.json` (`SUITE_4`),
`tests/fixtures/suite3-vectors/zero-12.json` and
`tests/fixtures/suite4-vectors/same-length-zero-12.json` (the self-test's `include_str!`), and
`src/self_check.rs` (`ZERO_12_CONTAINER`, core and repair). A control then appends one such text
to the passwords WebAssembly and applies the gate's carried-vector test
(`scripts/verify-single-modules.mjs:149-154`). For comparison, it also appends a text of an
`OWNERS` file, which that test must find.

Inputs: the four single-module WebAssembly files that the gate's baseline run built at this commit,
`target/single-modules/{core,repair,passwords,wallet}/mhfe_bg.wasm`. The harness only reads them
and builds nothing. It uses public test data only. It runs no Argon2 and needs node only.

## Running

From the repository root:

```sh
node docs/audits/AUD-024-harnesses/verify-single-module-owners/unread-vectors.mjs
```

## Expected output at b6fca69

The harness exits 1. For every unread source and every module outside its owners it prints a
`GAP` line, for example:

- `GAP passwords: 80 texts carried by core and never looked for` for `published_rounds.rs`.
- 84 to 87 texts for the suite 4 validation fixture.
- 76 to 79 texts for each self-test fixture.
- 1 text, the zero-12 container, for `src/self_check.rs` in passwords and wallet.
- 2 texts, `Argon2id` and `argon2-sizes`, for `src/engine/known_answers.rs`. That file's five
  tags and its RFC 9106 tag are compile-time bytes, which no owner's WebAssembly holds as text.

In the control, the text of `src/mhfe/known_answers.rs` gives `carried 1 -> gate fails`. Each
unread source's text gives `carried 0 -> gate passes`. The harness exits 0 once the gate looks for
all of these texts.

The evidence of the AUD-024 run is
`docs/audits/AUD-024-evidence/verify-single-module-owners/unread-vectors.log`.

## Second script: texts a naive fix would flag

`naive-fix-coincidences.mjs` has the same inputs, and it also treats `src/self_check.rs` as
core-only. For each module and source, it prints which never-looked-for texts that module's
WebAssembly already carries today. A fix that only adds these sources to `OWNERS` would
wrongly flag those texts.

Run it from the repository root:

```sh
node docs/audits/AUD-024-harnesses/verify-single-module-owners/naive-fix-coincidences.mjs
```

At b6fca69 it exits 1 and prints these `carries` lines:

- `0123456789abcdef` in repair, passwords and wallet: the hexadecimal alphabet. It is also
  `src/engine/known_answers.rs`'s salt.
- `0102030405060708` in passwords: part of the decimal digit table.
- `7075626c…` in passwords: that module's own password fixture.
- The zero-12 container in repair: repair's own `ZERO_12_CONTAINER`.

Its log is `docs/audits/AUD-024-evidence/verify-single-module-owners/naive-fix-coincidences.log`.
