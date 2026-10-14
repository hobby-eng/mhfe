# CLI and browser feature parity gaps (AUD-024, commit b6fca69)

Audit AUD-024, role gap-1-cli-browser-feature-parity, at commit
b6fca69238344dd2525b06270ee6ff3b055e68c1. The role mapped every option and question of the ten
user commands of `mhfe`, and every application requirement of mhfe_spec/README.md, to the browser
package's classes and bindings. `check-parity-gaps.mjs` turns the gaps it found into checks that
pass once each gap is closed.

## What it checks

- C1: `mhfe rekey` takes `--coin` and `--path` for a confirmation by address, as the confirmation
  `{ address, coin, path }` of `MhfeClient.rekey()` does. Asked with `--help`, so nothing runs.
- C2: `MhfeClient.parameters()` (the binding `suiteParameters`) gives the wallet check's bits or
  odds, which `mhfe check` states beside a result that is not verified.
- C3: the duty in `docs/BROWSER-PACKAGE.md` about a same-length container names a mistyped setting,
  not only a wrong password (mhfe_spec/README.md, suite 4: "a mistyped password or setting is not
  detected").
- C4: `MhfeClient.rekey()` in `web/client.d.ts` gives the other lengths that detection would read
  before it seals, as `mhfe rekey` warns of them before the new password.
- C5: `mhfe check` lists the original seed phrase's own checks that passed beside "does not match"
  too, as the browser's `evidence.passed` does (the `DoesNotMatch` arm of `report()` in
  `src/bin/mhfe/check.rs`).

C3 to C5 read the sources; C4 and C5 look for a field name or a call in one block, so a fix in
another shape needs this script adjusted.

## Inputs

- A release or debug build of the commit, by default `target/release/mhfe`. The audit used one
  built with `CARGO_TARGET_DIR=/home/user/Documents/bip_tools/tmp/aud024/target`.
- The browser package of the same commit as `scripts/build-wasm.sh` writes it:
  `target/wasm-bindgen/mhfe.js` and `dist/runtime/mhfe.wasm`.

No secret and no Argon2 work: the program is only asked for its help, and the bindings only for
their fixed values.

## Command (from the repository root)

```sh
node docs/audits/AUD-024-harnesses/gap-1-cli-browser-feature-parity/check-parity-gaps.mjs /home/user/Documents/bip_tools/tmp/aud024/target/release/mhfe
```

## Expected output at b6fca69

All five checks fail and the script exits 1:

```text
FAIL C1 mhfe rekey takes --coin and --path: exit 2: ✗ Error: Unexpected argument '--coin' found
FAIL C2 MhfeClient.parameters() gives the wallet check's bits or odds: keys version, suiteId, ...
FAIL C3 BROWSER-PACKAGE.md says a same-length container does not detect a mistyped setting: ...
FAIL C4 MhfeClient.rekey() gives the other detected lengths before the seal: ...
FAIL C5 mhfe check lists the checks that passed beside "does not match": ...
5 check(s) fail.
```

Once the gaps are closed it prints `ok` for each check, then `Every check passes.`, and exits 0.
