# AUD-024 verify-wasm-stack-residue harness

Audit AUD-024, verifier role verify-wasm-stack-residue, reviewed commit
`b6fca69238344dd2525b06270ee6ff3b055e68c1` (branch aud023-remediation).

## What it checks

`stack-residue.mjs` looks in the browser package's WebAssembly memory for wallet secrets left
below the stack top, the dead shadow stack, after a call has returned. It reads the stack top
(the initial value of global 0, `__stack_pointer`) and the lowest data segment from
`dist/runtime/mhfe.wasm`, and stops with exit 2 unless `[0, stack top)` holds no data. It computes
its needles itself with `node:crypto`: the BIP39 seed (in two halves), the BIP32 master private key
and chain code, and the PBKDF2 salt block `mnemonic` + passphrase.

1. `walletFingerprint` on BIP39's published 12-word vector (`abandon` x11 `about`, passphrase
   `TREZOR`, xprv9s21...UsAF).
2. `walletCheck` on BIP39's published 24-word vector (`abandon` x23 `art`, passphrase `TREZOR`).
3. A session of hidden wallets at its wait for the page, the point at which `web/core-worker.js`
   awaits `host.ask("opened")` right after `session.open` returns. It runs at the package check's
   reduced cost (rounds at 256 KiB and one pass, the Argon2 known answers at their own costs), on
   `REDUCED_COST_CONTAINER` with the public test passwords.

In each case, a control then zeroes `[0, stack top)` with no WebAssembly frame active. It shows that
no copy remains and that the module still works: a later call, and in case 3 the
`PASSWORD_ALREADY_USED` refusal and another wallet of the same session.

## Inputs

Public test data only: BIP39's published vectors, `REDUCED_COST_CONTAINER` from
`scripts/public-test-data.mjs` and the public test passwords from
`scripts/package-check/test-values.mjs`. It needs `dist/runtime/mhfe.wasm`, `dist/core/argon2-st.js`
and `target/wasm-bindgen/mhfe.js` from `scripts/build-wasm.sh`, which it reads through
`scripts/package-check/package.mjs`. It also needs Node 26. No network is used and no Argon2 runs
at suite cost.

## Running

From the repository root:

```sh
node docs/audits/AUD-024-harnesses/verify-wasm-stack-residue/stack-residue.mjs
```

## Expected output at b6fca69

It exits 1. One copy each of the master key and chain code stays after `walletFingerprint`, at
1048129 and 1048161. The seed halves (1045104, 1045136) and two salt blocks (1046888, 1047288)
stay after `walletCheck`. The hidden wallet's master key and chain code (1047937, 1047969) stay at
the session's wait. Every control finds no copy after the scrub, and the module and the session
still work. The last line is:

```text
FAIL: 8 copies of a seed, master key, chain code or passphrase salt block stay below the stack top after the calls
```

After a fix that zeroes the dead stack in the worker, the same check run through the worker's call
path prints `PASS` and exits 0.
