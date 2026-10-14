# AUD-024 harness: Argon2 lane residue (gap-1-browser-argon2-heap-residue)

Audit AUD-024, commit b6fca69238344dd2525b06270ee6ff3b055e68c1 (branch aud023-remediation, clean
tree). The harness checks that an Argon2 call leaves no bytes from which its output can be rebuilt.
That output is a round key `K_i` of MHFE. The check covers the browser package's two Emscripten
builds and the native engine. It runs at reduced cost with public data only. It never runs
Argon2 at 2 GiB.

## What it checks

- `lane-stacks.c`, the native engine. It links the `libargon2.a` of `cargo build --release` and
  calls `argon2_ctx` as `src/engine/ffi.rs` does: four lanes on four threads, the work area handed
  out by a callback, and the SSSE3 flag in bit 31 where the processor has it. It searches every
  private writable mapping of the process for each lane's last block, read through
  `/proc/self/mem`. It then rebuilds the tag from what it finds, and searches again after a later
  1 MiB call and after an unrelated thread.
- `residue-node.mjs <root> bridge <KiB>`: `dist/core/argon2-mt.js` and `argon2-st.js` through the
  page's bridge `web/argon2-engine.js`, loaded as `scripts/package-check/package.mjs` loads them.
  It runs secret calls A, B and C (C with two passes), each followed by the 1 MiB known answer.
  After each step it searches the Emscripten heap.
- `residue-node.mjs <root> operations <KiB>`: the package's WebAssembly core runs whole
  operations with the rounds at `<KiB>` and one pass, and the known answers at their own cost. The
  operations are an encryption with its rehearsal (24 rounds, then the known answer) and a session
  of hidden wallets after one wallet, while it waits for the page and after `free()`.
- `residue-browser.mjs <root> <KiB>`: the same bridge check in a Blob worker of Playwright's Chromium
  and Firefox. The page is cross-origin isolated through `page.route()` with COOP and COEP, so no
  socket is opened. The lane workers run `argon2-mt.js` from a Blob, as in fast mode.

Each search uses the lane's last block that `blocks.c` computes. `blocks.c` is the vendored
`ref.c`, built natively and single-threaded with `FLAG_clear_internal_memory = 0`. Its 1 MiB tag
equals the repository's OpenSSL known answer `e0e8eba3…5df2`. A block counts as found as a copy, or
as the XOR of two adjacent 1024-byte windows: `ref.c` `fill_block` computes
`next_block = block_tmp ^ blockR` from two stack locals. When every lane's block is found, the tag
is rebuilt from the found bytes with Python's `hashlib`. RFC 9106 3.2 and 3.3 define it as
BLAKE2b-256(LE32(32) || XOR of the four last blocks). The rebuilt tag is compared with the call's
output. The heap is also searched for the password, salt and key bytes, and for the first, second
and middle block of each lane, which a wiped work area must not hold. Lane stacks are located by
hooking `Worker.prototype.postMessage`, which the glue's `spawnThread` calls with
`{ cmd: 2, pthread_ptr }`. The stack bounds are read at `pthread_ptr + 48` and `+ 52`, as the
glue's `establishStackSpace` reads them.

## Inputs

- The repository at b6fca69 with the browser package built (`dist/`, `target/wasm-bindgen/mhfe.js`).
- `libargon2.a` from `cargo build --locked --release` with any `CARGO_TARGET_DIR`. For this audit it
  was `/home/user/Documents/bip_tools/tmp/aud024/target/release/build/mhfe-experimental-1ebf7d5f2c253740/out/libargon2.a`,
  SHA-256 `507fbba5d6daf3f3ea6237d34dc8e059c5f091a6c4d85ba83dfb22cca00a2c9d`.
- gcc, Node.js 26, Python 3. For `--browsers`, Playwright 1.64 with its Chromium and Firefox.

## Command, from the repository root

```sh
docs/audits/AUD-024-harnesses/gap-1-browser-argon2-heap-residue/run.sh \
  "$CARGO_TARGET_DIR/release/build/mhfe-experimental-1ebf7d5f2c253740/out/libargon2.a" --browsers
```

## Expected output at b6fca69

The harness exits 1, because the check fails:

- Native: `after the secret call returned (lane threads joined)` finds each lane's last block once,
  as a copy in the glibc-cached stacks of the four lane threads. The rebuilt tag `YES` equals the
  call's output. After the later 1 MiB call nothing is found. The run ends with `FAIL`.
- `bridge`, threaded build: after secret A, and still after the known answer that follows, each
  lane's last block is found as one XOR pair, 5136 bytes below the top of the stack of the thread
  that ran that lane's last segment. The addresses are 33694896, 33770912, 33846928 and 33922944
  at 32 MiB, and `keyRebuiltFromHeap` is true. Secret B, of the same size, overwrites A's residue
  and leaves its own. No copy of the password, salt or key and no inner work-area block is found.
  Single-threaded build: only lane 3 is found, at 62544, and only before the known answer. The key
  is never rebuilt.
- `operations`, threaded build: after the encryption returns, rounds 1 and 24 are rebuilt. Round
  24 of the rehearsal recomputes round 1's key `K_1`. The session of hidden wallets rebuilds its
  last round's key while it waits for the page and after `free()`. Single-threaded build: nothing
  is rebuilt.
- `--browsers`: in Chromium and Firefox, the threaded build gives the same four XOR pairs, and the
  tag is rebuilt after the known answer (`tagRebuiltFromHeapAfterKnownAnswer: true`). The
  single-threaded build gives `not every lane found`.

After a fix, every step prints PASS or exits 0, and the harness exits 0.

## Supporting probes

The probes in `probes/` are not part of the pass/fail check. The evidence folder
`docs/audits/AUD-024-evidence/gap-1-browser-argon2-heap-residue/` keeps their logs.

- `bridge-edges.mjs <root>` (`g1-bridge-edges`). `_malloc(0)` is not 0. An empty password goes
  through the bridge and gives the reference tag. Refused inputs give
  `ARGON2_FAILED: the reference code returned error -6`, `-14`, `-12` and `-15`. No copy of the
  password stays after the refused calls.
- `wipe-bound.mjs <root>` (`g1-wipe-bound`). This is the measure of
  `scripts/package-check/argon2-faults.mjs` `checkArgon2Wipe`, applied to both builds. The
  single-threaded build leaves about 2,291 non-zero bytes and the threaded build about 12,612.
  Both are below the 16 KiB bound, so the package check would not tell the threaded residue
  apart.
- `h0-search.mjs <root>` (`g1-h0-search`). H0 is computed with `hashlib`. The probe checks it
  against `blocks.c` by rebuilding the first block of lane 0. Neither H0, its first 16 bytes nor
  the password is found in either build, after the secret call or after the known answer.
- `residue-browser-terminate.mjs <root> <KiB>` (`g1-browser-lane-workers`). It is
  `residue-browser.mjs` with a count of the workers that Playwright sees. There are 5 workers (the
  operation worker and four lane workers) before the operation worker is terminated, and 0 two
  seconds after, in Chromium 156 and Firefox 157.
- `source-lines.sh <root> <pretty-printed argon2-mt.js>` (`g1-source-lines`) prints the lines that
  the findings cite.

Each `.mjs` probe takes the compiled `blocks` helper from `MHFE_BLOCKS`, or from this folder.
