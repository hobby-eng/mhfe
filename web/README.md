# MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics — Browser API

The browser build exposes a synchronous WASM engine and an asynchronous Worker
adapter. Applications should use the Worker adapter so a 30–120 second KDF does
not freeze the document UI.

Build with `scripts/build-wasm.sh`, serve `dist/` over HTTP, and create a client:

```js
import { MhfeWorkerClient } from './client.js';

const wasmBytes = /* Uint8Array embedded in the standalone HTML */;
const client = MhfeWorkerClient.fromUrl(
  new URL('./mhfe-worker.js', import.meta.url),
  wasmBytes,
);
const parameters = await client.ready();
const encrypted = await client.encryptAscii(mnemonic, password, 0);
```

Encryption returns `apiVersion`, `suiteId`, `pim`, `effectivePasses`,
`sourceWords`, and `encryptedMnemonic`. Decryption returns the same public
context plus `recoveredMnemonic` and `recoveryVerifier`. That verifier status is
`matched` for 12/15/18/21-word sources and `unavailable` for a 24-word source,
whose 256-bit payload leaves no room for an internal verifier. The normal browser API
does not expose packed plaintext, entropy, round keys, salts, or masks. Those
values exist only in the explicitly test-only CLI vector command.
`client.d.ts` defines the complete public Worker-client contract.

Use `decryptAsciiAuto` or `decryptPreNormalizedUtf8Auto` for the standard
recovery flow. The Worker tests all 12-, 15-, 18-, and 21-word verifier layouts
after one inverse permutation. One match selects that length, no match falls
back to 24 words, and multiple matches fail with `AMBIGUOUS_SOURCE_WORDS`; its
message lists every matching length. The explicit-length methods remain
available as a user override.

`cancel()` terminates the Worker because a synchronous Argon2id invocation
cannot process a cancellation message while running. Create a new client for a
retry. Normal `disposeEngine()` runs the Rust destructor and its best-effort
zeroization. Forced Worker termination discards the Worker realm without a
guarantee that Rust destructors execute. Only one engine and one 512 MiB work
area are retained by a Worker.

The `*PreNormalizedUtf8` methods accept bytes that the caller has already
normalized using the specification's exact Unicode 18 NPSS-NFKD procedure.
They validate UTF-8 and length but cannot prove normalization. The `*Ascii`
methods are self-contained and exact. JavaScript strings cannot be reliably
erased; transferred password byte arrays are copied and wiped where reachable.

The Worker performs no network requests and does not invoke the generated
`wasm-bindgen` fetch-based initializer. Its caller must pass a
`WebAssembly.Module`, `Uint8Array`, or `ArrayBuffer` during construction. A
consuming standalone HTML artifact should bundle the reviewed Worker and
generated binding source, embed the WASM bytes, keep `connect-src 'none'`, and
allow only the Blob Worker it creates. The Worker is a responsiveness boundary,
not an independent security vault.
