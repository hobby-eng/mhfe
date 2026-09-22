# MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics — implementation API

This repository exposes one cryptographic core through three adapters. All
adapters implement `MHFE-BIP39-256-EXPERIMENTAL-2`; they do not define separate
formats. The normative protocol is defined in the
[companion MHFE specification](https://github.com/hobby-eng/mhfe-spec).

## Rust library

`MhfeEngine::new(pim)` validates `PIM` and allocates one reusable 512 MiB
Argon2id work area. `encrypt_mnemonic`, `decrypt_mnemonic`, and
`decrypt_mnemonic_auto` accept a
`NormalizedPassword` and return reduced operational results. Applications may
reuse an engine for sequential operations with the same PIM. The work area is
zeroized after every forward or inverse permutation and again on `Drop`.

`decrypt_mnemonic_auto` is the standard recovery path. After one inverse
permutation it checks every 12-, 15-, 18-, and 21-word layout. A unique match
selects that length, no match selects the 24-word interpretation, and two or
more matches return `AmbiguousSourceWords` with the complete matching-length
list. `decrypt_mnemonic` retains an explicit source length as a user override.
Each length defines exactly one candidate mnemonic; ambiguity can occur only
between different lengths.

`encrypt_vector` and `decrypt_vector` are separate, explicitly test-only APIs.
Their result objects include source entropy, packed state, round salts, Argon2id
outputs, and masks; those zeroizing objects must never be created or logged for
real inputs.

`NormalizedPassword::from_test_ascii` is an exact self-contained path for the
ASCII subset. `from_npss_nfkd_utf8` and its owned-buffer variant require bytes
that a conforming caller has already normalized with Unicode 18 NPSS-NFKD.
They validate UTF-8 and the 1..1024-byte protocol boundary but cannot prove the
normalization precondition.

The implementation deliberately does not call JavaScript
`String.prototype.normalize()`: its ICU/Unicode version is controlled by the
browser and is not the protocol's pinned Unicode 18 NPSS profile.

English mnemonic words are lowercase and case-sensitive. The BIP39 parser
accepts repeated whitespace between otherwise valid words and emits canonical
single-space lowercase output; it does not treat uppercase words as equivalent.

## Browser Worker client

`web/client.js` is the recommended HTML-facing adapter and `web/client.d.ts`
defines its complete typed contract. The constructor requires a
`WebAssembly.Module`, `Uint8Array`, or `ArrayBuffer`; the Worker initializes
synchronously from that supplied value and performs no fetch. This permits a
single-file consumer to bundle the Worker and generated binding source, embed
the reviewed bytes, and retain `connect-src 'none'`. The adapter provides:

- suite-parameter discovery and readiness;
- ASCII and pre-normalized UTF-8 encryption;
- ASCII and pre-normalized UTF-8 recovery with automatic source-length
  detection or an explicit override;
- engine disposal, Worker termination, and cancellation;
- structured errors with stable codes.

The Worker stages transferred password bytes into a zeroizing Rust object,
wipes its reachable JavaScript byte copy before the expensive operation, and
clears the Rust password in a `finally` path. JavaScript strings cannot be
reliably erased, so byte-oriented calls are preferable once a conforming
Unicode 18 normalizer is available. The Worker performs no network requests.

The normal browser response deliberately contains only public suite context,
the encrypted mnemonic, or the recovered mnemonic. It excludes entropy,
packed state, salts, Argon2 outputs, masks, and traces. Recovery returns
`recoveryVerifier: "matched"` for 12/15/18/21-word sources and
`recoveryVerifier: "unavailable"` for 24-word sources.

Cancellation terminates the Worker because the synchronous Argon2id call
cannot process another message while running. A cancelled client cannot be
reused; create a new Worker for a retry. Normal `disposeEngine()` invokes the
Rust destructor and its best-effort zeroization. Forced Worker termination
discards the Worker realm, but browser APIs do not guarantee destructor
execution during that termination path.

## CLI

The CLI is explicitly for public vectors and benchmarks. `--test-password` is
visible in process listings and shell history. The `vector` command includes
round secrets by design and must never be used with a real recovery phrase or
password.

## Error codes

The Rust/WASM layer uses these stable codes:

| Code | Meaning |
|---|---|
| `INVALID_MNEMONIC` | Source text is not a valid English BIP39 mnemonic. |
| `INVALID_CONTAINER` | Encrypted text is not a valid 24-word English BIP39 container. |
| `INVALID_SOURCE_WORDS` | Source length is outside 12, 15, 18, 21, or 24. |
| `INVALID_ENTROPY_LENGTH` | Direct library input is not 16, 20, 24, 28, or 32 bytes. |
| `INVALID_PIM` | PIM is outside 0..31. |
| `EMPTY_PASSWORD` | Normalized password is empty. |
| `PASSWORD_TOO_LONG` | Normalized UTF-8 exceeds 1024 bytes. |
| `INVALID_PASSWORD_UTF8` | Pre-normalized input is not valid UTF-8. |
| `UNSUPPORTED_UNICODE_PASSWORD` | Non-ASCII text was given to the ASCII-only helper. |
| `PASSWORD_NOT_SET` | Direct WASM use attempted an operation without staging a password. |
| `FIXED_POINT` | Encryption produced the unchanged packed state and was refused. |
| `RECOVERY_VERIFIER_MISMATCH` | Short-source recovery rejected the candidate. |
| `AMBIGUOUS_SOURCE_WORDS` | Two or more short layouts matched; the message lists every matching length. |
| `MEMORY_ALLOCATION_FAILURE` | The 512 MiB work area could not be allocated. |
| `ARGON2_FAILURE` | Argon2id rejected or failed an operation. |
| `INTERNAL_ERROR` | An invariant or internal conversion failed. |

The Worker adapter additionally uses `INVALID_REQUEST`, `WORKER_FAILURE`, and
`SERIALIZATION_FAILURE`. Cancellation rejects with `MhfeCancelledError`.

## Compatibility rule

Consumers must inspect `apiVersion` and `suiteId`. A change to the format,
normalization, KDF schedule, round function, or serialization requires a new
suite identifier. An incompatible JavaScript contract requires a new API
version.
