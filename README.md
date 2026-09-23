# MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics

[![CI](https://github.com/hobby-eng/mhfe/actions/workflows/ci.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/ci.yml)
[![Published vectors](https://github.com/hobby-eng/mhfe/actions/workflows/vectors.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/vectors.yml)
[![RustSec audit](https://github.com/hobby-eng/mhfe/actions/workflows/audit.yml/badge.svg)](https://github.com/hobby-eng/mhfe/actions/workflows/audit.yml)

<p align="center">
  <img src="assets/mhfe-mascot.png" alt="MHFE penguin mascot carrying a cold-storage plate" width="240">
</p>

*Rust reference implementation of the experimental suite*

This repository provides a reusable Rust library, a Linux command-line program,
and an optional browser/WASM API for `MHFE-BIP39-256-EXPERIMENTAL-2`. It
implements the complete encryption and recovery workflow, including every
supported BIP39 source length, automatic short-source length detection, PIM
handling, structured errors, public test-vector generation, and benchmarking.

The protocol text is maintained separately in the companion
[MHFE specification repository](https://github.com/hobby-eng/mhfe-spec). This repository contains
experimental implementation code and evidence, not the authoritative design rationale.

The code has an internal implementation audit, but it has **not received an independent
cryptography-specialist review and must not protect real funds**. See
[`docs/audits/`](docs/audits/).

The library contains the reusable BIP39 packing, balanced Feistel permutation,
Argon2id, BLAKE2b-256, and HMAC-SHA-256 implementation. Its optional WASM API
calls the same core instead of reimplementing the algorithm for HTML. The
repository has no path dependencies on the wallet-tools project or any other
local checkout; all Rust dependencies and exact versions are recorded in
`Cargo.toml` and `Cargo.lock`.

## Current limitation

The specification pins NPSS-NFKD from Unicode 18. The Rust normalization crate
available when this prototype was created contains Unicode 17 tables. The CLI
therefore accepts **ASCII test passwords only**, for which Unicode 18 NFKD is
exactly the identity transformation. It rejects non-ASCII input instead of
silently generating incompatible vectors.

The browser adapter never uses JavaScript `String.prototype.normalize()`, whose
Unicode version is browser-dependent. Non-ASCII callers must provide bytes
already normalized by a conforming Unicode 18 NPSS-NFKD implementation.

English BIP39 input is lowercase and case-sensitive. Repeated whitespace is
accepted by the underlying BIP39 parser and canonical output uses one space;
uppercase words are rejected rather than case-folded.

## Build and test

```bash
cargo test --locked
cargo build --release --locked
scripts/build-wasm.sh
```

Canonical release assets are built in a pinned Linux/amd64 container:

```bash
scripts/build-reproducible.sh
```

The container pins its base image by digest, Rust 1.98.1, Node.js 24.20.0,
`wasm-bindgen-cli` 0.2.128, and every Rust dependency through `Cargo.lock`.
It emits deterministic Linux and browser/WASM archives plus `SHA256SUMS`.
The browser archive is the canonical byte sequence for downstream consumers;
an application embedding MHFE should pin the release and verify its published
SHA-256 value instead of independently rebuilding a nominally identical WASM
file.

The binary is written to `target/release/mhfe`. The plain WASM command verifies
that the reusable core compiles for the browser target; `scripts/build-wasm.sh`
additionally produces the JavaScript bindings and Worker adapter.

Run the complete standalone check with:

```bash
scripts/check.sh
```

Tags matching the package version, for example `v0.3.0`, run the repository's
own release workflow. It repeats all checks, invokes the same canonical
container build, and publishes a Linux x86-64 CLI archive, a browser/WASM
archive, and `SHA256SUMS`. No wallet-tools checkout is used by CI or release
builds.
RustSec auditing runs when the Cargo dependency files change and on a weekly
schedule; Dependabot watches both Cargo and GitHub Actions dependencies.

## Browser API

The optional `wasm` feature exports a browser API with stable error codes,
suite-parameter discovery, ASCII-password operations, and an advanced API for
UTF-8 bytes already normalized under the specification's Unicode 18
NPSS-NFKD rule. Build the distributable WASM bindings with:

```bash
scripts/build-wasm.sh
```

The generated package is written to `dist/`. `web/client.js` and
`web/mhfe-worker.js` keep the expensive synchronous WASM operation in a
dedicated Worker. The client passes embedded or caller-loaded WASM bytes (or a
compiled `WebAssembly.Module`) into the Worker, so the Worker performs no
fetch and can run in a single-file consumer with `connect-src 'none'`.
Normal disposal drops and zeroizes the reachable 512 MiB Rust work area.
Cancellation terminates the complete Worker realm; browsers do not guarantee
that Rust destructors run during forced termination. See `web/README.md`.
The browser result objects deliberately omit source entropy, packed plaintext,
round keys, salts, and masks; detailed internals are confined to the explicitly
test-only vector command.
The complete Rust, Worker, result, cancellation, and error contract is in
[`API.md`](API.md).

Recovery detects the original short-mnemonic length automatically by checking
all four encrypted verifier layouts after one inverse permutation. One match
selects that length, no match uses the 24-word interpretation, and multiple
matches stop with an ambiguity error listing every matching length. Explicit
length selection remains available as an override.

## Explicit public-test interface

`--test-password` is deliberately visible. Its value can appear in shell
history and process listings. Use it only with public test credentials.

```bash
./target/release/mhfe encrypt \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --test-password "public test password"
```

Generate a deterministic JSON vector containing the public test password,
normalized password bytes, packed state, encrypted mnemonic, both direction
traces, Argon2 outputs, and masks. Timings are printed separately and are not
written into the vector. Write experimental output to a temporary path; the
canonical published vectors live in the
[companion specification repository](https://github.com/hobby-eng/mhfe-spec/tree/main/vectors):

```bash
./target/release/mhfe vector \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --test-password "public test password" \
  --pim 0 \
  --output /tmp/zero-12-pim-0.json
```

Measure an exact encryption and decryption round trip:

```bash
./target/release/mhfe benchmark \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  --test-password "public test password" \
  --pim 0 \
  --runs 1 \
  --output benchmark.json
```

Each operation allocates one 512 MiB Argon2 work area. At `PIM=0`, encryption
and decryption each perform twelve Argon2id calls with `t=12`, `p=4`.

## Password-guessing scale

Password length does not materially change the cost of one MHFE operation. On
the prototype test laptop, a Chromium/WASM `PIM=0` decryption took 84.145
seconds. If a password is selected uniformly from an alphabet of size `A`, the
mean exhaustive-search work is approximately `A^length / 2` attempts. Applying
that single measured rate to one sequential process gives the following
non-normative illustration:

| Length | Digits (10) | Lowercase Latin (26) | Latin alphanumeric (62) |
| ------ | ----------- | -------------------- | ----------------------- |
| 6      | 1.33 years  | 412 years            | 75,700 years            |
| 8      | 133 years   | 278,000 years        | 291 million years       |
| 10     | 13,300 years | 188 million years   | 1.12 trillion years     |
| 12     | 1.33 million years | 127 billion years | 4.30 quadrillion years |
| 14     | 133 million years | 86.0 trillion years | 1.65 × 10^19 years |
| 16     | 13.3 billion years | 5.81 × 10^16 years | 6.36 × 10^22 years |
| 18     | 1.33 trillion years | 3.93 × 10^19 years | 2.44 × 10^26 years |
| 20     | 133 trillion years | 2.66 × 10^22 years | 9.39 × 10^29 years |

These numbers are not attack lower bounds. An independent optimized native
implementation measured during development completed the same attempt in about
34.26 seconds, approximately 2.46 times faster, and attackers can run many
machines in parallel. Each concurrent attempt nevertheless requires roughly
512 MiB of working memory with this suite. Hardware, implementation quality,
future optimizations, and the selected PIM all change the rate.

The table assumes uniformly random characters. Human-created passwords of the
same length can be vastly weaker because dictionaries and mutation rules avoid
most of the nominal search space. A predictable suffix such as `!` adds little;
password-manager-generated randomness is materially different from a memorable
phrase of equal length.

Short-source recovery redundancy also affects how a guess can be recognized:

| Source length | Internal verifier | Random false acceptance |
| ------------- | ----------------- | ----------------------- |
| 12 words      | 128 bits          | `2^-128`                |
| 15 words      | 96 bits           | `2^-96`                 |
| 18 words      | 64 bits           | `2^-64`                 |
| 21 words      | 32 bits           | `2^-32` (about 1 in 4.29 billion) |
| 24 words      | None              | No internal test        |

For a 21-word source, the built-in check is 32 bits long. If a wrong password
produces an effectively random result, the chance that it passes this check by
accident is about 1 in 4.29 billion. Normal recovery does not require any
additional confirmation. Software testing billions of password guesses can use
known wallet information to confirm the extremely rare accidental match.

For a 24-word source, the correct password and PIM (only if a non-zero PIM was
deliberately used; otherwise it defaults to `0`) always recover the exact
original 256-bit entropy. The ordinary BIP39 checksum is then recomputed
automatically, producing the original valid 24-word mnemonic; no external
evidence is required for recovery. The limitation is only password
verification: every permitted password and PIM produces some 256-bit result
that can also be encoded as a checksum-valid 24-word mnemonic, so the container
alone cannot tell the user whether an entered password was the intended one.

Version 0.3.1 adds the optional
`MHFE-BIP39-256-EXPERIMENTAL-2-CYCLE-WALK-FINAL-WORD` profile for 24-word
sources. It repeatedly applies the complete, unchanged suite-2 permutation
until the encrypted container has the same complete final BIP39 word as the
source. Recovery repeats the inverse permutation until it returns to that
final-word class. The first application is mandatory, and no iteration counter
is stored.

The match probability is approximately 1 in 2,048 per complete permutation.
At the 34.26-second native rate measured above, the mean is about 19.5 hours on
one sequential worker; the actual run may be much shorter or much longer. The
library reports progress after every complete permutation and supports
cancellation between permutations. Applications must make the profile an
explicit recovery choice because the container does not identify it.

The preserved final word is visible in the encrypted container and is not a
password verifier. Recovery with a wrong password also eventually returns a
different 24-word candidate in the same final-word class. Standard suite-2
encryption remains the default and unchanged.

The Rust source is licensed under MIT. Published vectors are maintained in the
[companion specification repository](https://github.com/hobby-eng/mhfe-spec/tree/main/vectors)
and released there under CC0-1.0 so other implementations can copy them verbatim.
