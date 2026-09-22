# MHFE: Memory-Hard Feistel Encryption for BIP39 Mnemonics

*Experimental Rust implementation*

This repository contains a minimal library and Linux command-line program for
`MHFE-BIP39-256-EXPERIMENTAL-2`. It is intended to generate public test vectors,
check round trips, and measure the current experimental parameters.

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

The binary is written to `target/release/mhfe`. The plain WASM command verifies
that the reusable core compiles for the browser target; `scripts/build-wasm.sh`
additionally produces the JavaScript bindings and Worker adapter.

Run the complete standalone check with:

```bash
scripts/check.sh
```

Tags matching the package version, for example `v0.3.0`, run the repository's
own release workflow. It repeats all checks and publishes a Linux x86-64 CLI
archive, a browser/WASM archive, and `SHA256SUMS`. No wallet-tools checkout is
used by CI or release builds.
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

For a large 21-word search, a false verifier match still needs confirmation
against a known public address or other external wallet evidence. A 24-word
source has no spare bits for an internal verifier, so the format itself cannot
identify the correct password at all; recovery requires external evidence.

The Rust source is licensed under MIT. Published vectors are maintained in the
[companion specification repository](https://github.com/hobby-eng/mhfe-spec/tree/main/vectors)
and released there under CC0-1.0 so other implementations can copy them verbatim.
